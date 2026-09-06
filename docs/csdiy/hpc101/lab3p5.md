# Lab 3.5:昇腾算子开发与优化

<center>Grapesea</center>

[TOC]

> * 实验文档：[Lab 3.5：昇腾算子开发与优化 - HPC101](https://hpc101.zjusct.io/lab/Lab3.5-AscendC-Op/)
> * [RMSNorm论文](https://arxiv.org/abs/1910.07467)
> * [Triton-Ascend](https://github.com/Ascend/triton-ascend)
> * [昇腾算子性能优化：流水优化](https://www.hiascend.com/zh/developer/techArticles/20240819-1)
> * [昇腾算子性能优化：内存优化](https://www.hiascend.com/zh/developer/techArticles/20240823-1)
> * [昇腾算子性能优化：搬运优化](https://www.hiascend.com/zh/developer/techArticles/20240906-1)

## 环境配置

> 本次实验需要在 Ascend 910B4 上实现并优化一个 `FusedAddRmsNorm` 算子. 可以选择 Ascend C、TileLang 或 Triton-Ascend，我最后选择的是 Triton-Ascend，主要原因是它的 block 编程模型和之前写 GPU kernel 时比较接近，同时仍然可以控制 tiling、归约和数据精度.

本次测试使用的环境为：

| 项目         | 配置            |
| ------------ | --------------- |
| NPU          | Ascend 910B4    |
| CANN         | 8.5.0           |
| Python       | 3.11.14         |
| 开发路径     | Triton-Ascend   |
| 性能 Shape   | $256\times1024$ |
| 输入输出类型 | FP16            |
| 中间计算类型 | FP32            |
| `eps`        | $10^{-6}$       |

正确性和性能测试分别运行：

```bash
hpc submit -p lab3p5 bash checker/run.sh
hpc submit -p lab3p5 bash checker/profile.sh
```

其中正确性测试包含 $32\times4096$、$256\times1024$、$1\times4096$、$1997\times3037$ 和 $2048\times4096$ 五个 shape；性能只测试 $256\times1024$，最终成绩读取 `msprof op` 给出的 `Task Duration(us)`，所以不能拿 Python 端到端计时来代替 kernel 时间.

## FusedAddRmsNorm理论推导

首先把算子本身理清楚. 输入 `x`、`residual` 的形状都是 $[B,H]$，`weight` 的长度为 $H$. 对第 $b$ 行，计算过程为：

$$
R_{b,i}=x_{b,i}+residual_{b,i},
$$

$$
s_b=\frac{1}{H}\sum_{i=0}^{H-1}R_{b,i}^2,
\qquad
q_b=\frac{1}{\sqrt{s_b+\varepsilon}},
$$

$$
y_{b,i}=R_{b,i}\cdot q_b\cdot weight_i.
$$

这个算子有两个输出：

* `residual_out` 为 $R$，后续 residual stream 还需要继续使用；
* `y` 为做完 RMSNorm 之后的结果.

这里不同的行之间完全独立，只有同一行的 $H$ 个元素在平方和处存在归约. 因此最自然的并行方法是沿 $B$ 维把行分给不同 AIV，单个 program 内完成一行或一组连续行的 `load-add-reduce-normalize-store`.

做算子融合的原因：如果先单独运行 Add，再运行 RMSNorm，那么 Add 写出的 $R$ 会被 RMSNorm 从 GM 再读一次. 但是在 fused kernel 中，$R$ 在加法完成后已经位于片上中间结果中，可以一边写出 `residual_out`，一边继续用于平方和以及最终的归一化，不需要因为下一个 kernel 再从 GM 读回来.

也就是说，融合并没有消除必须存在的 `residual_out` 写回，但是消除了一次大小为 $B\times H$ 的中间结果读取. 对性能 shape 而言，这一次读取就是：

$$
256\times1024\times2\ \text{Byte}=512\ \text{KiB}.
$$

这也是代码中一直保留 FP32 `r`，而不是写完 `residual_out` 后重新 load 的原因.

虽然输入输出都是 FP16，但是 Golden 的残差加法、平方和、开方和缩放都在 FP32 下完成，最后才转成 FP16. 因此我在 load 之后先转为 FP32：

```python
r_flat = (
    tl.load(x_ptr + offsets).to(tl.float32)
    + tl.load(residual_ptr + offsets).to(tl.float32)
)
```

`r_flat` 后续同时服务于 `residual_out`、平方和以及 `y` 的计算. 这样既少了一次访存，也避免 FP16 平方和的累计误差. 最后写回时再转换：

```python
tl.store(resout_ptr + offsets, r_flat.to(tl.float16))
tl.store(y_ptr + offsets, y.to(tl.float16))
```

## 代码实现与优化

### 初始实现

最直接的 Triton 写法是一个 program 处理一行，用 `tl.arange(0, BLOCK_H)` 生成列下标，对尾部做 mask，然后在这一行里完成 Add、平方和归约与 RMSNorm：

```python
pid = tl.program_id(0)
cols = tl.arange(0, BLOCK_H)
mask = cols < H
offsets = pid * H + cols

x = tl.load(x_ptr + offsets, mask=mask, other=0.0).to(tl.float32)
residual = tl.load(residual_ptr + offsets, mask=mask, other=0.0).to(tl.float32)
r = x + residual
mean_square = tl.sum(r * r, axis=0) / H
inv_rms = tl.rsqrt(mean_square + eps)
y = r * inv_rms * tl.load(weight_ptr + cols, mask=mask)
```

这一版可以作为功能 baseline，但是对于 $B=256$ 会启动 256 个很小的 program. 910B4 上单个空 kernel block 也有初始化和调度开销；而一行只有 1024 个元素，单个 program 的有效工作并不足以把这些固定开销摊平. 所以后续优化的重点并不是继续拆小，而是让一个 program 一次处理多行.

### 优化思路

#### 多行合并与核数选择

性能 shape 的 $H=1024$ 已经对齐，所以我为它单独写了 fast path. 一个 program 不再只处理一行，而是连续处理 8 行：

```python
flat = tl.arange(0, BLOCK_M * BLOCK_H)
offsets = tl.program_id(0) * (BLOCK_M * BLOCK_H) + flat
```

这里 `BLOCK_M=8`、`BLOCK_H=1024`，所以每次处理连续 8192 个 FP16 元素. 和逐行版本相比有几个好处：

* program 数从 256 减少到 32，降低 block 初始化和调度开销；
* 两个输入和两个输出都是连续地址，MTE 可以发射更大的搬运；
* 一个 program 内同时存在 8 行互相独立的计算，Vector pipeline 有更多可以交错调度的工作；
* 32 个 program 刚好覆盖 256 行，没有 mask、分支和尾块.

最开始我也试过 4、5、6、7、8 以及更大的行 tile. tile 太小时 program 太多，启动与搬运粒度不理想；tile 太大时 program 数继续下降，能够并行工作的 AIV 变少，同时 FP32 中间结果的存活范围和 UB 压力变大. 对这个 shape，8 行和 32 blocks 是两者之间比较合适的折中.

#### 一维连续搬运后再reshape

另一种写法是直接构造二维 `rows[:, None] * H + cols[None, :]`. 在 Triton 的语义上它很直观，但是固定 shape 下实际上没有必要做这些二维地址计算和 mask. 最终 fast path 先用一维连续 offsets 完成 load：

```python
r_flat = (
    tl.load(x_ptr + offsets).to(tl.float32)
    + tl.load(residual_ptr + offsets).to(tl.float32)
)
r = tl.reshape(r_flat, (BLOCK_M, BLOCK_H), can_reorder=True)
```

`reshape` 只是重新解释 program 内张量的形状，之后 `tl.sum(..., axis=1)` 才沿每行的 1024 个元素归约. 这样既保留了二维归约语义，又让 load/store 的地址表达保持连续.

#### 保留并复用FP32残差

`R=x+residual` 后面会被使用三次：写出 `residual_out`、计算 $R^2$、计算最终的 $y$. 最终代码只 load 和相加一次，并保留 `r_flat/r`：

```python
tl.store(resout_ptr + offsets, r_flat.to(tl.float16))
r = tl.reshape(r_flat, (8, 1024), can_reorder=True)
mean_square = tl.sum(r * r, axis=1) * 0.0009765625
y = (r * inv_rms[:, None]) * weight[None, :]
```

这里 `0.0009765625` 就是 $1/1024$，固定 shape 下用编译期常量乘法代替运行时除以 `H`. 更重要的是，写 `residual_out` 时转成 FP16 的副本不会改变继续参与 norm 的 FP32 `r`.

#### 归约、开方和广播的A/B测试

归约后的 8 个均方值要计算倒数平方根. 直觉上 `tl.rsqrt` 应该最快，但是在 Triton-Ascend 当前 lowering 下，最终实测 `1.0 / tl.sqrt(...)` 的中位数更好：

```python
mean_square = tl.sum(r * r, axis=1) * 0.0009765625
inv_rms = 1.0 / tl.sqrt(mean_square + eps)
```

从 5.44 us 降到约 5.09 us，大约是 6.4%. 这说明 DSL 层看起来更短并不等于后端机器指令一定更快，最后仍然要以板端 profile 为准.

广播则保持隐式写法：

```python
cols = tl.arange(0, BLOCK_H)
weight = tl.load(weight_ptr + cols).to(tl.float32)
y = (r * inv_rms[:, None]) * weight[None, :]
```

我曾经显式把 `weight` repeat 成 8 行，希望让数据布局更规则，结果时间直接从约 5.1 us 上升到 74.5 us；把 FP16 norm 显式 repeat 的版本也达到 71.2 us. 原因是这种写法促使编译器真的物化大张量，增加 UB 占用和搬运/复制，而原来的 `weight[None, :]` 本来就可以作为广播参与逐元素计算.

不同乘法结合顺序也做了测试. `r * (inv * weight)`、`(r * weight) * inv` 和当前的 `(r * inv) * weight` 数学上接近，但会影响临时张量、广播以及编译器调度. 实测没有比当前写法稳定更快，所以没有为了源码上少一个括号去修改.

#### Double Buffer和编译参数

最终 fast path 启用了：

```python
multibuffer=True
```

希望让编译器安排 GM 搬运与 Vector 计算的重叠. 我也测试了显式 `num_stages=2`，但中位数由 5.44 us 变为 5.53 us，没有加速；profile 过程还会提示：

```text
[WARNING] Please DO NOT tune args ['num_stages']!
```

因此最终没有保留 `num_stages=2`. 这个例子说明 pipeline stage 不是越多越好：当前每个 program 只有一个固定的 8 行 tile，没有很长的外层 tile 循环，增加 stage 反而可能扩大 buffer 或同步开销.

#### 通用shape的处理

性能 fast path 不能替代正确的通用实现，因为 checker 还会测试单行、较大 shape 和 $H=3037$ 的非对齐情况. 因此我保留了 `_fused_add_rmsnorm_generic_kernel`：

```python
programs = min(B, 32 if H <= 1024 else 40)
row_tile = 4 if H <= 1024 else 1
```

通用路径首先用商和余数把连续行均匀分给各 program：

```python
rows_base = B // PROGRAMS
remainder = B % PROGRAMS
```

前 `remainder` 个 program 多处理一行，使不同核的行数最多只差 1. 每次循环再处理 `ROW_TILE` 行，并同时对行尾和列尾做 mask：

```python
tile_mask = row_mask[:, None] & mask[None, :]
```

这样 $B=1$ 时不会为了形式上的 32 或 40 核启动大量空 program，$H=3037$ 时也不会越界. 对 $H\le1024$ 使用 4 行 tile 增大搬运粒度；更宽的行使用单行 tile，避免 FP32 临时值和 padding 过多占用 UB. 计分 shape 则绕过这部分动态分配、循环和 mask，进入专用的 8 行 fast path.

### 未采用优化

#### 用FP16做平方和

我测试了把 `r` 转成 FP16 后平方、FP16 平方再转 FP32 累加等版本：

| 方案               | Task Duration | 与FP32 Golden不完全相等的元素数 |
| ------------------ | ------------: | ------------------------------: |
| FP32平方和         |       5.22 us |                              23 |
| FP16平方和         |       5.74 us |                           34270 |
| FP16平方、FP32累加 |       5.90 us |                            4072 |

`neq` 并不等于 checker 错误，因为 checker 允许 $10^{-3}$ 的相对或绝对误差；但是这里低精度版本既没有更快，和 Golden 的偏差也明显增多，所以没有理由采用.

把所有缩放都降成 FP16 时，单个测试输入已经出现 1154 个超出容差的错误元素，直接不满足正确性要求. 将 `inv_rms` 单独舍入成 FP16 曾测得 4.98 us，但重复结果为 5.28 us，收益处在波动范围内，而且主动降低精度会增加隐藏 case 风险，所以最终仍然保持完整 FP32 中间计算.

#### 提前或者显式展开weight

把 weight 提前 load、改变乘法顺序都没有稳定收益；显式 repeat weight 更是从 5 us 量级回退到 70 us 以上. 因此 weight 只在每个 program 内 load 一次，然后依赖 Triton 的广播语义在 8 行上复用.

#### 盲目增加block和stage

这个算子的每行工作量不大，启动更多 block 会增加固定开销；tile 过大又会减少并行度和增加 UB 压力. 同样，`num_stages=2` 在没有足够 tile 循环时也没有形成有效流水. 因此最后选择的是经过 shape 约束后的 `32 blocks × 8 rows`，而不是固定使用全部 40 个 AIV，也没有堆叠更多编译选项.

### 最终实现框架

最终 host 侧根据 shape 分路：

```python
if B == 256 and H == 1024:
    _fused_add_rmsnorm_kernel[(32,)](
        x, residual, weight, y, residual_out,
        eps,
        BLOCK_M=8,
        BLOCK_H=1024,
        multibuffer=True,
    )
else:
    _fused_add_rmsnorm_generic_kernel[(programs,)](...)
```

性能 kernel 内的数据流可以概括为：

```text
GM中的x/residual
        |
        | 连续搬入8行并转FP32
        v
    r = x + residual -----------------> FP16 residual_out
        |
        | r保留在program内，不重新读GM
        v
  FP32平方和归约（每行一个值）
        |
        v
  sqrt + reciprocal
        |
        | 广播inv_rms和weight
        v
       FP16 y
```

这里真正起作用的优化不是某一个孤立的参数，而是让 tiling、地址模式和数据流互相配合：32 个 program 保证足够并行，8 行连续 tile 摊薄启动与搬运发射成本，一维 load/store 保持连续地址，`reshape` 只负责表达按行归约，FP32 `r` 则贯穿 Add、Reduce 和 Normalize，避免一次 GM 回读.

我感觉本次实验最明显的结论是，微秒级算子的优化不能只凭“某个 intrinsic 理论上更快”或者“核越多越快”来判断. `rsqrt`、更多 stage、显式广播和低精度平方都曾经看起来合理，但实测不是回退就是不稳定. 最终有效的修改反而比较朴素：按硬件启动成本选择合适的 block 数，用连续多行 tile 增大搬运粒度，把能复用的 FP32 中间结果留在片上，再用重复 A/B profile 判断后端真实生成结果. 

最后89分，开摆烂了.
