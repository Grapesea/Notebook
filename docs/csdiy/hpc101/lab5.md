# Lab 5: Gemma4 端到端推理优化

<center>Grapesea</center>

[TOC]

> 参考资料：
>
> * [实验文档](https://hpc101.zjusct.io/lab/Lab5-Gemma4/)
>* [A Visual Guide to Gemma 4 12B - by Maarten Grootendorst](https://newsletter.maartengrootendorst.com/p/a-visual-guide-to-gemma-4-12b)，读了一遍非常通俗易懂.
> 

## GPTQ权重优化

首先学习一下原理：

### 基础

Gemma 4 12B是一个 Decoder-only 的小模型，实际上这指的是，在多模态情境下不使用encoder也获得了多模态理解和推理的能力.

Decoder-only 语言模型把序列概率分解为 $p(x_1,\ldots,x_L)=\prod_{t=1}^{L}p(x_t\mid x_{<t})$.

推理包括两个阶段：Prefill 一次处理 prompt 中的全部 token，并生成各层的 KV Cache；Decode 每轮只输入一个新 token，复用历史 KV Cache 计算下一个 token. Prefill 通常包含较大的矩阵乘，偏计算密集；Decode 的矩阵乘退化为矩阵向量乘，反复读取全部权重，通常更受显存带宽和 kernel 发射开销限制. 

Gemma 4 的缩放点积注意力为
$$
A=\frac{QK^T}{\sqrt{d_h}}+M,\qquad
P=\operatorname{softmax}(A),\qquad O=PV.
$$

因果掩码保证位置 $i$ 只能看到不晚于自身的位置. Gemma4 混合使用全局注意力与窗口大小为 $W=1024$ 的滑动窗口注意力. 后者只保留 $j\le i,\,j>i-W$ 范围内的键值. 真正高效的实现应跳过窗口外的分数计算，而不是先计算完整
$L\times L$ 分数矩阵再加掩码. 

Grouped Query Attention 令多个 Query heads 共享一个 KV head. 若 Query head 数为 $H_q$、KV head 数为 $H_{kv}$，则Query head $h$ 使用
$$
h_{kv}=\left\lfloor\frac{h}{H_q/H_{kv}}\right\rfloor.
$$

Gemma4-12B 的滑窗层为 $H_q=16,H_{kv}=8$，全局层为 $H_q=16,H_{kv}=1$. GQA 不减少 Query 数量，但减少 K/V 投影、注意力计算和 KV Cache；实现时不应物化重复的 K/V. 

Gemma4 的前馈层为

$$
\operatorname{FFN}(x)=W_{down}
\left[\operatorname{SiLU}(W_{gate}x)\odot(W_{up}x)\right],
$$

其中$\operatorname{SiLU}(x)=x\sigma(x)$. 因此每层包含 gate、up、down 三个大矩阵（这在lab3中已有涉及）. Decode 每一步都要读取这些权重，所以W4A16 量化可同时降低常驻显存和权重读取量. 

### 权重与 KV Cache 显存

设模型有 $N$ 层，隐藏维度 $D$，Query heads 为 $H_q$，KV heads 为 $H_{kv}$，head dimension 为 $D_h$，FFN 中间维度为 $F$，词表为 $V$. 忽略 Norm 等小参数，参数量近似为
$$
P\approx 2VD+ND(2H_qD_h+2H_{kv}D_h+3F).
$$

$x$-bit 权重占用约为

$$
M_w=P\frac{x}{8}\ \text{bytes}.
$$

12B 参数的 BF16 理论值约 24 GB，而 INT4 理论值约 6 GB；实际 INT4 checkpoint 还包含 scale、zero point、未量化参数、对齐和运行时内存. 

静态 BF16 KV Cache 的一般表达式为

$$
M_{kv}=2BSNH_{kv}D_h\frac{16}{8}\ \text{bytes},
$$

其中 2 表示 K 和 V. 对于混合注意力，更准确地写为

$$
M_{kv}=2B\frac{y}{8}
\left(N_lS H_{l,kv}D_{l,h}+N_gS H_{g,kv}D_{g,h}\right).
$$

滑窗层采用 ring cache 后变为

$$
M_{kv}^{ring}=2B\frac{y}{8}
\left(N_l\min(S,W)H_{l,kv}D_{l,h}
+N_gS H_{g,kv}D_{g,h}\right).
$$

### INT4 线性量化

实数权重 $r$ 和整数 code $q$ 的映射为

$$
q=\operatorname{clip}\left(\operatorname{round}\left(\frac r s+z\right),
q_{min},q_{max}\right),\qquad
\hat r=s(q-z).
$$

本框架每个输出通道、每 `group_size` 个输入列共享一组量化参数. 对称 INT4 使用有符号值 $[-8,7]$，checkpoint 中编码为 $[0,15]$，反量化为
$$
\hat r=s(q_{code}-8),\qquad
s=\frac{\max |r|}{7}.
$$

非对称量化使用

$$
s=\frac{r_{max}-r_{min}}{15},\qquad
z=\operatorname{round}\left(-\frac{r_{min}}s\right).
$$

一个 `uint8` 的低、高清半字节依次保存两个 INT4 code. 输入维度补齐到 group size 的整数倍；补齐位置必须编码成反量化后的零. 

### 从 RTN 到 GPTQ

RTN 只最小化权重数值误差 $\lVert W-Q\rVert$，没有考虑输入分布. 设校准激活为 $X\in\mathbb R^{N\times d_{in}}$，线性层权重$W\in\mathbb R^{d_{out}\times d_{in}}$，更有意义的层重构目标是
$$
\min_Q\lVert XW^T-XQ^T\rVert_F^2
=\min_Q\lVert X(W-Q)^T\rVert_F^2.
$$

忽略不影响优化的常数，其 Hessian 为 $H=\frac{2}{N}X^TX$，$H$ 的对角项表示单个输入通道的重要程度，非对角项表示通道相关性. GPTQ按输入列量化：当前列舍入后，利用逆 Hessian 调整尚未量化的列，让后续列补偿当前误差. 

令$H^{-1}=U^TU$，且 $U$ 为上三角矩阵. 第 $i$ 列由 $w_i$ 量化为 $q_i$ 后，归一化误差为

$$
e_i=\frac{w_i-q_i}{U_{ii}},
$$

剩余权重更新为

$$
W_{:,i:}\leftarrow W_{:,i:}-e_iU_{i,i:}.
$$

该更新不会改变已经量化的列，只把误差沿校准数据所揭示的相关方向传播. 预测的二次损失可累计为

$$
L_{pred}=\frac12\sum_i
\frac{\lVert w_i-q_i\rVert_2^2}{U_{ii}^2}.
$$

若某输入通道在校准集中恒为零，则对应 Hessian 对角项为零，称为 dead column. 该列不影响校准输出，可以把对应权重清零并把 Hessian 对角项设为1. 随后加入阻尼

$$
H\leftarrow H+\lambda I,\qquad
\lambda=\alpha\operatorname{mean}(\operatorname{diag}H).
$$

阻尼保证 Cholesky 分解稳定；过大会削弱通道相关信息. 实现中使用 FP32 构造 Hessian、求 Cholesky 因子并传播误差. 



## 端到端推理性能优化

这一部分我是把完整推理按阶段和矩阵形状采样. 端到端日志负责观察总时间、OOM和batch效果，Linear微基准负责判断相同INT4权重在decode与prefill中应该走哪条路径，CUDA allocator报错用来定位峰值显存来自哪个临时张量.

### Baseline表现

最初的`int4_reference`在每次Linear forward时都执行：

```python
weight = dequantize_weight(quantized, dtype=inputs.dtype)
output = F.linear(inputs, weight, bias)
```

也就是说，虽然checkpoint是INT4，运行时却反复物化完整BF16权重. Decode一次只算很少的行，这个反量化成本无法摊薄；随后每个token、每一层还要重新做一次. 性能公开集共10个请求、生成320个token，batch size 1需要：

```text
elapsed_s: 248.0881 s
generated_tokens_per_s: 1.2899 token/s
```

从调用结构和后面的对照试验可以判断，主要问题并不是Python调度，而是每步反量化、读取大权重和大量小kernel. 仅把请求组成batch之后就降到了86.0530 s，也说明decode中重复读取权重是主要矛盾：一次读权重同时服务更多请求，可以明显提高有效计算量.

### Linear形状采样

模型中最有代表性的MLP投影在decode阶段形状约为：

```text
M = 4, K = 3840, N = 15360
```

对这一形状单独采样，自写Triton INT4 kernel约为1.73 ms，ATen的INT4 Tensor Core路径约为0.235 ms，后者快约7.4倍. 这解释了为什么74秒左右的Triton版本仍有非常大的优化空间：decode反复执行小$M$投影，单次省下的1 ms会被层数和token数放大.

但是把$M$换成prefill的长序列之后，结论正好相反. ATen INT4小矩阵kernel并不适合大$M$，反量化一次再调用cuBLAS反而更快. 所以采样给出的结论不是“某个kernel永远最快”，而是要按负载分派：

| 阶段                     | 矩阵特点           | 最终路径                    | 原因                                    |
| ------------------------ | ------------------ | --------------------------- | --------------------------------------- |
| Decode                   | $M\le64$，反复调用 | ATen INT4 Tensor Core       | 不物化BF16权重，小矩阵延迟最低          |
| Prefill                  | $M$较大            | 反量化 + cuBLAS             | 大GEMM效率高，反量化成本可被多token摊薄 |
| 不支持ATen私有算子的环境 | 任意               | Triton / reference fallback | 保留可运行性和正确性                    |

### 显存采样

仅看平均显存没有意义，10 GiB环境真正卡住的是某一个层、某一次prefill的峰值申请. 调试日志中出现过以下具有代表性的分配失败：

```text
262144000 bytes
524288000 bytes
769654784 bytes
1025507328 bytes
```

其中约770 MiB的申请来自长prompt下SDPA的GQA fallback：全局注意力只有1个KV head，但实现可能临时扩展成16个head. 另外，prefill同时保留ATen pack和原始packed权重，再物化数百MiB的BF16大投影，也容易触发allocator重试甚至OOM.

因此最后的显存策略是：

* GPU常驻ATen格式的INT4权重，服务decode；
* 原checkpoint布局的packed权重留在pinned CPU内存，只在当前层prefill时搬到GPU；
* 滑窗层KV Cache改成ring buffer，只保留最近1024个位置；
* prefill的attention按query维分块，控制score和probability的峰值；
* GQA decode不再物化重复K/V.

这实际上是用少量PCIe传输换取显存空间. 如果显存足够，两套布局都常驻GPU会更简单；但在10 GiB限制下，峰值是否能过比省一次H2D更重要.

### 迭代过程

下面的数据都来自相同的10条公开性能请求和320个生成token. MIG会有一定波动，所以表格主要用来看数量级和优化方向：

| 版本                        | Batch size |   `elapsed_s` |             吞吐量 | 现象                   |
| --------------------------- | ---------: | ------------: | -----------------: | ---------------------- |
| reference路径               |          1 |    248.0881 s |     1.2899 token/s | 每次Linear物化BF16权重 |
| 仅增加batch                 |          4 |     86.0530 s |     3.7186 token/s | 权重读取由多个请求摊薄 |
| Triton INT4 + 分块attention |          4 |     74.5443 s |     4.2927 token/s | 小矩阵仍是热点         |
| 中间复测                    |          4 |     76.6967 s |     4.1723 token/s | MIG运行存在波动        |
| ATen INT4 + 混合prefill     |          4 |     42.5252 s |     7.5250 token/s | decode投影明显加快     |
| 加GQA/调度并增至batch 5     |          5 |     36.3942 s |     8.7926 token/s | 已接近36秒阈值         |
| 最终版本                    |          5 | **35.6799 s** | **8.9686 token/s** | 达到性能满分区间       |

中间也试过一些看起来合理、实际上会负优化的方法：

* 所有阶段都强制使用ATen INT4：大$M$ prefill反而比cuBLAS慢；
* prefill直接使用SDPA GQA：fallback可能展开KV，在长prompt时申请约770 MiB；
* attention始终用FP32 softmax：batch 5峰值显存过高；
* 把query chunk继续缩小：显存会下降，但kernel数量和发射开销增加；
* 盲目继续增大batch：padding和峰值显存开始抵消并行收益.

所以最后取batch size 5和query chunk 384. 这两个数字都不是理论上的固定最优值，而是当前数据集、10 GiB显存和这套实现共同约束下的实验结果.

## 多种优化方法的尝试

### 融合INT4反量化与矩阵乘

第一版优化写了Triton kernel，直接从`uint8`取出低/高半字节，根据K方向的group找到scale，然后在寄存器中反量化并做矩阵乘. 它避免了完整BF16权重张量：

```python
low = packed & 0x0F
high = packed >> 4
code = tl.where(k & 1 == 0, low, high)
weight = (code.to(tl.float32) - 8.0) * scale
acc += tl.dot(x, weight)
```

原理上，reference路径的显存流量近似包含“读INT4 + 写BF16 + 再读BF16”，融合以后变为“读INT4和scale后直接参与计算”. Decode本身算术强度低，因此减少中间权重的写回和二次读取会直接改善性能.

后来又使用PyTorch内部的Tensor Core INT4算子. checkpoint把较早的K元素放在低半字节，而ATen pack要求放在高半字节，所以模型加载时先交换nibble，再一次性转换：

```python
swapped = (qweight << 4) | (qweight >> 4)
int4pack = torch._convert_weight_to_int4pack(swapped.contiguous(), 8)

output = torch._weight_int4pack_mm(
    inputs, int4pack, group_size, scale_and_zero
)
```

这一步必须放在计时区间之前，否则每轮重新pack会把收益全部吃掉. ATen量化参数最后一维为`(scale, additive_offset)`；对称量化的offset为0，非对称情况应为$(8-z)s$.

### Prefill和Decode分流

最开始我希望一个融合kernel处理所有形状，但是采样结果不支持这种做法. 最终按输入行数判断：小于等于64行时走ATen INT4；大矩阵则从CPU取本层的packed权重，反量化为输入dtype后调用`F.linear`.

为了减少pageable内存的隐式staging copy，CPU上的权重在加载时调用`pin_memory()`，搬运时使用`non_blocking=True`. 对特别大的投影还会先查询剩余显存；如果连BF16临时权重都放不下，就直接回退到INT4 GEMM，避免先触发一次必然失败的allocator申请.

共享embedding和LM head也需要单独处理. Gemma4词表大小为262144，若每轮输出投影都反量化整张embedding表，它会成为decode的另一个大热点. 最终lookup所需的checkpoint布局权重放在CPU，LM head使用ATen INT4 pack，从而既保留共享权重语义，又避免GPU上额外常驻约0.5 GiB副本.

### 分块Attention与GQA

Prefill若一次物化完整$L\times L$ attention score，长序列很容易超过显存. 我沿query维每384个位置切一块：

```python
for start in range(0, query_length, 384):
    query_chunk = query[:, :, start:start + 384]
    scores = torch.matmul(query_chunk, key.transpose(2, 3))
    scores.add_(mask_chunk)
    probability = torch.softmax(scores, dim=-1)
    outputs.append(torch.matmul(probability, value))
```

峰值score空间从$O(BH_qL^2)$降到$O(BH_qCL)$，其中$C=384$. 总计算量没有变化，所以这只是显存分块，不是真正跳过无效计算的Flash Attention.

Decode只有一个query token，滑窗层直接调用支持`enable_gqa=True`的fused SDPA；全局层则保持单KV head，通过广播完成矩阵乘，不生成16份cache. 这样不仅减少显存流量，还减少了逐head kernel发射.

实现GQA时我还踩了几个shape相关的坑：

* `SlidingAttentionLayer`漏存`num_qo_heads`，量化阶段直接报`AttributeError`；
* `[:, head]`会移除singleton维度，正确写法应是`[:, head:head+1]`；
* query分块以后mask也必须使用当前的`position_chunk`，否则长度598的序列和512大小的chunk无法广播.

这些问题不一定在短样本中出现，所以最后必须重新跑完整62条质量集，而不能只用前几条样本判断正确性.

### Ring KV Cache

原始实现为所有层都按`max_sequence_length`静态分配KV Cache. 但是滑窗层永远只访问最近$W=1024$个位置，因此可以用：

$$
slot=position\bmod W
$$

把新KV覆盖到ring buffer中. Decode读取时再按逻辑位置恢复顺序. 混合注意力下，显存从：

$$
M_{kv}=2B\frac{y}{8}\left(N_lSH_{l,kv}D_h+N_gSH_{g,kv}D_h\right)
$$

变成：

$$
M_{kv}^{ring}=2B\frac{y}{8}\left(N_l\min(S,W)H_{l,kv}D_h+N_gSH_{g,kv}D_h\right).
$$

全局层仍然需要完整历史，不能一起截断. Ring Cache主要释放了batch增大所需的显存，本身不一定直接缩短很多计算时间.

### 静态Batch重排

静态batch中只要有一个请求还没有生成完，其他已经结束的请求所在slot仍会造成浪费. prompt长度差别很大时，padding也会让prefill执行很多无效位置.

因此在所有请求已知的公开评测中，我先按prompt长度、再按生成长度排序，然后才组成静态batch. 这样相近长度的请求更容易放到一起，可以同时减少：

* prefill padding；
* 短请求等待长请求的空decode轮次；
* 单个batch的意外显存峰值.

这还不是continuous batching，因为一个请求结束后不会立刻补入新请求；但是对于只有10条、全部预先到达的性能集，重排已经能取得大部分容易获得的收益.

### 去掉计时路径中的同步

原始指标代码为了精确测每个小阶段，会频繁执行`torch.cuda.synchronize()`并查询峰值显存. 但是正式指标是整个数据集的端到端`elapsed_s`，每token同步会破坏CUDA异步流水.

最终配置设置：

```yaml
synchronize_metrics: false
```

同时运行脚本增加`--no-progress`，避免每个请求完成后刷新终端进入端到端时间. 总计时边界仍然保证GPU工作完成，只是不再在内部每个小区间强制同步.

## 量化正确性修正

这次有一个问题很值得单独记下来：packed INT4的解包不能直接把结果交错写回原来的`uint8`视图. 错误版本近似为：

```python
codes[..., 0::2] = packed & 0x0F
codes[..., 1::2] = packed >> 4
```

`uint8`并不存在两个独立的`uint4`子元素，第一次赋值会修改后面还需要右移读取的存储，导致大量错误token. 最后改成先独立计算，再stack：

```python
low = packed & 0x0F
high = packed >> 4
codes = torch.stack((low, high), dim=-1).flatten(-2)
```

另外还修正了embedding scale链式赋值提前引用`hidden_states`的问题. 这些修正说明“程序能生成文本”不能代替精度验证；性能优化过程中只要改了权重布局、attention shape或embedding，都需要重新计算NLL.

## 最终结果

质量评测使用完整62条公开样本，共20418个有效token，最终结果为：

| 指标       | BF16参考 | W4A16结果 |                      差值/要求 |
| ---------- | -------: | --------: | -----------------------------: |
| Mean NLL   | 2.308456 |  2.376512 |  $\Delta\mathrm{NLL}=0.068057$ |
| Perplexity |        — | 10.767283 |                   比值1.070426 |
| 质量要求   |        — |    Passed | $\Delta\mathrm{NLL}<0.1$满分线 |

不同序列长度桶的结果为：

| 长度桶 | 序列数 | INT4 Mean NLL | $\Delta\mathrm{NLL}$ |
| -----: | -----: | ------------: | -------------------: |
|    128 |     32 |      3.026874 |             0.081730 |
|    256 |     16 |      2.477330 |             0.046893 |
|    512 |      8 |      2.380981 |             0.056245 |
|   1024 |      4 |      1.990667 |             0.082277 |
|   2048 |      2 |      2.011638 |             0.073156 |

所有长度桶都低于0.1，说明提升阻尼、修改运行时kernel和修正embedding之后，并没有只在短序列上碰巧通过.

最终性能结果：

```text
requests:               10
generated_tokens:       320
elapsed_s:              35.6798625930096
requests_per_s:         0.280270
generated_tokens_per_s: 8.968644
batch_size:             5
```

相对248.0881 s的参考路径，端到端时间减少：

$$
1-\frac{35.6799}{248.0881}=85.62\%,
$$

加速比为：

$$
\frac{248.0881}{35.6799}=6.95\times.
$$

相对76.6967 s的batch-4 Triton版本又缩短了53.48%. 最终质量和性能都进入100分区间，对应验证日志分别为：

* `results/quality-final-184607.log`；
* `results/lab5-baseline-184599.log`.

## 总结

这次最重要的结论是：端到端推理优化不能只优化一个算子. Baseline的主要问题是decode中反复物化BF16权重；换成INT4 Tensor Core以后，瓶颈又移动到prefill、attention临时显存、LM head和batch利用率. 最终版本实际上是几种方法的组合：

* GPTQ保证W4A16精度；
* decode使用ATen INT4 Tensor Core；
* prefill使用CPU/GPU混合权重和cuBLAS；
* query分块、GQA广播和ring KV Cache控制10 GiB下的峰值显存；
* 长度感知的batch重排提高有效计算比例；
* 去掉计时路径中的逐token同步.

还有两个限制需要注意. 第一，`_convert_weight_to_int4pack`和`_weight_int4pack_mm`是PyTorch私有接口，换PyTorch版本后要重新验证；第二，35.6799 s距离36 s阈值只有约0.32 s，MIG邻居负载会造成波动，正式提交最好重复运行并取中位数. 如果继续优化，我会优先考虑真正不物化score的Flash Attention和continuous batching，而不是继续微调固定的chunk size.