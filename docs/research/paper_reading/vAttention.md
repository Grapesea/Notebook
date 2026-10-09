# [ASPLOS 2025] vAttention: Dynamic Memory Management for Serving LLMs without PagedAttention

> 实际上这是OS课的bonus，跟实验室的工作没什么关系.
>
> * 论文地址：[ACM DOI](https://doi.org/10.1145/3669940.3707256)
> * Github 仓库：[microsoft/vattention](https://github.com/microsoft/vattention)

📌 **Paper Type: LLM Serving / KV Cache Memory Management / System & Infrastructure Co-design**

**TL;DR：vAttention 通过分离虚拟地址预留与物理显存映射，让 KV cache 在虚拟地址上保持连续、在物理显存上按需增长，从而复用未经分页改写的 attention kernel；再通过异步映射、延迟回收和小页支持控制管理开销与碎片。**

## 原先工作的 Problem

1. **静态预留物理显存导致内部碎片。** 请求的输出长度事先未知；若按模型最大 context length 为每个请求分配 KV cache，大量已分配显存在请求生命周期中并未使用，限制 batch size 和吞吐。
2. **PagedAttention 缓解碎片，但改变了 kernel 看到的内存布局。** KV cache 分块后，块之间的虚拟地址通常不连续，需要在服务框架中维护 Block-Table，并改写 kernel 来定位各块。逻辑块到虚拟地址的映射之外，仍有系统的虚拟到物理地址转换。
3. **分页适配增加开发与运行开销。** 论文测得 FA2 和 FlashInfer 的 paged prefill kernel 最多分别慢 37% 和 42%；额外指令、page index 与寄存器压力影响 GPU 路径，Block-Table 构造影响 CPU 路径。不同 block size 也会改变性能。

> 🖼️ **[Figure 1: PagedAttention 的两层内存管理]**

![Figure 1](./D:/Downloads/figures/vAttention/1.png)

读图：Block-Tables 连接逻辑 KV blocks 与其虚拟地址；Page-Tables 再连接虚拟地址与物理页。作者希望把动态物理页管理放在下层，消除 attention kernel 对第一层的依赖。

---

## 框架 Overview

vAttention 是一个用于 LLM serving 的 **KV cache allocator**，不是新的 attention 数学算法，也不训练模型。方法可拆为三个协同部分：

* **Virtual tensors：** 为各层 K/V 预留覆盖最大 batch size 和 context length 的连续虚拟地址区间，用固定 reqId 定位每个请求。
* **Dynamic physical mapping：** 初始化准备物理页池，在执行前按各请求当前长度映射需要的页；kernel 仍通过普通 tensor 地址访问 KV cache。
* **LLM-specific optimizations：** 利用 decode 每轮增长一个 token 的规律提前映射；prefill 复用结束请求留下的映射，并进行 eager allocation；用更小 page-groups 减少页尾碎片。

关键在于：**连续的虚拟地址不要求连续的物理显存。** 大块虚拟地址预留不会按同样大小占用物理显存；物理页可以分散，再映射到连续虚拟区间。kernel 因而保留原来的寻址方式，内存管理模块承担动态增长。

但这里也不能简单理解成“访问到缺页时自动分配”：vAttention 会在 kernel 执行前通过 `step` 确保映射充分，并在可能时提前完成下一轮的映射。

## 构建方法论（Methodology）

### 1. System & Infrastructure Co-design：虚拟与物理内存解耦（§5）

传统 `cudaMalloc` 同时分配虚拟地址和物理显存。vAttention 利用 CUDA VMM 区分地址预留、物理页准备、映射和释放，并扩展 PyTorch allocator 来创建 **virtual tensors**。

一个 worker 有 $N$ 层，每层分别维护 K 和 V，因此预留 $2N$ 个 virtual tensors。定义：

$$
S=L\times H\times D\times P,\qquad V_{\mathrm{total}}=2NBS.
$$

$L$ 是模型最大 context length，$H$ 是该 worker 上的 KV heads 数，$D$ 是 head dimension，$P$ 是每个元素的字节数，$B$ 是最大 batch size；$S$ 是单请求、单层、单个 K 或 V 的最大容量。

每个请求占据不重叠的地址区间，起点为：

$$
\operatorname{offset}(\mathrm{reqId})=\mathrm{reqId}\times S,\qquad 0\le\mathrm{reqId}<B.
$$

论文示例：Yi-34B、FP16、TP-2 时，$N=60,H=4,D=128,P=2,L=200K$；取 $B=500$，单 worker 预留约 **12 TB 虚拟地址**。这不是 12 TB 物理显存。

> 🖼️ **[Figure 5: 从地址预留、按需映射到请求槽位复用]**

![Figure 5](./D:/Downloads/figures/vAttention/5.png)

(a) 仅预留 R1/R2 的地址空间；(b)(c) 请求增长时映射物理页；(d) R1 结束后暂不回收映射；(e) R3 复用 R1 的槽位及物理页。复用的是内存资源，新请求仍须写入自己的 KV 数据。

### 2. Memory & Long-Context Management：小页降低碎片（§6.2、§8.2）

按层分配的 K/V 都可能留下页尾空间。若使用 2 MB 大页，这些余量会跨层、跨请求累积。论文中的标准 CUDA VMM 路径使用 2 MB 分配粒度，作者通过修改开源 NVIDIA unified memory driver，增加 **64 KB、128 KB、256 KB page-groups**。

这里 page-group 是一次分配的一组物理页；不能把它与 PagedAttention 的 token block 直接等同。两者关系取决于模型的 KV heads、precision 和 TP degree。例：Llama-3-8B、TP-2 时，64 KB page-group 在单层 K 或 V 中容纳 64 tokens，2 MB 容纳 2048 tokens（Table 8）。

对每个独立、按页向上取整的 K/V 请求区间，页尾余量小于一个 page-group。由此可推导单请求所有层的余量上界约为 $2Ng$，其中 $g$ 为 page-group 大小；这是根据布局的推导，不是论文另列的公式。

作者也提供无需修改 driver 的 **Tensor Slicing**：创建形状为 $[B,L,N,H,D]$ 的 K/V tensors，再按层取 slice，使一页容纳多层 KV。论文将碎片降低到原设计的约 $1/N$。代价是单层 slice 不再连续，需要 kernel 支持 stride；论文中的早期 FlashInfer 缺乏该支持，因此主实现采用小页 driver 扩展。

### 3. Test-Time Compute & Allocation Scheduling：隐藏映射延迟（§4、§6.1）

这里自适应的是显存分配时机。依据两条 workload 观察：decode 每轮每请求仅增长一个 token；实测内存增长速率最高约 750 MB/s，并不会随 batch size 无限增长。

* **Decode：allocation-compute overlap。** 在 iteration $i-1$ 调用 `step` 时判断 iteration $i$ 是否需要新页，用后台线程将映射与当前 GPU 计算重叠。若当前轮确实缺少映射，仍须先补齐才能执行。
* **Prefill：deferred reclamation。** 请求结束后暂留其映射，新请求可复用同一 reqId。若新 prompt 更长，只需补充不足部分。
* **Prefill：eager allocation。** 预先为一个待使用的 inactive reqId 映射部分页，减少新请求进入时的临界路径开销。
* **回收策略。** 页池空闲资源下降到阈值时，再在后台回收 inactive 请求占用的页。论文举例阈值为 GPU memory 的 10%。

这些优化相互补充：小页减少浪费但可能增加映射次数；异步处理和复用减少频繁映射对推理延迟的影响。

---

## Training / Construction vs. Inference Pipeline

### Construction / Initialization

本论文没有 SFT、RL、loss function 或训练数据构造，优化对象是 serving runtime。

1. 配置 $N,B,L,H,D,P$ 与 page-group size。
2. `init` 预留 virtual tensors，并准备尚未映射到各请求 KV tensors 的物理页池。
3. 在服务框架中接入 vAttention API；小页路线使用作者的 driver 扩展。
4. 模型权重和其他 activations 继续由普通 PyTorch allocator 管理。

> 🖼️ **[Figure 6: vAttention 与 serving framework、PyTorch 和 CUDA 的关系]**

![Figure 6](./D:/Downloads/figures/vAttention/6.png)

### Inference / Serving（Algorithm 1、Table 4）

| 阶段           | API / 操作            | 作用                                              |
| -------------- | --------------------- | ------------------------------------------------- |
| 接收并调度请求 | `alloc_reqid()`       | 分配空闲 KV cache 槽位                            |
| 执行前         | `step(cache_seq_len)` | 根据当前长度保证所需物理页已映射；返回成功或失败  |
| GPU 执行       | `model.forward()`     | 使用普通 non-paged attention kernel 访问 KV cache |
| Decode 推进    | 更新 sequence length  | 为下一轮判断是否需要补充页                        |
| 请求结束       | `free_reqid(reqId)`   | 标记 inactive，映射可延后回收或复用               |

**Continuous batching：** 请求结束后 KV cache 的 batch 维可能出现空槽。FlashAttention 的 `cache_batch_idx` 将紧凑的 query batch 映射到固定 reqId 对应的 KV 槽位，避免搬动整段 KV cache。

若 `step` 无法满足显存需求，框架可以 preempt 请求。作者将更复杂的 CPU KV swapping 策略留作 future work。

**核心创新：把 KV cache 的动态物理管理与 attention kernel 的地址布局解耦。**

---

## 本文架构优势

1. **减少 kernel 与 allocator 的耦合。** 更新 attention kernel 时不必重复加入 Block-Table 寻址逻辑；Figure 16 展示少量框架代码即可替换 prefill kernel。
2. **兼顾空间效率与连续地址。** 不必在静态大块物理预留和不连续虚拟 KV 布局之间选择。
3. **优化与 workload 特征对应。** 用单 token 增长规律预测映射，用请求更替复用映射，用小页提高最大 batch size。
4. **主要性能收益有边界。** 长 context、较高 P:D ratio 的 workload 收益更大；短 context 的 FA2 prefill 和同库 decode 收益有限。