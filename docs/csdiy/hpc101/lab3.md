# Lab 3: GDN Prefill前向优化

> [LLM推理优化基础知识](https://blogs.erix025.me/EfficientAI/sct-llm-talk/sct-llm-talk/)
>
> 涉及论文：
>
> * [[2412.06464] Gated Delta Networks: Improving Mamba2 with Delta Rule](https://arxiv.org/abs/2412.06464)
> * [[2406.06484] Parallelizing Linear Transformers with the Delta Rule over Sequence Length](https://arxiv.org/abs/2406.06484)
> * [[2312.06635] Gated Linear Attention Transformers with Hardware-Efficient Training](https://arxiv.org/abs/2312.06635)
>
> [TileLang](https://tilelang.com/)
>
> 性能评测包含两种计时区间：
>
> - **forward 端到端时间**：从 `raw_g` 开始，包含 `g_cumsum`、$A$、$U$、$W$、$S$ 和 $O$ 的全部计算，以及中间结果读写和 kernel launch 的开销。**这部分时间仅供参考与其他实现对比，最终评分不以此为准**。
> - **核心计算时间**：只统计学生函数内 $U$、$W$、$S$ 和 $O$ 的计算，不包括 `g_cumsum` 和 的预处理。学生函数内的张量分配、数据转换和 kernel launch 均包含在内。 **这部分时间将作为最终评分的主要依据**。
>
> 正确性评测和性能评测都会在多组不同的输入 shape 下进行。最终的性能分数是各组 shape 的加权平均。
>
> FlashQLA 将作为本实验的主要性能基线，同时也会给出 FLA 和 FlashInfer 在相同 case 下的结果作为 参考。性能分根据多个 case 上的综合表现计算，而不是由某一个 case 的最快结果决定。未通过正确性 检查、运行出错或超时的 case 不计性能分

## 理论学习与拆解





```bash
npx degit ZJUSCT/HPC101/src/lab3 lab3
```





## 优化过程

### 等价数学变换

#### Profiling变化



### Kernel Fusion



### Shared Memory



### ping-pong buffer / multi-buffering



### warp specialization



