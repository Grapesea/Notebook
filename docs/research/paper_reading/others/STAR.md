# [IEEE J-STSP 2023]Attention-Refined Unrolling for Sparse Sequential micro-Doppler Reconstruction

> 论文地址：[arXiv:2306.14233](https://arxiv.org/abs/2306.14233)
> Github仓库：[rmazzier/STAR](https://github.com/rmazzier/STAR)

## 原先工作的 Problem

1. **规则采样与真实通信流量不匹配。** 常规 STFT 依赖密集、规则的信道测量，而通信包到达时间不规则；为感知额外发送探测包，又会增加通信开销。
2. **极少观测下重建质量差。** IHT 等方法在高缺失率下产生背景伪影，并丢失人体运动对应的频率分量，影响细粒度活动识别。
3. **迭代成本高，时序信息利用不足。** IHT 通常需要多次迭代；已有 sequential unrolling 方法主要用历史信息初始化求解器，但当前观测太少时，良好的初始化仍不足以保证最终结果。

------

## 框架与构建方法论（Methodology）

### Overview

STAR 全称为 **Single Thresholding with Attention Refinement**，负责将不完整 CIR 转换为 micro-Doppler 频谱，之后由独立 CNN 进行活动分类。

STAR 分为三个模块：

- **Single-layer LIHT：** 利用稀疏恢复模型获得当前窗口的初始频谱。
- **Attention mechanism：** 比较当前频谱与过去已恢复的频谱，提取时序上下文。
- **Solution refinement：** 根据上下文补充缺失的频谱能量，并抑制背景噪声。

**关键创新是将历史信息用于修正求解器的输出。** DUST 等方法在求解器输入端使用 attention；STAR 则允许 LIHT 只提供初步估计，再利用历史信息弥补当前观测不足。

> 🖼️ **[Figure 2: STAR 的 LIHT、历史 attention 与输出修正模块]**

### 1. System & Infrastructure Co-design：单层 LIHT

设完整窗口包含 \(K\) 个时间样本，当前仅获得其中 \(M_t\) 个：

\[ h[t]=\Phi_tz[t]+n,\qquad \Phi_t=M_tF_K. \]

其中，\(h[t]\) 是可用 CIR 测量，\(M_t\) 是采样选择矩阵，\(F_K\) 是 inverse Fourier matrix，\(z[t]\) 是待恢复的 DFT。

人体不同运动部位产生不同 Doppler 分量，因此论文利用频域稀疏性求解：

\[ \min_{z[t]}\|h[t]-\Phi_tz[t]\|_2^2 \quad\text{s.t.}\quad \|z[t]\|_0\leq\Omega. \]

STAR 将复数变量转换为实数表示，通过可学习矩阵 \(W\) 展开 IHT：

\[ z^{(0)}[t]=H_\Omega\left(\frac1\mu W^Th[t]\right), \]\[ z[t]=H_\Omega\left[ \left(I-\frac1\mu W^TW\right)z^{(0)}[t] +\frac1\mu W^Th[t] \right]. \]

\(H_\Omega\) 保留绝对值最大的 \(\Omega\) 个元素，\(\mu\) 是步长倒数。随后将实部、虚部平方相加，得到初始功率频谱 \(\widetilde y[t]\)。

### 2. Memory & Long-Context Management：历史 attention

将过去 \(N_p\) 个输出组成矩阵 \(Y[t]\)，则：

\[ a[t]=Y[t]^T \operatorname{Softmax}\left( \frac{Y[t]\widetilde y[t]}{\sqrt K} \right). \]

当前初始频谱是 query，历史频谱同时作为 keys 和 values。相似度越高的历史窗口，获得越大的权重。

**该 attention 不含可学习参数，也不学习 Q/K/V 投影。** 默认仅使用过去六个窗口，属于局部时序上下文；推理过程保持 causal。

### 3. Fine-tuning & Alignment：输出修正与监督目标

最终频谱为：

\[ y[t]= \left(\widetilde y[t]+\operatorname{ReLU}(Ua[t]+b)\right) \odot\sigma(Va[t]). \]

- **加性分支：** 补充重建不足的频率分量。
- **乘性分支：** 通过 \([0,1]\) mask 抑制背景噪声。

这里按 Algorithm 1 表述：原文 Eq. (18) 的首项写为 \(z[t]\)，但算法、维度与文字描述对应的是 \(\widetilde y[t]\)。

训练同时监督最终频谱与中间 DFT：

\[ \mathcal L[t] =0.9\operatorname{MSE}(y[t],y_{gt}[t]) +0.1\operatorname{MSE}(z[t],z_{gt}[t]). \]

**监督目标来自完整 CIR 上的收敛 IHT，而非独立测得的真实物理频谱。**

------

## Training vs. Inference Pipeline

### Training / Construction Phase

使用 DISC 数据集：416 条 60 GHz IEEE 802.11ay CIR 序列，7 名受试者，包含 walking、running、waving hands、sitting down/standing up 四类活动。

先按序列划分 train / validation / test，再切滑动窗口，比例为 **0.8 / 0.01 / 0.19**。训练时随机生成缺失 mask，并对 running 序列 oversampling。

| 配置                                 | 论文值             |
| ------------------------------------ | ------------------ |
| 窗口长度 / 移动步长                  | 64 / 32            |
| CIR 采样间隔                         | 0.27 ms            |
| 稀疏度 \(\Omega\) / 步长倒数 \(\mu\) | 5 / 20             |
| 历史窗口 \(N_p\)                     | 6                  |
| Optimizer                            | Adam               |
| Learning rate                        | \(2\times10^{-4}\) |
| Epochs                               | 5                  |
| GPU                                  | NVIDIA RTX3080     |
| 参数量                               | 24,640             |
| FP32 参数存储                        | 约 98 kB           |

Batch size、训练总耗时：**Not explicitly specified in text**。

### Inference / Reconstruction Phase

不完整 CIR → LIHT 初始估计 → 功率频谱 → 历史 attention → 加性与乘性 refinement → 当前频谱，并更新历史缓存。

下游 CNN 在完整观测的 IHT 频谱上训练，在各方法恢复的频谱上测试；每个分类片段约 **1.7 s**。

------

## Experiments & SOTA Comparison

### Experimental Setup

- 重建指标：**RMSE、SSIM**。
- 下游指标：**Global F1、per-class F1**。
- Baselines：IHT、IHT 1 iteration、DUST、DUST-V2、OMP、LASSO。

评测需要注意：OMP、LASSO 的重建质量分别与自身的完整观测结果比较，因此跨算法 RMSE/SSIM 并非完全统一的参考目标。

### Quantitative Results

标准 STAR 的结果如下：

| 缺失测量比例 | RMSE ↓ | SSIM ↑ | Global F1 ↑ |
| ------------ | ------ | ------ | ----------- |
| 50%          | 0.0545 | 0.884  | 0.881       |
| 75%          | 0.0779 | 0.745  | 0.829       |
| 90%          | 0.1213 | 0.536  | 0.773       |

在 50%/75% 缺失时，多种方法的分类表现接近；**90% 缺失时，STAR 的优势明显扩大**，尤其体现在 sitting/standing up、waving hands 等细粒度动作。

### Attribution Analysis

以下均为 90% 缺失：

| Variant         | RMSE ↓     | SSIM ↑    | Global F1 ↑ |
| --------------- | ---------- | --------- | ----------- |
| No Attention    | 0.1999     | 0.319     | 0.582       |
| Only Add        | 0.1998     | 0.230     | 0.586       |
| Learn S         | 0.1412     | 0.488     | 0.330       |
| \(N_p=9\)       | 0.1214     | **0.581** | 0.757       |
| STAR，\(N_p=6\) | **0.1213** | 0.536     | **0.773**   |

这些结果说明：

- **乘性去噪很关键：** 只保留加性分支，F1 从 0.773 降至 0.586。
- **更多参数不保证更好：** Learn S 增加自由参数，反而明显损害高缺失率表现。
- **历史并非越长越好：** 九个历史窗口提高 SSIM，却未提高分类 F1。
- No Attention 同时去掉 attention 与 refinement，不能独立量化 attention 的贡献。

新房间实验中，STAR 的 Global F1 为 **0.652**，完整观测参考为 **0.750**。这提供了跨环境证据，同时显示泛化后仍有下降。

------

## 本文架构优势

1. **模型与数据互补：** 稀疏恢复提供初步估计，历史频谱提供当前观测缺失的信息。
2. **输出端修正有效：** 避免将历史信息仅用于初始化。
3. **轻量且 causal：** 无 attention 投影参数，只缓存少量历史输出。
4. **收益落到下游任务：** 不仅改善频谱指标，也保留了活动识别需要的运动特征。

论文推导 STAR 与一次 IHT 具有同阶复杂度，而 IHT 通常需要约 15–20 次迭代；**这不等于已实测 15–20 倍端到端加速**。

## Case study

> 🖼️ **[Figure 9: 90% CIR 缺失下 waving hands 的重建对比]**

IHT、DUST 存在明显背景伪影；OMP 丢失较多细节；LASSO 较干净但弱化了运动特征。STAR 同时保留运动纹理并降低背景噪声，对应两个 refinement 分支的联合效果。

## Limitations & Future Work

**作者明确提出的方向：** 进一步融入 signal processing domain knowledge，探索超越 deep unrolling 的 model-based / physics-informed neural networks，将信号传播方程与人体运动模型嵌入架构。

专门的 Limitations 讨论：**Not explicitly discussed in paper**。

根据实验设置可识别的适用边界包括：IHT 生成的监督目标、有限受试者与动作类别、主要采用随机缺失模式，以及多目标场景对前置目标追踪和反射分离的依赖。这些属于对实验与假设的分析，并非作者在结尾明确列出的局限。