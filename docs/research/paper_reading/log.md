# 科研学习日志

## 论文阅读列表

| 简略标题                                 | 发表时间/会议       | 阅读情况 | 标签                          |
| ---------------------------------------- | ------------------- | -------- | ----------------------------- |
| [PPO](./PPO.md)                          | ICML 2017           | √        | RL, LLM                       |
| [GAE](./GAE.md)                          | ICLR 2016           | √        | RL                            |
| [DPO](./DPO.md)                          | NeurIPS 2023 Oral   | √        | RL, LLM                       |
| [DeepSeekMath (GRPO)](./DeepseekMath.md) | 2024.4              | √        | RL, LLM, Reasoning            |
| [GNN-RAG](./GNN-RAG.md)                  | ACL 2025 Findings   | +        | GNN, RAG, KG                  |
| [Search-R1](./Search-R1.md)              | COLM 2025           | √        | RL, LLM, Reasoning            |
| [Search-o1](./Search-o1.md)              | EMNLP 2025 Main     | +        | RL, LLM, Reasoning            |
| [GTA-RAG](./GTA-RAG.md)                  | EMNLP 2026 Findings | √        | RL, KG, RAG, Reasoning        |
| [CoG](./CoG.md)                          | ACL 2026 Main       | √        | RAG, LLM, Reasoning           |
| [Temp-R1](./Temp-R1.md)                  | ACL 2026 Main       | √        | TKG, RAG, Reasoning           |
| [STAR](./SATR.md)                        | IEEE J-STSP 2023    | +        | 计算机网络, Signal Processing |
| [vAttention](./vAttention.md)            | ASPLOS 2025         | +        | 操作系统, LLM, Memory         |

记号：（√）已完成；（+）进行中；（#）计划内未开始；（-）暂时弃坑；（×）永久弃坑

## Multi-hop Reasoning

> 深度科研项目：面向复杂多跳推理的检索增强生成系统研究
>
> 此为思路梳理，类似个人学习和研究的记录日志.

Start (2026.9.7)：

在当下的多跳推理研究中，学界认为主要有以下3种技术路线：

1. **迭代式检索-推理**（IRCoT、Self-RAG、Iter-RetGen）：以"检索→推理→再检索"的循环结构逼近多跳证据链；
2. **图结构增强**（HippoRAG、GraphRAG、HopRAG）：借助知识图谱/超图显式建模实体间的逻辑连接；
3. **强化学习驱动**（Search-R1、R3-RAG、DeepRetrieval）：用最终答案正确性作为奖励信号，端到端训练模型自主决定检索时机与查询内容

师兄师姐们在ACL发表的相关研究里[[1]](#1) [[2]](#2)，给出的路线有1和3两种，前者以CoG为代表，后者以Temp-R1为代表. 当前我研读了CoG（虽然看得半懂不懂），囿于硬件条件没办法跑复现实验.

服务器到手了，开始复现CoG. 感觉得再读一下，好难懂.

---

(2026.9.8):

读完了[彭思达老师的CCF Talk](../think.md).

---

(2026.9.10)

发现2026.1的一篇综述[[3]](#3)给出了更广的分类，并开始重读CoG整理成笔记.

怎么感觉强化学习还得从头再学一遍，Shiyu Zhao老师的看过但忘了……？

---

(2026.9.11)

睡过头了，报到注册，重新捡起CS224W，主要是因为翻到了 GNN-RAG[[4]](#4) 这篇文献.

CoG读完了.

---

(2026.9.12)

什么都没干.

---

(2026.9.13-14)

~~什么都没干~~

看了 Temp-R1

---

(2026.9.15)

看完 Temp-R1，捡起 CS224N+CS224W，希望这个学期能投一个会.

Claude 号没了，唉.

---

(2026.9.16-9.17)

被校内的东西困住了，累坏了.

---

(2026.9.18)

拼命学CS224W，通掉了67两节. 争取10月以前干完吧.

---

(2026.9.19-23)

事情很多，一不小心又过了好多天.

9.21明确了做 RL，让 astra 规划了一份学习路径，感觉 reverse curriculum learning 就是我自己学习的路径啊……之前有个 idea 就是这个意思.

transe 服务器能连回来了，继续开始. 放弃 CoG 复现，等组会听听 Jev 是怎么回事，感觉没什么很新奇的地方，难道成本能降下来吗？

今年应该还能多攒两个项目，一个知识图谱格式的照片整理软件（效仿 Zotero/Obsidian/Agentero），似乎也是B/S大作业规定的翻版，前几天才发现；一个暂时没看出来怎么赢的计网论文复现作业.

---

(2026.9.23)

Jev：决策方面的通用模型，创作类不行.

Jev 如果输入多个问题，并行处理的机制是？是工程实现上并行吗？

Jev 的输出是结构化的，不需要自然语言的结构化清洗和处理；价格低且速度快、准确率高.

与结构化LLM的区别：

* 生成方式不同：并非自回归 token generation.
* 训练方式不同：并非 RLHF，而是 RLCD.

架构猜测：更通用？

参数猜测：10B？开源的[NandhaKishorM/laya](https://github.com/NandhaKishorM/laya)不足1B.

决策、归一化

---

(2026.9.24-26)

学习了MFRL收尾章节，感觉现在得靠ChatGPT

---

(2026.9.27)

Search-R1开始，学不懂了……Temp-R1不是很契合，这次的主要目标是Multi-hop，所以

---

(2026.9.28)

1. 基座模型

    Qwen-3.6-8B ?

    训练效果？

    基模强的情况：上下文管理、流程设置

    跟新一点的benchmark比较，8B效果未必好 -> 大小模型协同

    **8B上模型训练做baseline** -> ?

2. 数据集问题？想体现思维链断裂的话目前没有特别合适的数据集（领域完全不同）

    * MuSiQue (Open Domain): 最多4跳

    * StepGame: 每个题目标明了需要1-10跳

    * BrowseComp: 联网检索的
    * DeepResearch:  Open Domain
    * **长程Memory：**特殊action训练进去（compact/）
    * 长程任务
    * 问题需要多处检索

    有可能需要*自己造一个训练数据集*（不知道怎么造），而且担心数据集污染问题

3. 细化方法问题：

    训练方式：Reverse Curriculum Learning

    先确定数据集再考虑自己造一个训练集

4. Reward

    基于标签`<rethinking>`(行为)？ -> 基于目标

5. 准备投1月ARR.

    短时间出一个结果：Follow 1篇论文作为 baseline, 直接对方法提升. 方法核心缺陷、路线选择.

    从最新的方法（**EMNLP2026选1篇：GTA-RAG**）往前找，缺的往回找，实验设置、找灵感，arxiv上找后序论文（也可以去测试新的benchmark）.

Summary:

* 测一些Baseline: 

    * RL-based:

        * GTA-RAG (主baseline, EMNLP 2025)

        * Search-R1 (COLM 2025) [Github地址](https://github.com/PeterGriffinJin/Search-R1)

        * ReSearch 
        * RouteRAG: [Github地址](https://github.com/YucanGuo/RouteRAG)

    * Training-free:

        * IRCoT (ACL2023) [Github地址](https://github.com/StonyBrookNLP/ircot)

        * HippoRAG 2 (ICML2025) 

    * 

---

这几天都比较颓废，今天要完成 OS 的 lab1 和 xv6 的2个lab，CN/NLP都没布置作业，很耐人寻味. B/S的大作业国庆找个时间干掉. 计算理论应该抓紧写掉作业1.

---

(2026.9.29-30)

列计划

---

(2026.10.1-10.7)

跑GTA-RAG的训练，不知道结果怎么样，Qwen-2.5-3B反正是复现失败了，掉了10个点，反而比baseline低了；

读完了 Search-R1, GTA-RAG, GAE, PPO, DPO, GRPO

---

## 任务清单

### 知识背景

- [x] REINFORCE 单步练习：纯 Python＋PyTorch
  - 时间：9/25，已完成

- [x] 赵世钰第 9 章：策略梯度与 REINFORCE
  - 时间：9/26，2h
  - 重点：目标函数、策略梯度、REINFORCE

- [x] 赵世钰第 10 章 P1—P2：Actor-Critic 与优势
  - 时间：9/26，1.5h
  - 配套：batch＋baseline 代码练习，2h

- [ ] 赵世钰第 7 章 TD 基础＋第 10 章 P3 重要性采样
  - 时间：9/27，2h
  - 配套：多步回报练习，2h

- [x] CS224N：按需补充 softmax、反向传播、Transformer 与语言建模
  - 时间：9/26—10/7 穿插，每次不超过 1h
  - 不要求先完成整门课程

- [x] LLM 训练细节：token 对数概率、mask、当前／旧／参考策略
  - 时间：9/28，1.5h

- 教材：[赵世钰《强化学习的数学原理》](https://github.com/MathFoundationRL/Book-Mathematical-Foundation-of-Reinforcement-Learning)
- 视频：[作者课程主页](https://www.shiyuzhao.net/opencourse)
- 课程：[CS224N](https://web.stanford.edu/class/cs224n/)

### 需要补的论文

- [x] **PPO**：[Proximal Policy Optimization Algorithms](https://arxiv.org/pdf/1707.06347)
  - 时间：9/27，1.5—2h
  - 重点：§2、§3、§5
  - 补充材料：[PPO算法详解 - 李宇的文章 - 知乎](https://zhuanlan.zhihu.com/p/689524878)
- [x] **GAE**：[Generalized Advantage Estimation](https://arxiv.org/abs/1506.02438)
  - 时间：9/28，1h
  - 重点：优势计算、γ 与 λ；证明后补
- [x] **DeepSeekMath**：[DeepSeekMath](https://arxiv.org/pdf/2402.03300)
  - 时间：9/28，1.5—2h
  - 重点：§4.1 GRPO
- [x] **Search-R1**：[Training LLMs to Reason and Leverage Search Engines with Reinforcement Learning](https://arxiv.org/pdf/2503.09516)
  - 时间：10/1，2h
  - 重点：搜索交互、奖励、训练 mask
- [ ] **Search-R1 实证研究**：[An Empirical Study on Reinforcement Learning for Reasoning-Search Interleaved LLM Agents](https://arxiv.org/abs/2505.15117)
  - 时间：10/3—10/4，1.5h
  - 重点：初始化、奖励与检索环境
- [ ] **ReSearch**：[Learning to Reason with Search for LLMs via Reinforcement Learning](https://arxiv.org/abs/2503.19470)
  - 时间：10/5—10/7，1h
  - 重点：与 Search-R1 比较
- [x] **DPO**：[Direct Preference Optimization](https://arxiv.org/pdf/2305.18290)
  - 时间：10/7 后，2h；有余力可提前
  - 重点：§3—§4；不作为 Search-R1 前置任务
- [ ] [**CaRR**](https://arxiv.org/abs/2601.06021v1)
- [ ] [**MRE 框架 (T-GRPO)**](http://arxiv.org/abs/2601.01195v1)
- [ ] GAT-RAG: 

### 复现框架和实验

- [ ] **CleanRL-PPO**：[文档与代码入口](https://docs.cleanrl.dev/rl-algorithms/ppo/)
  - 时间：9/27—9/28，合计 3h
  - 阅读普通 `ppo.py`，运行小环境
  - 定位 rollout、GAE、策略损失、价值损失

- [x] **CS336 Assignment 5**：[官方仓库](https://github.com/stanford-cs336/assignment5-alignment)
  - 时间：9/28 选做 2h，未完成部分 10/7 后继续
  - 优先：组内优势、GRPO 损失、token mask
  - 暂不要求完成全部训练实验

- [ ] **Search-R1**：[官方仓库](https://github.com/PeterGriffinJin/Search-R1)
  - 10/1：固定代码与环境，启动模型和检索，跑 5—10 条轨迹
  - 10/2：固定数据划分，跑 32 条轨迹，接通评测
  - 10/3：完成最小 RL 更新、checkpoint 保存与重载
  - 10/4：开展小规模答案奖励 RL 训练
  - 10/5：比较训练前后结果，分析约 40 条轨迹
  - 10/6：构造 10—20 个有效干预题对
  - 10/7：整理结果表、运行说明和两页研究备忘录

### 时间与优先级备注

- 每天主要任务控制在 6—7h，超出部分顺延
- 必做：策略梯度基础 → PPO／GRPO 核心 → Search-R1 基线
- 可顺延：完整 CS336 作业、DPO、第二套训练框架
- 3 张 A100 40GB：先试 3B 量级模型，依据显存与吞吐调整
- 10/3 若训练未跑通，后续优先排错，取消假期新增奖励
- 10/7 目标：可复现基线＋错误诊断＋下一步研究假设

### 投稿计划

|             | 截稿ddl    | 结果       | Track                                                        |
| ----------- | ---------- | ---------- | ------------------------------------------------------------ |
| DASFAA 2027 | 2026.11.25 | 2027.1.25  | **Data Science & Intelligence and Advanced Applications**: Data science, artificial intelligence, and intelligent data management techniques for knowledge discovery, analytics, and advanced applications. |
| COLT 2027   | ~ 2027.2.5 | ~ 2027.5.4 |                                                              |
|             |            |            |                                                              |
| IJCAI 2027  | ~2027.1.20 |            |                                                              |
| ACL 2027    | ~2027.1.6  |            |                                                              |

ARR: 1年4次 1/5/8/10月 可投 NAACL / EMNLP / ACL / ...

---

## 文献

> * <a id="1">[1]</a>：[ACL 2026 Main] Temp-R1: A Unified Autonomous Agent for Complex Temporal KGQA via Reverse Curriculum Reinforcement Learning，论文地址: https://arxiv.org/abs/2601.18296，Github仓库: https://github.com/zjukg/Temp-R1，阅读笔记: [跳转此处](./Temp-R1.md)
> * <a id="2">[2]</a>：[ACL 2026 Main] CoG: Controllable Graph Reasoning via Relational Blueprints and Failure-Aware Refinement over Knowledge Graph，论文地址: https://arxiv.org/abs/2601.11047，Github仓库: https://github.com/zjukg/CoG，阅读笔记: [跳转此处](./CoG.md)
> * <a id="3">[3]</a>：[Arxiv 2601.00536] Retrieval--Reasoning Processes for Multi-hop Question Answering: A Four-Axis Design Framework and Empirical Trends，论文地址：https://arxiv.org/abs/2601.00536
> * <a id="4">[4]</a>：[ACL 2025 Finding] GNN-RAG: Graph Neural Retrieval for Large Language Model Reasoning，论文地址: [ACL链接](https://aclanthology.org/2025.findings-acl.856.pdf)  [Arxiv链接](https://arxiv.org/abs/2405.20139)，阅读笔记：[跳转此处](./GNN_RAG.md)

