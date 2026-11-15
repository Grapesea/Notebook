# 科研学习日志

## 论文阅读列表

| 简略标题                                 | 发表时间/会议       | 阅读情况 | 标签                          |
| ---------------------------------------- | ------------------- | -------- | ----------------------------- |
| [PPO](./PPO.md)                          | ICML 2017           | √        | RL, LLM                       |
| [GAE](./GAE.md)                          | ICLR 2016           | √        | RL                            |
| [DPO](./DPO.md)                          | NeurIPS 2023 Oral   | √        | RL, LLM                       |
| [DeepSeekMath (GRPO)](./DeepseekMath.md) | 2024.4              | √        | RL, LLM, Reasoning            |
| [GNN-RAG](./GNN-RAG.md)                  | ACL 2025 Findings   | +        | GNN, RAG, KG                  |
|                                          |                     |          |                               |
| [Search-R1](./Search-R1.md)              | COLM 2025           | √        | RL, LLM, Reasoning            |
| [Search-o1](./Search-o1.md)              | EMNLP 2025 Main     | +        | RL, LLM, Reasoning            |
| [GTA-RAG](./GTA-RAG.md)                  | EMNLP 2026 Findings | √        | RL, KG, RAG, Reasoning        |
| [CoG](./CoG.md)                          | ACL 2026 Main       | √        | RAG, LLM, Reasoning           |
| [Temp-R1](./Temp-R1.md)                  | ACL 2026 Main       | √        | TKG, RAG, Reasoning           |
|                                          |                     |          |                               |
| [STAR](./STAR.md)                        | IEEE J-STSP 2023    | +        | 计算机网络, Signal Processing |
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

(2026.10.8)

Search-R1补完笔记，GTA-RAG和RouteRAG还没跑完，codex崩了.

---

(2026.10.9)

| 标题                                                         | 会议 / 年份                     | 论文网址                                          | 一句话摘要                                                   |
| ------------------------------------------------------------ | ------------------------------- | ------------------------------------------------- | ------------------------------------------------------------ |
| Trustworthy Alignment of Retrieval-Augmented Large Language Models via Reinforcement Learning | **ICML 2024**                   | https://proceedings.mlr.press/v235/zhang24bg.html | 通过强化学习协调外部检索证据与模型参数知识之间的冲突，使模型在存在可靠上下文时更多依赖外部证据而非自身记忆。 |
| RLKGF: Reinforcement Learning from Knowledge Graph Feedback Without Human Annotations | **ACL 2025 Findings**           | https://aclanthology.org/2025.findings-acl.344/   | 利用知识图谱中的结构连接和语义信息自动构造奖励信号，在无需人工反馈的情况下训练模型进行更可靠的知识推理。 |
| Search Wisely: Mitigating Sub-optimal Agentic Searches By Reducing Uncertainty | **EMNLP 2025 Main**             | https://aclanthology.org/2025.emnlp-main.998/     | 提出 β-GRPO，将模型置信度/不确定性纳入强化学习过程，训练 Agent 更准确地判断何时应该搜索以及何时无需搜索。 |
| Chaining the Evidence: Robust Reinforcement Learning for Deep Search Agents with Citation-Aware Rubric Rewards (CaRR) | **ACL 2026 Main（Long Paper）** | https://aclanthology.org/2026.acl-long.950/       | 将复杂问题拆分为可验证的证据与引用子目标，通过 citation-aware process reward 奖励模型构建完整、可验证的多跳证据链。 |
| STAMP: Provenance-Guided Credit Assignment for Deep Search Agents | **arXiv 2026（Preprint）**      | https://arxiv.org/abs/2607.11172                  | 根据关键证据最早由哪个搜索动作获得来进行 provenance-guided credit assignment，从而把奖励更准确地分配给真正有贡献的推理/搜索步骤。 |
| EvidenceRL: Reinforcing Evidence Consistency for Trustworthy Language Models | **arXiv 2026（Preprint）**      | https://arxiv.org/abs/2603.19532                  | 将答案正确性奖励与证据一致性/蕴含奖励结合，鼓励模型生成能够被检索证据直接支持的推理过程。 |
| Source-Aware Reranking for Retrieval-Augmented Generation: A Reliability Prior Approach | **arXiv 2026（Preprint）**      | https://arxiv.org/abs/2607.22584                  | 为不同信息来源引入不同的可靠性先验，并与语义相关性结合进行重排序，与“不同来源赋予不同 confidence 权重”的思想高度相关。 |
| KbSD: Knowledge Boundary aware Self-Distillation for Behavioral Calibration in Agentic Search | **arXiv 2026（Preprint）**      | https://arxiv.org/abs/2606.29863                  | 显式建模模型参数知识的确定性和外部检索质量，使 Agent 学习何时相信内部记忆、何时搜索以及何时应当放弃回答。 |

---

(2026.10.10-10.23)

这两周很忙，后台实验一直在做但是没效果，直到10.23才重新全身心投入继续看论文和分析bad case.

拿到了gpt-5 的token，为什么 deepseek-v4.1-flash生成轨迹效果差这么多？

---

(2026.10.24-25)

很累，看了几篇论文，目前做的东西感觉还是棘手，失败反思.

---

(2026.10.26)

看了几篇调研找找方向，纯瞎想idea没道理：

* [EMNLP2025] StepSearch: Igniting LLMs Search Ability via Step-Wise Proximal Policy Optimization

    Github仓库：https://github.com/Zillwang/StepSearch

    论文地址：

* [ACL2024] Making Long-Context Language Models Better Multi-Hop Reasoners

    论文地址：[aclanthology.org/2024.acl-long.135.pdf](https://aclanthology.org/2024.acl-long.135.pdf)



> 先暂缓扩展 baseline 列表，把已经跑通的主 baseline 固定下来：
>
> 1. **保留失败运行的配置、checkpoint 和轨迹。** 不覆盖它，记录它究竟失败在哪一层。
> 2. **做一张错误分布表。** 区分没检索到、检索到但没用、中间实体错误、过早停止、最终答案提取错误等；可以多标签。
> 3. **只选一个占比值得关注、又能干预的问题。**
> 4. **做一次无训练的配对干预。** 同时统计“错→对”和“对→错”，而不只看成功救回的案例。
> 5. **有信号再做 baseline／新方法短程对照。** 同时看目标行为、EM/F1 和成本。
> 6. **短程结果可解释后，再决定完整训练或修改机制。**





> 每次实验启动前写下五句话就够了：
>
> 我的假设是什么？
> 这次唯一的主要改动是什么？
> 如果假设成立，除了总分，还应该观察到什么？
> 最多投入多少预算，什么情况提前停止？
> 结果为正或为负时，下一步分别做什么？

---

（2026.10.28）

目前的发现：（完全按照 GTA-RAG 的实验配置做的，gpt-5 生成）

复现情况对照 （Qwen-2.5-3B）：

| 数据集 | 论文 EM / F1 | 复现 EM / F1 | 差值（百分点） |
|---|---:|---:|---:|
| HotpotQA | 52.90 / 63.90 | 52.40 / 63.66 | −0.50 / −0.24 |
| 2WikiMultihopQA | 57.30 / 64.10 | 52.10 / 58.56 | −5.20 / −5.54 |
| MuSiQue | 29.00 / 38.20 | 31.00 / 40.00 | +2.00 / +1.80 |
| 三个数据集平均 | 46.40 / 55.40 | 45.17 / 54.08 | −1.23 / −1.32 |

实验结果基本上能复现出来，有一些小波动.



一些 bad case 分析：







| 标题 | 会议 / 年份 | 论文网址 | 一句话摘要 |
|---|---|---|---|
| Trustworthy Alignment of Retrieval-Augmented Large Language Models via Reinforcement Learning | **ICML 2024** | https://proceedings.mlr.press/v235/zhang24bg.html | 用 RL 协调外部证据与参数知识冲突，使模型在可靠检索上下文存在时更依赖证据 |
| RLKGF: Reinforcement Learning from Knowledge Graph Feedback Without Human Annotations | **ACL 2025 Findings** | https://aclanthology.org/2025.findings-acl.344/ | 利用知识图谱结构自动构造反馈，无需人工标注即可训练知识推理能力 |
| **Self-RAG: Learning to Retrieve, Generate, and Critique through Self-Reflection** | **ICLR 2024** | https://proceedings.iclr.cc/paper_files/paper/2024/hash/25f7be9694d7b32d5cc670927b8091e1-Abstract-Conference.html | 用 reflection tokens 学习何时检索、检索结果是否相关以及生成内容是否被证据支持，是 adaptive retrieval 的早期代表 |
| Search Wisely: Mitigating Sub-optimal Agentic Searches By Reducing Uncertainty | **EMNLP 2025 Main** | https://aclanthology.org/2025.emnlp-main.998/ | 用 uncertainty/confidence 建模是否需要搜索，并通过 β-GRPO 减少 over-search 与 under-search |
| **StepSearch: Igniting LLMs Search Ability via Step-Wise Proximal Policy Optimization** | **EMNLP 2025 Main** | https://aclanthology.org/2025.emnlp-main.1106/ | 用 information gain、redundancy penalty 等 step-wise reward 评价每一次检索，缓解纯 global reward 的稀疏性 |
| **LeTS: Learning to Think-and-Search via Process-and-Outcome Reward Hybridization** | **EMNLP 2025 Main** | https://aclanthology.org/2025.emnlp-main.257/ | 将中间 think-search 的 process reward 与最终 outcome reward 混合，直接针对只看最终答案的问题 |
| **An Empirical Study on Reinforcement Learning for Reasoning-Search Interleaved LLM Agents** | **arXiv 2025（Preprint）** | https://arxiv.org/abs/2505.15117 | 系统研究 reward、基模和搜索引擎影响，并发现 intermediate retrieval reward 的收益并不稳定 |
| *Chaining the Evidence: Robust Reinforcement Learning for Deep Search Agents with Citation-Aware Rubric Rewards (CaRR)* | ***ACL 2026 Main（Long Paper）*** | *https://aclanthology.org/2026.acl-long.950/* | *将复杂任务拆为可验证证据与引用子目标，用 citation-aware process reward 强化完整证据链* |
| STAMP: Provenance-Guided Credit Assignment for Deep Search Agents | **arXiv 2026（Preprint）** | https://arxiv.org/abs/2607.11172 | 根据关键证据首次由哪个搜索动作获得进行 provenance credit assignment，把奖励分给真正有效的步骤 |
| EvidenceRL: Reinforcing Evidence Consistency for Trustworthy Language Models | **arXiv 2026（Preprint）** | https://arxiv.org/abs/2603.19532 | 联合答案正确性与 evidence entailment / consistency reward，使输出更受检索证据支撑 |
| KbSD: Knowledge Boundary aware Self-Distillation for Behavioral Calibration in Agentic Search | **arXiv 2026（Preprint）** | https://arxiv.org/abs/2606.29863 | 联合建模内部知识确定性与外部检索质量，学习 search / answer / abstain 的行为边界 |
| **Atom-Searcher: Enhancing Agentic Deep Research via Fine-Grained Atomic Thought Reward** | **arXiv 2025（Preprint）** | https://arxiv.org/abs/2508.12800 | 将 reasoning 拆成 Atomic Thoughts，用细粒度 process reward 缓解 outcome-only RL 的稀疏监督 |



打算提的问题：

* 目前 qwen-2.5-3B 一次训练+测评 就需要3-4天，非常慢，7B耗时更长，完全没办法跑完；

    应该怎么找算力？（12月以前科研经费还剩￥2000 可以用去租卡，但是autodl等平台的A100卡似乎都被租完了）

* chatgpt-5 生成的2000条轨迹本身问题比较多（准确率 80%），论文复现结果（3B上）其实还可以，基本能成功达到指标附近的值（Deepseek生成的轨迹问题更大）

* idea 怎么快速验证？ bad case 分析的粒度该怎么做？

    GTA-RAG 训练一轮太久了，有点想要通过几个信号融进模型中来看效果

* 自己的 idea 怎么细化和深入探索比较好？confidence 这个信号感觉太模糊了，即使选了几种辅助的信号也没有特别好

---

(2026.10.29-30)

开组会，得到的信息是：

1. 先去统计bad case的分布，看自己的架构对某一类或者几类的解决和可解释性是否好；
2. 算力不足应该是因为近期的CVPR，再等一段时间会好一点；
3. 添加过程信号来看情况，看指标问题
4. 看论文的目的性：去看motivation是如何去驱动reward函数设计的，怎么得出的方法论
5. confidence函数的建模和处理是一大难点，我对“合适的方案”压根没有基本概念

---

(2026.11.1-11.5)

排查了轨迹问题. 专业课事情太多，烦死了.

[【学习天地】如何写好一篇科技论文](https://www.cc98.org/topic/6681907)

看的论文：

* [ICLR 2026] IGPO： [Information Gain-based Policy Optimization: A Simple and Effective Approach for Multi-Turn Search Agents](https://arxiv.org/pdf/2510.14967)

* [arxiv 2026] KnowGPO：[KnowGPO: Knowledge-Grouped Policy Optimization for Search Agents](https://arxiv.org/pdf/2610.22331)

* [ACL 2026 Findings] CriticSearch：[CriticSearch: Fine-Grained Credit Assignment for Search Agents via a Retrospective Critic](https://aclanthology.org/2026.findings-acl.596.pdf)
* [ACL 2026 Main] CaRR：[Chaining the Evidence: Robust Reinforcement Learning for Deep Search Agents with Citation-Aware Rubric Rewards](https://aclanthology.org/2026.acl-long.950/)

---

(2026.11.13)

DecomposeR

[ACL2025] Structure-aware Domain Knowledge Injection for Large Language Models

[ACL2026] KoCo: Conditioning Language Model Pre-training on Knowledge Coordinates

---

## 投稿计划

|                 | 分级 | 截稿ddl                         | 结果          | Track                                                        |
| --------------- | ---- | ------------------------------- | ------------- | ------------------------------------------------------------ |
| ~~DASFAA 2027~~ | B    | ~~2026.11.25~~                  | ~~2027.1.25~~ | ~~**Data Science & Intelligence and Advanced Applications**: Data science, artificial intelligence, and intelligent data management techniques for knowledge discovery, analytics, and advanced applications.~~ |
| COLT 2027       | B    | 2027.1.30 20:00                 |               |                                                              |
|                 |      |                                 |               |                                                              |
| ~~IJCAI 2027~~  | B    | ~~摘要2027.1.4; 全文2027.1.11~~ |               |                                                              |
| ACL 2027 (ARR)  | A    | 2027.1.5 20:00                  |               |                                                              |
| SIGIR 2027      | A    | 2027.1.22 20:00                 |               |                                                              |
| KR 2027         | B    | 2027.4.29 20:00                 |               |                                                              |

ARR: 1年4次 1/5/8/10月 可投 NAACL / EMNLP / ACL / ...

---

## 文献

> * <a id="1">[1]</a>：[ACL 2026 Main] Temp-R1: A Unified Autonomous Agent for Complex Temporal KGQA via Reverse Curriculum Reinforcement Learning，论文地址: https://arxiv.org/abs/2601.18296，Github仓库: https://github.com/zjukg/Temp-R1，阅读笔记: [跳转此处](./Temp-R1.md)
> * <a id="2">[2]</a>：[ACL 2026 Main] CoG: Controllable Graph Reasoning via Relational Blueprints and Failure-Aware Refinement over Knowledge Graph，论文地址: https://arxiv.org/abs/2601.11047，Github仓库: https://github.com/zjukg/CoG，阅读笔记: [跳转此处](./CoG.md)
> * <a id="3">[3]</a>：[Arxiv 2601.00536] Retrieval--Reasoning Processes for Multi-hop Question Answering: A Four-Axis Design Framework and Empirical Trends，论文地址：https://arxiv.org/abs/2601.00536
> * <a id="4">[4]</a>：[ACL 2025 Finding] GNN-RAG: Graph Neural Retrieval for Large Language Model Reasoning，论文地址: [ACL链接](https://aclanthology.org/2025.findings-acl.856.pdf)  [Arxiv链接](https://arxiv.org/abs/2405.20139)，阅读笔记：[跳转此处](./GNN-RAG.md)

