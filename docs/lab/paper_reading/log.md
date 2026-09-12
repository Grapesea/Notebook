# Multi-hop Reasoning

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



> <a id="1">[1]</a>：[ACL 2026 Main] Temp-R1: A Unified Autonomous Agent for Complex Temporal KGQA via Reverse Curriculum Reinforcement Learning，论文地址: https://arxiv.org/abs/2601.18296，Github仓库: https://github.com/zjukg/Temp-R1，阅读笔记: [跳转此处](./[ACL2026]Temp_r1.md)
>
> <a id="2">[2]</a>：[ACL 2026 Main] CoG: Controllable Graph Reasoning via Relational Blueprints and Failure-Aware Refinement over Knowledge Graph，论文地址: https://arxiv.org/abs/2601.11047，Github仓库: https://github.com/zjukg/CoG，阅读笔记: [跳转此处](./[ACL2026]CoG.md)
>
> <a id="3">[3]</a>：[Arxiv 2601.00536] Retrieval--Reasoning Processes for Multi-hop Question Answering: A Four-Axis Design Framework and Empirical Trends，论文地址：https://arxiv.org/abs/2601.00536
>
> <a id="4">[4]</a>：[ACL 2025 Finding] GNN-RAG: Graph Neural Retrieval for Large Language Model Reasoning，论文地址: [ACL链接](https://aclanthology.org/2025.findings-acl.856.pdf)  [Arxiv链接](https://arxiv.org/abs/2405.20139)，阅读笔记：[跳转此处](./[ACL2025]GNN-RAG.md)

