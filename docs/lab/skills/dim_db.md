# 分析维度库 v4.0（知识图谱 / RAG / AI 方向）

## 使用指引

**选取原则：** 优先覆盖论文主图（Figure 1/2）所展示的核心 pipeline 中的关键模块。若论文创新横跨多个维度，可选取更多；若创新高度集中，3 个维度即可。每个维度下的分析深度应与论文叙述的篇幅匹配。

**维度间关系提示（防止混淆）：**
- **Retrieval Strategy & Index Design** 与 **Knowledge Graph Embedding & Representation** 有交集：前者侧重非结构化文本的召回/索引架构，后者侧重结构化图谱实体关系的向量化表征。若论文核心贡献在于图谱本身的表征学习（如 TransE / RotatE / GNN-based embedding），应选后者。
- **Graph Reasoning & Multi-hop Traversal** 与 **Generation & Answer Grounding** 互补：前者聚焦"如何在图上找证据"，后者聚焦"如何基于证据生成忠实答案"。
- **Query Understanding & Rewriting** 与 **Agentic RAG & Multi-step Planning** 的区分：前者指对单次 query 的改写/分解（如 HyDE、query decomposition）；后者指多轮、带工具调用与反思的动态检索-生成循环。
- **Knowledge Editing & Model Updating** 与 **Fine-tuning & Alignment** 互补：前者关注对已训练模型/知识库的局部、增量式修正（不重新全量训练），后者关注整体参数层面的训练范式。
- **Scaling Laws & Data/Model Efficiency** 与 **Data Engine, Benchmark & Evaluation** 互补：前者关注宏观规律（数据量-性能曲线、模型尺寸效应），后者关注数据工程与评测体系的具体实现。
- **Hallucination Detection & Mitigation** 与 **Safety, Robustness & Attribution** 侧重不同：前者聚焦"生成内容是否与检索证据一致"这一具体问题，后者是更广义的鲁棒性/可信度议题，二者常需搭配分析。
---

## 维度库

| 维度名称                                             | 适用场景                                                     | 关注要点                                                     |
| ---------------------------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| **Query Understanding & Rewriting**                  | 涉及 query 改写、分解、扩展的 RAG 类论文                     | Query decomposition、HyDE / query2doc、意图识别、多子查询生成与聚合策略 |
| **Retrieval Strategy & Index Design**                | 涉及检索召回、索引结构的论文                                 | Dense / sparse / hybrid retrieval、向量索引结构（HNSW / IVF）、embedding 模型选型、召回粒度（chunk / passage / document） |
| **Knowledge Graph Construction & Extraction**        | 以图谱构建、信息抽取为核心方法的论文                         | NER / Relation Extraction / Entity Linking、schema 归纳或对齐、开放域抽取 vs 受限 schema、抽取质量校验 |
| **Knowledge Graph Embedding & Representation**       | 核心贡献在于**图谱实体关系的向量化表征学习**                 | 平移模型（TransE / RotatE）、GNN-based embedding、知识补全（KGC）、表征质量评估方式 |
| **Graph Reasoning & Multi-hop Traversal**            | 需要在图谱上做多跳推理、路径搜索的论文                       | 路径检索算法、子图召回（subgraph retrieval）、GNN message passing、多跳问答中的证据链构建 |
| **Cross-modal / Structured-Text Fusion & Alignment** | 需要融合结构化知识（KG/表格）与非结构化文本的论文            | 融合机制（cross-attn / early-late fusion / prompt 拼接）、结构化-文本对齐损失、图文/图表联合表征 |
| **Reranking & Relevance Optimization**               | 涉及召回结果二次排序的论文                                   | Cross-encoder rerank、listwise / pairwise 排序损失、rerank 与生成质量的因果关系 |
| **Generation & Answer Grounding**                    | 关注最终答案生成与证据锚定的论文                             | 引用/溯源机制、faithfulness 约束、生成解码策略（copy mechanism / constrained decoding） |
| **Hallucination Detection & Mitigation**             | 以降低幻觉、提升事实一致性为核心目标的论文                   | 幻觉检测方法（NLI-based / self-consistency）、事实核查、检索证据与生成内容的一致性约束 |
| **Knowledge Editing & Model Updating**               | 涉及对模型内部知识做局部修正/更新的论文                      | 定位-编辑方法（ROME / MEMIT 类）、增量式知识注入、编辑的副作用（collateral damage）评估 |
| **Memory & Long-Context Management**                 | 涉及长期记忆、长上下文处理、对话历史管理的论文               | 外部记忆模块（episodic / retrieval-augmented memory）、长上下文压缩、context window 处理策略 |
| **Agentic RAG & Multi-step Planning**                | 引入多轮检索-生成循环、工具调用、自我反思的论文              | ReAct / self-RAG 类框架、检索时机决策（when to retrieve）、工具调用与规划、closed-loop 迭代与终止条件 |
| **Prompt Engineering & In-context Learning**         | 核心贡献在于 prompt 设计或上下文学习范式的论文               | Few-shot 示例选择策略、CoT / ToT 提示范式、prompt 对性能的敏感性分析 |
| **Fine-tuning & Alignment**                          | 涉及模型微调、对齐训练的论文                                 | SFT / RLHF / DPO 等训练范式、指令数据构建、对齐目标与奖励设计 |
| **Data Engine, Benchmark & Evaluation**              | 数据收集/生成/增强方法类论文，或以提出 Benchmark 为核心贡献的论文 | 数据来源与规模、自动化标注/筛选、数据质量与多样性、benchmark 设计（任务覆盖度、评估指标设计、baseline 选取合理性） |
| **Scaling Laws & Data/Model Efficiency**             | 研究模型/数据规模效应的论文                                  | 数据量-性能 scaling 关系（power law 拟合）、数据多样性 vs 数量的权衡、模型尺寸与能力的相变点、检索库规模对效果的边际收益 |
| **Test-Time Compute & Adaptive Retrieval**           | 在推理阶段动态调整计算量或检索策略的论文                     | 自适应检索次数、难度感知的计算分配、test-time self-correction、推理延迟与准确率的 trade-off |
| **Safety, Robustness & Attribution**                 | 强调鲁棒性、可信度与可解释性的论文                           | 分布外泛化、对抗扰动、可追溯性（provenance/attribution）、隐私与知识产权风险 |
| **System & Infrastructure Co-design**                | 涉及系统/工程层面创新的论文                                  | 向量数据库选型与工程实现、serving 延迟优化、模型压缩（量化/蒸馏）用于部署、成本与吞吐权衡 |
| **Multi-Agent & Collaborative Reasoning**            | 多智能体协作、辩论式推理类论文                               | 通信机制（显式/隐式）、角色分工（proposer/critic/verifier）、集中式 vs 去中心化协作、协作推理中的一致性达成 |