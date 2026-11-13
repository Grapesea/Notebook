# [ACL 2026] CoG: Controllable Graph Reasoning via Relational Blueprints and Failure-Aware Refinement over Knowledge Graph

> * 论文地址: [https://arxiv.org/abs/2601.18296](https://arxiv.org/abs/2601.18296)
>
> * Github仓库: [https://github.com/zjukg/CoG](https://github.com/zjukg/CoG)

原先工作的Problem: 现有 LLM-driven graph agent 范式（ToG、PoG 等）采用 **plan–retrieve–generate** 循环迭代扩展证据链，但在复杂场景下表现不稳定，作者将其归因为 cognitive rigidity（认知刚性）——不论任务不确定性如何，都套用同质化（homogeneous）的搜索策略。这种刚性具体表现为两类相互强化的问题：

1. 无偏探索导致错误的展开（Error Cascading from Indiscriminate Exploration）：无差别探索无法区分高价值信号与噪声，一次早期的关系选择失误（如选 *contains* 而非 *adjoins*）会将 agent 暴露给规模大得多的候选集，噪声主导推理分支，导致不可逆的轨迹偏离
2. 短视决策导致结构性不匹配（Structural Misalignment from Myopic Decisions）：过度依赖局部语义匹配而忽视全局逻辑约束，选中"看似相关但结构错误"的关系（如 *actor* 而非 *director*），使得下游约束（如 runtime 检查）无法满足，被迫过早终止

---

CoG是一个针对**在知识图谱上做可控推理**的无需训练的框架，分为以下两层：

* Relational Blueprint Guidance （Planning）
* Failure-Aware Refinement （Correction）

构建方法论（Methodology）：

* 离线的蓝图构建（Offline relational blueprint construction）：

    从训练集的 gold SPARQL 路径中，通过规则化去实例化（去除 Freebase ID 等实体标识，只保留 relation 谓词序列）抽象出**关系蓝图模板**（relational blueprint template），并对模板去重、构建语义索引，形成一个结构先验的构想图.

    具体过程：

    * 对于问题 $Q$，对其中所有的 topic entity 做掩码处理，得到$Q_m = \text{Mask}(Q,E_0)$，然后使用预先训练好的 sentence encoder $f(\cdot)$，召回其中的 Top-K，用 hybrid copy-adapt strategy 处理后形成最终的blueprint $S_{\text{BP}} = \langle r_1^{\text{BP}}, \cdots, r_L^{\text{BP}} \rangle$.

* 系统1-关系蓝图构建下的探索（Online Blueprint-Guided KG Exploration）：

    * 初始设置：知识图谱 $\mathcal{G}=(\mathcal{E},\mathcal{R})$，关系路径 $z=(r_1,\dots,r_L)$ 描述与具体实体无关的抽象查询模式，推理路径 $p_z$ 则是 $z$ 在 $\mathcal{G}$ 上以具体实体实例化的结果 $e_0 \xrightarrow{r_1} e_1 \dots \xrightarrow{r_L} e_L$，将问题 $Q$ 抽取出初始 topic entities 集合 $E_0 = \{t_0\}$；

    * Candidate relation collection and **blueprint guided reranking**：在每一步的 $E_{t-1}$的基础上，将所有可触及的关系（reachable relations）收集成候选关系集合 $\mathcal{R}_{\text{cand}}$ . CoG 将 $S_{\text{BP}}$ 注入，执行选择将 frontier 扩展为 $E_t$，并对新证据做约束验证；已验证的三元组与中间结论存入 working memory $\mathcal{M}$ 供后续决策使用. 这个过程中需要逐步更新子目标集合 $\mathcal{O}_t = \{o_0,\cdots, o_t \}$，作为后续计算的辅助.

        定义槽位对齐索引（slot-alignment index）用作分数评估指标，记 $\pi(0) = 1$，递推规则：

        $$
        \pi(t) = \arg \max_{j \in [1,L]}\text{sim}(h(o_t), h(r_j^{\text{BP}}))
        $$

        其中 $h(\cdot)$ 是文本 encoder，采用余弦相似度计算，保证$\forall j \in [\pi(t-1), L]$（$\pi(t)$单调递增）和 $\pi(t) = L$（若step > L）

        定义分数信号：

        $$
        \begin{aligned}
        \phi_{\text{loc}}(o_t, r) = \text{sim}(h(o_t), h(r))\\
        \phi_{\text{step}}(r, r_{\pi(t)}^{\text{BP}}) = \text{sim}(h(r), h(r_{\pi(t)}^{\text{BP}}))\\
        \phi_{\text{glob}}(S_{\text{BP}}, r) = \max_{j \in [1,L]}\text{sim}(h(r), h(r_{j}^{\text{BP}}))
        \end{aligned}
        $$

        loc指的是local relevance， step 指的是 step-wise relevance，glob 指的是 global compatibility，于是对于每个 $r \in \mathcal{R}_{\text{rand}}$，可以生成融合分数（预先设置权重 $\lambda_\text{loc} = 0.6, \lambda_\text{step} = 0.25, \lambda_\text{glob} = 0.15$）：

        $$
        \text{Score}(r) = \lambda_{\text{loc}}\phi_{\text{loc}}(o_t, r) + \lambda_{\text{step}}\phi_{\text{step}}(r, r_{\pi(t)}^{\text{BP}}) + \lambda_{\text{glob}}\phi_{\text{glob}}(S_\text{BP}, r)
        $$

        据此，我们重排 $\mathcal{R}_{\text{cand}}$，保留 top-scoring 关系形成紧凑的 $\tilde{\mathcal{R}}_{\text{cand}}$.

    * **Blueprint-guarded pruning**：用 LLM 结合 $(Q, o_t, \mathcal{M})$ 对 $\tilde{\mathcal{R}}_{\text{cand}}$ 进一步精炼，并施加 Structure-Consistency Safeguard——最终候选集为 LLM 选中的关系 与 按 $\phi_{\text{step}}$ 排名第一的候选的**并集**. 这一双源选择设计是为了在语义细粒度判断（LLM）与结构一致性判断（$\phi_{\text{step}}$）之间取长补短，避免单一视角偏差.

    * State update and answer generation：每步扩展后，LLM 基于当前子目标状态 $o_t$ 与 $\mathcal{M}$ 中已验证证据做 sufficiency check：若充分则综合已验证轨迹与子目标状态生成最终答案；若不充分，则进一步判断"证据缺失（可通过扩展解决）"还是"早期错误决策导致轨迹偏离（需要 System 2 介入）

* 系统2-失败感知的诊断式回溯（Failure-aware Refinement）：

    * 当检测到失败信号（如停滞或证据不足）时，LLM 结合working memory中的推理轨迹 $\mathcal{T}=[e_0,r_1,e_1,\dots]$ 以及被剪枝分支的摘要，定位到应对偏差负责的决策点 $t_{\text{err}}$；随后执行有针对性的回溯：将 frontier 还原到 $t_{\text{err}}$ 之前的状态，召回此前被过早剪枝但结构相关的候选，恢复扩展；
    * Grounded Inference（兜底机制）：极端情况下（KG 缺失关键边），若重路由仍无法恢复可验证证据链，CoG 聚合已验证路径片段与未满足约束，提示 LLM 在这一受限有效上下文内合成答案，而非自由生成，从而在避免过早终止的同时抑制参数化幻觉.

---

本文架构优势：取代现有 LLM-driven graph agent 中"千篇一律"的搜索策略，在不训练任何参数的前提下，同时缓解了多跳 KGQA 中的 error cascading（噪声主导错误分支）与 structural misalignment （局部语义匹配导致的全局结构错位）两大顽疾.

---

Case study：

