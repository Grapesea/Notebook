# [ACL 2026] Temp-R1: A Unified Autonomous Agent for Complex Temporal KGQA via Reverse Curriculum Reinforcement Learning

> * 论文地址: [https://arxiv.org/abs/2601.18296](https://arxiv.org/abs/2601.18296)
>
> * Github仓库: [https://github.com/zjukg/Temp-R1](https://github.com/zjukg/Temp-R1)
> * [Connected Papers](https://www.connectedpapers.com/main/e03ec55dfd5fe4ecc9a3d4766652d154601e6368/Connected-Papers-|-Find-and-explore-academic-papers/graph)

原先工作的Problem: 现有 TKGQA 方法通常采用由 planner、retriever、generator 等模块组成的固定工作流，不仅依赖昂贵的闭源 LLM API，也限制了模型根据问题难度自主调整推理策略的能力。将 Search-R1 等 RL-based search agent 直接用于 TKGQA 时，还存在以下问题：

1. 内部思考过载（Overloaded Internal Reasoning）：单一的 `<think>` 同时承担搜索规划、语义过滤和时间排序，复杂时序问题中容易遗漏约束，甚至对已经检索到的正确事实得出错误结论；
2. 强化学习中的捷径陷阱（The Shortcut Trap in Reinforcement Learning）：MULTITQ 等数据集中简单问题占多数，直接训练会使 agent 过早学会 `<search> → <answer>` 等短路径，在简单样本上取得高 reward 后停止探索复杂的 action combination，形成 path dependency.

<center><img src="./figures/Temp-r1/0.png" style="zoom:40%;" /></center>

<center><img src="./figures/Temp-r1/1.png" style="zoom:60%;" /></center>

---

Temp-R1 是一个面向**复杂时序知识图谱问答（TKGQA）**的端到端 autonomous agent，通过以下四部分学习自主搜索与时序推理：

* Expanded Action Space
* SFT Cold Start
* Group Relative Policy Optimization（GRPO）
* Reverse Curriculum Learning

<center><img src="./figures/Temp-r1/2.png" style="zoom:60%;" /></center>

工作流：

* **Rollout Loop（Expanded Action Space）**：

    将 TKGQA 建模为 MDP。除外部检索动作 `<search>` 外，Temp-R1 将 `<plan>`、`<filter>` 和 `<rank>` 从通用 `<think>` 中显式拆分出来：`<plan>` 分析问题类型、时间约束和子问题，`<filter>` 按语义及时间约束过滤事实，`<rank>` 按时间戳排序，最后由 `<answer>` 终止 rollout.

    $$
    \mathcal A=\mathcal A_{\text{internal}}\cup\mathcal A_{\text{external}},\qquad
    \mathcal A_{\text{internal}}=\{\texttt{<plan>},\texttt{<filter>},\texttt{<rank>}\},\quad
    \mathcal A_{\text{external}}=\{\texttt{<search>}\}.
    $$

* **SFT Cold Start**：

    使用 GPT-4o 生成并过滤约 1,000 条高质量轨迹，使 base model 先学会合法的 tag 格式和基本 action sequence。SFT 只对 agent 生成的 token 计算 masked cross-entropy，system prompt、用户问题和检索结果不计算 loss：

    $$
    \mathcal L_{\text{SFT}}(\theta)=-\frac{1}{T}\sum_{t=1}^{T}m_t\log\pi_\theta(x_t\mid x_{<t}).
    $$

* **GRPO with TKG**：

    从 SFT policy 出发，对每个问题采样 $G$ 条 rollout trajectory，并根据组内 reward 计算 relative advantage：

    $$
    \hat A_i=\frac{r_i-\operatorname{mean}(\{r_k\})}{\operatorname{std}(\{r_k\})+\eta}.
    $$

    使用的 reward function 只判断最终答案是否正确：

    $$
    R=\begin{cases}
    1,&a_{\text{pred}}=a_{\text{gold}},\\
    0,&\text{otherwise}.
    \end{cases}
    $$

* **Reverse Curriculum Learning Strategy**：

    传统 curriculum learning 从简单问题逐步过渡到困难问题，容易让 agent 先学会短路径。Temp-R1 反过来先使用复杂的 multiple / multi-hop 问题，迫使模型掌握复杂工具组合；超过 warm-up threshold $T_0$ 后再加入简单问题：

    $$
    D_t=\begin{cases}
    D_{\text{multi}},&t\le T_0,\\
    D_{\text{multi}}\cup D_{\text{single}},&t>T_0.
    \end{cases}
    $$

---

本文架构优势：将固定 TKGQA workflow 转化为由 RL 学习的动态 action policy；通过 `<filter>` 和 `<rank>` 降低单一 `<think>` 的认知负担，再利用 Reverse Curriculum Learning 避免 agent 在简单问题上形成捷径。最终以 8B 开源模型在复杂时序问题上超过依赖闭源 LLM 的强 baseline，并在推理阶段不再需要外部 LLM API.

---

Case study：对于问题 *Who was the last person to visit China before the University of Stellenbosch?*，两种方法都检索到 University of Stellenbosch 的访问日期为 2008-12-01，以及多个候选访问记录。Search-R1 在单一 `<think>` 中误将 2008-11-21 判断为最近日期；Temp-R1 先通过 `<filter>` 删除 2008-12-01 之后的记录，再通过 `<rank>` 排序，最终正确选择 2008-11-28 的 **Straits Exchange Foundation**。该案例说明错误并非来自检索，而是来自检索后的时间约束处理，显式 action decomposition 可以缓解这一问题.
