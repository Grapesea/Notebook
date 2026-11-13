# [ACL 2026] Graph-S³: Enhancing Agentic Textual Graph Retrieval with Synthetic Stepwise Supervision

> * 论文地址: [ACL Anthology](https://aclanthology.org/2026.acl-long.1169/)
> * arXiv: [arXiv:2510.03323](https://arxiv.org/abs/2510.03323)
> * Github仓库: **暂未发现 Graph-S³ 独立官方仓库**
> * 相关/前身实现: [Changgeww/GRAIL](https://github.com/Changgeww/GRAIL)
> * **更简洁的摘要：** Graph-S³ 用离线构造的 golden subgraph 为图检索 agent 的每一步提供 process-level reward，再通过 SFT → GRPO 两阶段训练学习交互式图探索策略，从而缓解长链图检索中的 sparse reward 和错误 credit assignment。

原先工作的 Problem:

1. **传统 graph retrieval 容易产生冗余或不完整的子图。** similarity-based、GNN-based 等方法多数采用 one-shot retrieval，在复杂 multi-hop QA 中无法根据当前推理状态动态决定继续探索或剪枝。:chatgpt-content-reference{index="0"}
2. **Agentic graph retrieval 缺乏可靠的细粒度训练信号。** SFT 容易学习训练轨迹中的固定 action pattern；只使用最终答案作为 RL reward 时，长 action chain 中 reward 过于 sparse，难以确定早期某个 retrieval action 是否真正有效。即使中间存在冗余甚至错误步骤，也可能偶然得到正确答案。:chatgpt-content-reference{index="1"}
3. **复杂 multi-hop graph reasoning 存在明显的 credit assignment 问题。** action space 很大，而最终 answer reward 无法区分每个 `Explore / Choose` 操作对正确 evidence subgraph 的贡献，因此训练容易不稳定。:chatgpt-content-reference{index="2"}

---

Graph-S³ 是一个面向 **agentic textual graph retrieval / graph-based QA** 的训练式框架，核心由以下三部分组成：

* Synthetic Graph Reasoning Data & Golden Subgraph Construction
* Two-stage SFT + Stepwise RL Training
* Interactive Graph Retriever

> 🖼️ **[Figure 2: Data synthesis pipeline 与两阶段训练框架。左侧先生成并筛选 trajectory，再 refinement；右侧由 answer-level sparse reward 转为 golden-subgraph-based stepwise dense reward]**

整个核心思想可以概括为：

**先离线找到“什么样的 graph exploration path 是好的”，再把这个标准转换为每一步的 reward，最后训练 agent 自己学会搜索。**

---

构建方法论（Methodology）：

* **Synthetic trajectory generation 与 golden subgraph refinement**

  将 textual graph 写为三元组集合：

  $$
  G=\{t_i\}_{i=1}^{m},\qquad
  t_i=(e_i^h,r_i,e_i^t)
  $$

  retriever 使用三个显式 action：

  - `Explore Entity(x)`：扩展实体 $x$ 的邻接三元组，将信息加入 perception window $G^p$；
  - `Choose Relation`：从 $G^p$ 中筛选与 query 相关的 triples，写入 focused subgraph $G^{sub}$；
  - `Finish`：认为已有 sufficient evidence，终止检索并基于 $G^{sub}$ 回答问题。:chatgpt-content-reference{index="3"}

  State 定义为：

  $$
  s_t=(q,G_t^p,G_t^{sub},h_t)
  $$

  其中 $h_t=(a_1,\ldots,a_{t-1})$ 保存过去 action history，使下一步决策同时依赖当前 graph state 与已有 reasoning trajectory。GPT-4o 作为 behavior model 在图中执行这些 action，并生成 reasoning trace。只有最终答案正确的 trajectory 才会保留，其原始 state-action pair 直接形成 SFT 数据。:chatgpt-content-reference{index="4"}

  对正确 trajectory 进一步执行 **trajectory refinement**：寻找仍能保持相同正确答案的最短可行子序列，

  $$
  \tau_i^*
  =
  \arg\min_{\tau\in\mathcal F_i}|\tau|
  $$

  删除无必要的 detour，并将 refined trajectory 对应的 subgraph 作为后续 RL 的 golden reference。这样 reward 所依据的目标本身已经经过 compactness refinement，而非直接奖励一条可能包含大量冗余操作的“正确轨迹”。:chatgpt-content-reference{index="5"}

* **Stage I SFT → Stage II GRPO with Synthetic Stepwise Reward**

  Stage I 使用 raw successful trajectories 做 SFT，让 retriever 先学会基本的 graph navigation、action syntax 与 reasoning pattern：

  $$
  \mathcal L_{\mathrm{SFT}}
  =
  -\mathbb E_{(s_t,y_t)\sim D_{\mathrm{SFT}}}
  \left[
  \sum_l
  \log\pi_\theta
  (y_t^l\mid I(s_t),y_t^{<l})
  \right]
  $$

  Stage II 使用 refined trajectory 构造 **process-level reward**。核心变化是 reward 从：

  `整个 trajectory → final answer correct / wrong`

  转为：

  `每个 action → 它对 golden subgraph 的贡献程度`

  reward 形式为：

  $$
  \ell_t=
  \begin{cases}
  0,&\mathrm{Inv}(a_t)\\
  c_1,&\mathrm{Fmt}(a_t)=1\land\mathrm{Corr}(a_t)=0\\
  c_2,&\mathrm{Part}(a_t)=1\\
  1,&a_t=a_t^*
  \end{cases}
  $$

  分别评价 action validity、format correctness、partial correctness 和完全正确的 action，并使用 **GRPO** 进行训练。这样早期 retrieval decision 同样能够获得 dense supervision。:chatgpt-content-reference{index="6"}

* **Interactive Retrieval**

  inference 阶段不再固定做 `k-hop expansion`，而是不断执行：

  `Explore Entity → Choose Relation → Explore Entity → ... → Finish`

  `Explore` 负责提高 recall，`Choose` 持续压缩 perception window、控制 noise，`Finish` 自适应决定检索深度。

  因而 retrieval depth 由 learned policy 动态决定，可以避免固定 k-hop RAG 随 hop 增大迅速引入大量无关邻居。:chatgpt-content-reference{index="7"}

---

本文架构优势：

1. **将 outcome supervision 转化为 process supervision。** Graph-S³ 的主要贡献并非单纯换用 GRPO，而是构造了能够监督每一步 graph action 的 golden subgraph，使复杂 multi-hop trajectory 中的 credit assignment 更明确。:chatgpt-content-reference{index="8"}
2. **Retrieval 与 reasoning policy 联合学习。** agent 学习什么时候扩展实体、什么时候压缩关系、什么时候终止，不再依赖固定的 k-hop retrieval。
3. **显著降低无效 retrieval。** 在正确回答问题时，Graph-S³ 平均只需要 G-Retriever **11.44%** 的 retrieved triples，同时保持更高准确率，说明 trajectory refinement 和 interactive pruning 确实学习到了更 compact 的 evidence subgraph。:chatgpt-content-reference{index="9"}

---

Experiments & SOTA Comparison：

* Dataset：
  - **WebQSP**：主要为 1–2 hop Freebase QA；
  - **CWQ**：更加复杂的 multi-hop questions；
  - **MetaQA**：电影领域 KGQA，同时测试 1-hop / 2-hop / 3-hop。:chatgpt-content-reference{index="10"}
* Baseline：
  - k-hop RAG
  - Think-on-Graph (ToG)
  - LightRAG
  - G-Retriever
  - KG-Agent
* Backbone：
  - Qwen3-8B
  - Llama3.1-8B
  - Finetuned-8B
* Metric：
  - Accuracy
  - F1

Graph-S³ 在三个 backbone 下总体均保持领先，而且随着 reasoning hop 增加，相对于 KG-Agent / conventional k-hop RAG 的优势更加明显。以 Qwen3-8B 为例：

| Dataset      | KG-Agent Acc / F1 | Graph-S³ Acc / F1 |
| ------------ | ----------------: | ----------------: |
| WebQSP       |     29.66 / 38.02 | **36.24 / 47.88** |
| CWQ          |     15.64 / 22.45 | **17.87 / 23.29** |
| MetaQA 2-hop |     28.41 / 33.66 | **53.73 / 65.60** |
| MetaQA 3-hop |      4.07 / 10.89 | **12.73 / 29.49** |

:chatgpt-content-reference{index="11"}

Ablation 对这篇工作尤其重要：

* 去掉 **SFT**：agent 缺乏基本 graph navigation initialization；
* 去掉 **RL**：CWQ / MetaQA multi-hop 性能明显下降；
* 去掉 **interactive retrieval**：2-hop / 3-hop 急剧退化；
* 去掉 **trajectory refinement**：下降幅度最大，说明 noisy trajectory 会直接破坏 stepwise reward 的有效性。:chatgpt-content-reference{index="12"}

特别是 MetaQA 3-hop：

$$
36.29\;F1
\rightarrow
1.80\;F1
$$

when trajectory refinement is removed，说明 **golden trajectory 的质量比“有没有 RL”本身更加关键**。:chatgpt-content-reference{index="13"}

---

Training Details：

* Synthetic data：
  - SFT：9,035 instances
  - RL：3,504 instances
* SFT：
  - Qwen3-8B
  - learning rate $1\times10^{-4}$
  - 3 epochs
* GRPO：
  - learning rate $1\times10^{-5}$
  - batch size 512
  - 15 epochs
  - clip ratio 0.2
  - gradient clipping 1.0
  - KL coefficient 0.001
  - PPO mini-batch size 16
* Hardware：
  - 8 × NVIDIA A100 80GB
  - RL training 约 32 hours

:chatgpt-content-reference{index="14"}

---

Limitations & Future Work：

* 当前验证主要集中于 standard textual graph / KGQA benchmark，尚未验证更加开放的 graph reasoning scenario。
* 当前 action space 只有 `Explore Entity / Choose Relation / Finish`，未来可以进一步引入更多 graph manipulation actions。
* 可以结合 external tools 扩展 agent 能处理的问题复杂度。:chatgpt-content-reference{index="15"}

---

Case Study：

**成功案例：Sarah Polley**

问题要求寻找 Sarah Polley 导演电影的上映年份。Sarah Polley 同时具有演员、导演等大量连接，是典型 high-degree hub node。

Graph-S³：

`Sarah Polley`
→ `Choose directed_by`
→ films
→ `Choose release_year`
→ answer

其关键能力是通过 `Choose Relation` 主动删除大量 acting-related edges，仅保留 `directed_by` evidence。相比之下，普通 similarity retrieval 甚至因为 *Polly / Polley* lexical similarity 检索到无关实体。:chatgpt-content-reference{index="16"}

**失败案例：Jane Anderson**

问题：

> The screenwriter Jane Anderson co-wrote movies with whom?

agent 正确找到 Jane Anderson 编剧的电影，但后续继续选择指向 **Jane Anderson 本人** 的 `written_by` edges，没有探索其他 writer，最终陷入 self-verification loop。

该案例暴露出 Graph-S³ 仍然容易：

**过度关注 query 中显式出现的 entity，而忽略需要通过 sibling relation 找到的未知 entity。**

这对你关注的复杂 multi-hop reasoning 很有价值，因为这里的 failure 已经不属于 retrieval recall 问题，而是 **policy 在结构关系上的 long-horizon exploration bias**。:chatgpt-content-reference{index="17"}