# [COLM 2025] Search-R1: Training LLMs to Reason and Leverage Search Engines with Reinforcement Learning

> * 论文地址：[arXiv:2503.09516v5](https://arxiv.org/abs/2503.09516v5)
> * Github 仓库：[PeterGriffinJin/Search-R1](https://github.com/PeterGriffinJin/Search-R1)
> * **更简洁的摘要：** 将搜索引擎纳入 RL 环境，通过最终答案奖励学习交替思考与多轮搜索；对检索返回的 token 屏蔽策略损失，使模型自主学习查询生成和证据利用. 

原先工作的 Problem：

1. **检索策略没有随推理能力一起训练. ** 常规 RAG 通常直接使用输入问题检索；IRCoT 等方法可以通过 prompting 交替检索与推理，但模型没有在训练阶段学习何时搜索、如何根据新证据生成下一次查询. 
2. **搜索不可微，监督轨迹昂贵. ** 搜索引擎调用无法直接通过常规反向传播优化；依赖完整工具使用轨迹的训练方式，需要大量高质量标注，难以扩展. 
3. **检索文本与模型动作混在同一条 rollout 中. ** 若对全部 token 计算 RL 损失，会将搜索引擎返回的文本也视为模型生成的动作，引入不合理的优化信号. 

---

Search-R1 是一个面向**推理与多轮搜索联合学习**的 RL 框架，包含以下三个部分：

* **Multi-turn Search Rollout**：将搜索引擎作为环境，交替生成思考、查询和答案. 
* **Search-augmented Policy Optimization**：支持 PPO 与 GRPO，并使用 retrieved-token loss masking. 
* **Outcome-based Reward**：只根据最终答案的正确性提供训练信号. 

整体流程是：模型根据问题和已有证据生成思考，缺少知识时发起搜索；环境将检索结果插入上下文，模型继续生成下一步查询或答案. 训练时，最终答案的 reward 用于优化整条交互轨迹中的模型生成部分，使查询策略和后续推理共同得到更新. 

这里优化的是**搜索引擎的使用策略**，而非搜索引擎本身：retriever 提供外部知识，policy 学习如何通过多轮查询获取并利用这些知识. 

> 🖼️ **[Figure 1: PPO 与 GRPO 的 Search-R1 训练架构；重点观察搜索引擎进入 rollout 的位置，以及 value model 与组内 reward 比较的区别]**

---

## 构建方法论（Methodology）

1. Multi-turn Search Rollout：将搜索作为环境交互

    给定问题 $x$、policy model $\pi_\theta$ 和搜索引擎 $\mathcal R$，生成过程交替执行模型生成与外部检索：

    $$
    y\sim\pi_\theta(\cdot\mid x;\mathcal R).
    $$

    其中 $y$ 包含模型生成的内容和搜索返回的文本. 四组标签承担不同功能：

    | 标签                             | 功能                         | 内容来源   |
    | -------------------------------- | ---------------------------- | ---------- |
    | `<think>...</think>`             | 分析问题、已有信息与后续步骤 | Policy LLM |
    | `<search>...</search>`           | 生成搜索查询                 | Policy LLM |
    | `<information>...</information>` | 提供检索结果                 | 搜索环境   |
    | `<answer>...</answer>`           | 输出最终答案                 | Policy LLM |

    执行过程：

    1. Policy 根据问题和当前上下文生成 token. 
    2. 检测到完整的 `<search>...</search>` 后，解析查询并调用搜索引擎. 
    3. 将返回结果包裹在 `<information>` 标签中，插入当前 rollout. 
    4. Policy 基于更新后的上下文继续生成. 
    5. 生成 `<answer>...</answer>` 或达到 action budget 时结束. 

    若生成内容未形成合法的搜索或答案动作，环境插入重新思考提示，再继续 rollout. 

    训练模板只要求输出遵循上述结构，不指定具体解题内容，也不强制执行反思或搜索. **搜索查询能够依赖前一轮找到的新实体与证据，因此可以形成跨步骤的检索链. **

    > 🖼️ **[Table 1 / Algorithm 1: 标签模板与多轮搜索执行流程；适合放在 rollout 解释之后]**

2. Search-augmented Policy Optimization: PPO / GRPO 与 token masking

    一条 rollout 同时包含 policy 生成的 token 和环境返回的 token. 定义：

    $$
    I(y_t)=
    \begin{cases}
    1,&y_t\text{ 为模型生成的 token},\\
    0,&y_t\text{ 为检索返回的 token}.
    \end{cases}
    $$

    **检索结果参与上下文建模，但不参与策略损失. **模型可以根据检索结果决定下一步动作，却不需要对环境返回文本的生成概率负责. 

    令当前上下文为 $s_t=(x,y_{<t})$，定义当前策略与旧策略的概率比：

    $$
    \rho_t(\theta)=
    \frac{\pi_\theta(y_t\mid s_t;\mathcal R)}
    {\pi_{\mathrm{old}}(y_t\mid s_t;\mathcal R)}.
    $$

    其中：

    * $\pi_\theta$：当前正在更新的 policy. 
    * $\pi_{\mathrm{old}}$：生成这批 rollout 的旧 policy. 
    * $\pi_{\mathrm{ref}}$：冻结的 reference policy，用于 KL 正则化. 

    **PPO with Search Engine**

    只在模型生成的 token 上计算 clipped policy objective：

    $$
    J_{\mathrm{PPO}}(\theta)=
    \mathbb E\left[
    \frac{1}{\sum_t I(y_t)}
    \sum_{t:I(y_t)=1}
    \min\left(
    \rho_t(\theta)\hat A_t,\;
    \operatorname{clip}(\rho_t(\theta),1-\epsilon,1+\epsilon)\hat A_t
    \right)
    \right].
    $$

    $\hat A_t$ 由 value model 与 GAE 估计，$\epsilon$ 控制 clipping 区间. PPO 将相对 reference policy 的 KL 惩罚纳入 reward，再估计 advantage. 

    **GRPO with Search Engine**

    对同一问题采样 $G$ 条 rollout，以组内相对 reward 估计 advantage，替代单独训练的 value model. 优化结构仍包含 clipped probability ratio，但将 KL 正则项直接加入目标：

    $$
    J_{\mathrm{GRPO}}(\theta)=
    \mathbb E\left[
    \frac{1}{G}\sum_{i=1}^{G}
    \frac{1}{\sum_t I(y_{i,t})}
    \sum_{t:I(y_{i,t})=1}
    \left(
    \min\left[
    \rho_{i,t}\hat A_{i,t},
    \operatorname{clip}(\rho_{i,t},1-\epsilon,1+\epsilon)\hat A_{i,t}
    \right]
    -\beta D_{\mathrm{KL},i,t}
    \right)
    \right].
    $$

    其中 $\beta$ 为 KL 正则系数. **GRPO 的 KL 项同样屏蔽检索 token**. 

    PPO 与 GRPO 的核心区别在于 advantage 的估计方式；两者都通过 masking 区分模型动作与环境观察.

    🖼️ **[Figure 1: 对照 PPO 的 Value LLM → GAE 与 GRPO 的 Group Computation 两条分支]**



3. Outcome-based Reward：用答案反馈训练搜索与推理

    从完整 rollout 中提取最终答案 $a_{\mathrm{pred}}$，与标准答案 $a_{\mathrm{gold}}$ 比较：

    $$
    r(x,y)=\operatorname{EM}(a_{\mathrm{pred}},a_{\mathrm{gold}}).
    $$

    即：

    $$
    r(x,y)=
    \begin{cases}
    1,&\text{最终答案满足 Exact Match},\\
    0,&\text{否则}.
    \end{cases}
    $$

    训练不额外设置 format reward，也不训练 neural reward model；中间查询与推理步骤无需提供逐步监督标签. 

    **训练与推理的衔接：**

    * **Training**：对问题采样多轮交互轨迹，计算最终答案 reward，再用 PPO / GRPO 更新模型生成部分. 
    * **Inference**：使用训练后的 policy 执行同一套思考与搜索循环，直到生成答案或耗尽 action budget. 

    这种设计将监督需求集中到问题与答案，让模型通过交互自行探索有效的查询组合. 



## 本文架构优势

* **从 prompting 搜索转向学习搜索. ** 将多轮检索决策纳入 policy optimization，使模型能够依据新证据调整查询. 
* **明确区分动作与观察. ** Retrieved-token masking 避免对外部返回文本施加策略更新，同时保留其对后续生成的影响. 
* **减少完整轨迹标注需求. ** 仅依赖最终答案 reward，联合优化查询生成、证据利用和回答过程. 
* **兼容不同 RL 算法. ** 同一搜索 rollout 可以接入 PPO 或 GRPO，而无需改变工具交互格式. 

---

## Experiments & SOTA Comparison

### 实验配置

| 项目                        | 配置                                                     |
| --------------------------- | -------------------------------------------------------- |
| Policy model                | Qwen2.5-3B / 7B，分别使用 Base 与 Instruct               |
| 训练数据                    | 合并 NQ 与 HotpotQA 的训练集                             |
| 知识语料                    | 2018 Wikipedia dump                                      |
| Retriever                   | E5                                                       |
| 默认召回数量                | 每次 top 3 passages                                      |
| 最大 action budget          | 4                                                        |
| 评估指标                    | Exact Match（EM）                                        |
| 分布内评测                  | NQ、HotpotQA                                             |
| 分布外评测                  | TriviaQA、PopQA、2WikiMultiHopQA、MuSiQue、Bamboogle     |
| 默认 RL 算法                | PPO；另提供 GRPO 对照                                    |
| 训练硬件                    | 单节点 8×H100                                            |
| 训练步数                    | 500                                                      |
| Policy learning rate        | $10^{-6}$                                                |
| PPO value learning rate     | $10^{-5}$                                                |
| GRPO group size             | 5                                                        |
| 总 batch size               | 512                                                      |
| 最大 sequence length        | 4096 tokens                                              |
| KL coefficient / clip ratio | $\beta=0.001$ / $\epsilon=0.2$                           |
| Rollout sampling            | temperature = 1.0，top-p = 1.0                           |
| 实现组件                    | Verl、vLLM、FSDP、CPU offloading、gradient checkpointing |

---

## Case study

问题：**女性香水 Curious 的代言歌手出生于哪个城市和州？**

未使用检索的 R1 将歌手误认为 Beyoncé，给出 Houston. Search-R1 则执行以下检索链：

1. 搜索 `Curious fragrance information`，确认对应歌手为 **Britney Spears**. 
2. 搜索 `Britney Spears birthplace`，找到出生地 **McComb, Mississippi**. 
3. 搜索 `McComb, Mississippi location`，进一步确认城市与州的信息. 
4. 输出最终答案 **McComb, Mississippi**. 

关键在于：第二次查询使用第一次检索得到的歌手名字，后续查询继续依赖已获得的出生地信息，形成**由中间证据驱动的多轮搜索**. 

> 🖼️ **[Table 9: Curious → Britney Spears → McComb, Mississippi 的完整交互案例]**