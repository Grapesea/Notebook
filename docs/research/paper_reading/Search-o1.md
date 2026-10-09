# [EMNLP 2025] Search-o1: Agentic Search-Enhanced Large Reasoning Models

> * 论文地址：https://arxiv.org/abs/2501.05366v1
> * Github 仓库：https://github.com/sunnynexus/Search-o1
> * 项目主页：https://search-o1.github.io/

原先工作的 Problem：

1. **Knowledge insufficiency 导致错误传播. ** LRM 可以长时间推理，但参数知识不能覆盖每一个中间步骤；一处事实猜错，会影响后续推理. Figure 1 以 GPQA 上的 “perhaps”“alternatively”等词频展示 model-expressed uncertainty；这些词频是观察性信号，不是经校准的置信度指标. 
2. **问题级的一次检索不能覆盖步骤级的知识需求. ** Standard RAG 只对原问题检索一次，后续中间实体与子问题往往还没有出现，无法提前完整召回. 
3. **原始文档回填会干扰长推理链. ** 网页冗长、含无关内容；论文还提出，面向 reasoning 的对齐可能影响一般长上下文能力. 因此，需要在主推理链之外先理解文档，再注入有用信息. 

> 🖼️ **[Figure 1：GPQA diamond 上的 model-expressed uncertainty 与不同检索策略的词频对比；建议复用原文第 2 页]**

---

Search-o1 是一个**无需额外训练的推理时搜索增强框架**，由三个功能环节构成：

* Main reasoning：使用 QwQ-32B-Preview 推理，并自主决定是否发起搜索. 
* Agentic RAG：解析模型生成的搜索标记，执行 Web Search 和网页读取. 
* Reason-in-Documents：用同一 reasoning model 独立分析文档，输出当前步骤所需的精炼信息. 

## 构建方法论（Methodology）

### Overview

Figure 2 从左到右比较三种路径：直接推理遇到知识缺口后继续猜测；加入 Agentic RAG 后可以补知识，但长文档仍可能打断推理；Search-o1 则进一步将“阅读搜索结果”移到独立生成过程. 主模型先根据问题、已有推理和历史搜索结果生成 query，系统暂停主链并检索网页. Reason-in-Documents 同时接收 previous reasoning steps、current search query 与 searched web pages，分析哪些信息能推进当前问题，输出 `Final Information`. 系统仅将该输出插回主链，再继续推理，直到回答或再次搜索. 

这里的关键不是通用网页摘要，而是**以当前推理状态为条件的证据精炼**：相同网页在不同推理阶段可能需要不同信息. 两个生成过程承担不同职责，但使用同一原始模型，并非论文额外训练的两个 agent，也没有新增 reward model. 独立阅读隔离的是文档分析过程与原始长文档，不是将主推理历史完全丢弃. 

> 🖼️ **[Figure 2：Vanilla Reasoning、Agentic RAG 与 Search-o1 的主架构对比；原文第 4 页]**

### 1. Agentic RAG & Multi-step Planning

模型输出以下文本标记来请求检索：

```text
<|begin_search_query|> search query <|end_search_query|>
```

系统检测到结束标记后暂停生成，提取 query 并调用搜索. **检索时机由 prompt 引导的模型生成行为决定**，没有单独训练 uncertainty detector，也没有设定 “perhaps” 词频阈值触发搜索. 

第 i 次 query 的条件分布为：

$$
P(q_{\mathrm{search}}^{(i)}\mid I,q,R^{(i-1)})
=\prod_{t=1}^{T_q^{(i)}}P(q_{\mathrm{search},t}^{(i)}\mid q_{\mathrm{search},<t}^{(i)},I,q,R^{(i-1)}).
$$

其中 I 是 task instruction，q 是原问题，R 是此前包含搜索交互的推理历史，T 是 query token 长度. 这是 autoregressive generation 的形式化描述，**不是新的训练目标**. 

### 2. Retrieval Strategy & Index Design

$$
D^{(i)}=\operatorname{Search}(q_{\mathrm{search}}^{(i)}).
$$

D 是当前 query 的 top-k 文档. 实验使用 Bing Web Search API，region 为 US-EN，默认 k=10；Jina Reader API 读取网页内容. 没有自建 KG、图遍历或新的 dense retriever/index 学习. 

对照中的 Standard RAG 对原问题一次取 top-10 文档；RAgent 则先取 top-10 snippets，再由模型决定读取哪些 URL 的完整网页. 因此，RAgent 与 Search-o1 的对比并非只开关精炼模块的完全相同工作流. 

### 3. Memory & Long-Context Management

Reason-in-Documents 的独立调用先生成文档分析 $r_{\text{docs}}$，再输出精炼结果 $r_{\text{final}}$：

$$
r_{\mathrm{docs}}^{(i)}\sim M(\cdot\mid R^{(<i)},q_{\mathrm{search}}^{(i)},D^{(i)}),
\qquad
r_{\mathrm{final}}^{(i)}\sim M(\cdot\mid r_{\mathrm{docs}}^{(i)},R^{(<i)},q_{\mathrm{search}}^{(i)}).
$$

$R^{(<i)}$ 是当前搜索前的推理历史. 上述表达为原文 Eq. 4–5 的简写. 系统提取 `Final Information`，而不是把完整 r_docs 回填主链；没有有用信息时，prompt 要求输出 `No helpful information found.`. 

精炼结果以以下格式回填：

```text
<|begin_search_result|> refined information <|end_search_result|>
```

这可以缩减主链接收的噪声，但**不是历史推理链的整体压缩算法**：独立阅读仍需处理文档及 previous reasoning steps，论文也未指定固定摘要 token budget. 

### 4. Test-Time Compute & Adaptive Retrieval

系统循环执行“推理 → 搜索 → 独立阅读 → 回填 → 继续推理”. Algorithm 1 将未完成序列保存在 S 中，遇 EOS 的序列移入 F；需要搜索的序列组成独立阅读 batch，处理完再恢复生成. 

检索次数可随问题变化，但 prompt 存在最大搜索次数限制.
