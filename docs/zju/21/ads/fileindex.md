## Lec 3 Inverted File Index

!!! tips

    [修佬的笔记](https://note.isshikih.top/cour_note/D2CX_AdvancedDataStructure/Lec03/)
    $\quad$
    [wikipedia](https://en.wikipedia.org/wiki/Inverted_index)

### 引入与定义

倒排索引是一种常见的文本索引技术，使用链表对单词出现个数进行存储

其核心思想是，将传统的"文档→词汇"映射关系反转为"词汇→文档"映射

### 倒排索引的构建

### 搜索引擎评价-Relevance

有以下三个指标：

|                                 | Relevant 相关的） | Irrelevant（无关的） |
| ------------------------------- | ----------------- | -------------------- |
| Retrieved（被召回的，即找到的） | $R_R$             | $I_R$                |
| Not retrieved（没被找到的）     | $R_N$             | $I_N$                |

准确率（Precision）：$P = \dfrac{R_R}{R_R+T_R}$

召回率（Recall）：$R = \dfrac{R_R}{R_R+R_N}$
