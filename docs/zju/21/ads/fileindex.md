## Lec 3 Inverted File Index

!!! tips

    [修佬的笔记](https://note.isshikih.top/cour_note/D2CX_AdvancedDataStructure/Lec03/)
    $\quad$
    [wikipedia](https://en.wikipedia.org/wiki/Inverted_index)

### 引入与定义

倒排索引是一种常见的文本索引技术，使用链表对单词出现个数进行存储

其核心思想是，将传统的"文档→词汇"映射关系反转为"词汇→文档"映射

### 倒排索引的构建

* 读入字符串并解析得到单词<br>
* 使用词干提取和停用词过滤得到词项<br>
* 检查词典，如果词不存在就插入<br>
* 构建倒排列表 (Posting List)：为每个词维护一个 posting list，记录该词出现在哪些文档中. 可选：记录词频 (TF)、位置等信息

### 搜索引擎评价-Relevance

查询阶段的内容：

* 接收查询词<br>
* 在词典中查找<br>
* 获取 posting list<br>
* 计算相关性/精确度（如 TF-IDF, BM25）<br>
* 排序返回结果

维护 times 的作用：求几个 term 同时出现的 documents 时，从 times 小的 term 开始找.

有以下三个指标：

|                                 | Relevant 相关的） | Irrelevant（无关的） |
| ------------------------------- | ----------------- | -------------------- |
| Retrieved（被召回的，即找到的） | $R_R$             | $I_R$                |
| Not retrieved（没被找到的）     | $R_N$             | $I_N$                |

准确率（Precision）：$P = \dfrac{R_R}{R_R+T_R}$

召回率（Recall）：$R = \dfrac{R_R}{R_R+R_N}$

### PTA习题

???+ tips "2024mid"

    <center><img src = "../figures/ads/2024mid2.png" style = "zoom:50%"/></center>

    选D

???+ tips "2021mid"

    While accessing a term stored in a B+ tree in an inverted file index, range searches are expensive.

    错，开销并不大.

???+ tips "xyx-1"

    Among the following groups of concepts, which group is not totally relevant to a search engine?<br>
    A. thresholding, dynamic programming, precision<br>
    B. word stemming, compression, recall<br>
    C. distributed index, hashing, inverted file index<br>
    D. stop words, posting list, dynamic indexing

    选A,没有用到dp的知识.

    (T) In data retrieval, the response time is more important than the relevance of the answer set.<br>
    (T) When measuring the relevancy of the answer set, if the precision is low but the recall is high, it means that most of the relevant documents are retrieved, but too many irrelevant documents are returned as well.<br>
    (T) When measuring the relevancy of the answer set, if the precision is high but the recall is low, it means that most of the relevant documents are missing, but most of the retrieved documents are relevant. <br>
    (F) Word stemming is to eliminate the commonly used words from the original documents. <br>
    (T) While accessing a term, hashing is faster than search trees.

    第4句话的意思是stemming去除了commonly used words，但是Word stemming（词干提取）是将词汇还原到词根形式，将不同形式的同一个词统一处理；Stop words removal（停用词去除）是删除常用的无意义词. 题目描述的其实是停用词去除，不是词干提取.

    
