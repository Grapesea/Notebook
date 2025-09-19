本文将依照张国川老师的授课以及其余材料整理。

其中涉及的代码我试图手搓，放在了GitHub仓库：[Grapesea/ADS_code](https://github.com/Grapesea/ADS_code)里面.

> 一些有意思和非常有用的网站：[数据结构可视化交互动画版](https://totuma.cn/)

!!! tips

    摘编自[Miracle96的CC98经验帖](https://www.cc98.org/topic/6082358)：

    > 提前学习动态规划等经典算法，做做 leetcode 题。
    
    > 1.教考分离的情况较为严重。

    > 针对期末复习，**一定要把陈越钦定的ppt过一遍(因为这些是考点，而老师课上讲的并不一定是考点)**。不懂的地方结合杨洋的智云。最后刷资源中提到的历年卷。从难度来看，前半学期数据结构的部分关键是理解每个操作是怎么实现的，然后能在草稿纸上画出来即可。后半学期开始变得玄学，特别是Local search和近似算法这块的题目变化很多，难度很大，不过很多题目都是算法导论的课后习题改编的的。最后两章并行计算和外排序虽然听起来也很难，但是考的都是固定的模板，如果只想追求分数的话记住每种方法的复杂度即可。

    > 2.相对不重视代码，而重视对时间复杂度的分析

    > 实际上ADS的考点和OI/ACM差别还是挺大的。因此即使以前搞过也不能掉以轻心，需要记忆算法复杂度的结论和理解分析方法（比如势能分析一定要理解）。后半部分的近似算法等也跟OI关系不大，很多纯数学的推导。

    > 先过一遍课本知识，每天看一章，如cyll的PPT、wyy的笔记、[笔记: 修佬](https://note.isshikih.top/cour_note/D2CX_AdvancedDataStructure/) (但是后半部分,特别是近似算法,local search,随机算法,并行计算不全)、[Zhou Jianjun佬的考前突击](https://zhoutimemachine.github.io/note/courses/ads-final-review/)

    > 考前跟按考点整理的历年卷习题复习一遍：[xyx-1](https://www.yuque.com/xianyuxuan/coding/ads_exam_1) $\quad$ [xyx-2](https://www.yuque.com/xianyuxuan/coding/ads_exam_2)

    > 一些[历年卷](https://github.com/RyanFcr/ZJU_Course/tree/main/%E5%A4%A7%E4%BA%8C%E6%98%A5%E5%A4%8F/%E9%AB%98%E7%BA%A7%E6%95%B0%E6%8D%AE%E7%BB%93%E6%9E%84%E4%B8%8E%E7%AE%97%E6%B3%95%E5%88%86%E6%9E%90ADS/%E6%9C%9F%E6%9C%AB)

!!! tips
    数据结构：（占$\frac13$） 

    * Balanced Search Trees: AVL Tree, Splay Tree, B+ Tree, Red-Black Tree
    * Leftist Heaps, Skew Heaps, Binomial Queue
    * Inverted File Index（看起来简单实则极易丢分）

    算法：

    * Divide & Conquer
    * Backtracking, Dynamic Programming
    * Greedy Algorithms, Local Search
    * NP-Completeness, Approximation Algorithms
    * Randomized Algorithms, Parallel Algorithms
    * Streaming Algorithm (External Sorting)

    Grading Policy：（平时分60'，不溢出）

    * 作业10'
    * 讨论10'
    * Project 30' (2-3人，Presentation)
    * MidTerm(10*，可以被Final Term覆盖)

    * Final Term (40*)

