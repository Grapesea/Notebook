本文将依照张国川老师的授课以及其余材料整理。

其中涉及的代码我试图手搓，放在了GitHub仓库：[Grapesea/ADS_code](https://github.com/Grapesea/ADS_code)里面.

???+ tips "资源列表 & 前人经验"
    一些有意思且非常有用的网站：[数据结构可视化:usfca版](https://www.cs.usfca.edu/~galles/visualization/)

    [Algorithm Design-Princeton](https://www.cs.princeton.edu/~wayne/kleinberg-tardos/)

    [修佬的笔记](https://note.isshikih.top/cour_note/D2CX_AdvancedDataStructure/)
    $\quad$
    [WintermelonC的笔记](https://wintermelonc.github.io/WintermelonC_Docs/zju/compulsory_courses/ADS/)
    $\quad$
    [StarStone的笔记](https://starstone3.github.io/incourse/ADS/)

    [MIT 6.046J, 2015 spring](https://ocw.mit.edu/courses/6-046j-design-and-analysis-of-algorithms-spring-2015/)
    $\quad$
    <a href="wyh_ads_lec.pdf" download="wyh_ads_lec.pdf">点击下载wyh助教的ADS讲义</a>

    摘自[罹魂梦蝶的经验帖](https://www.cc98.org/topic/5647034)：

    > 学习情况：​我选的是bjj的班，老师本身上课的话可能并没有像myc或者zgc那样花费了很多时间投入，我本人也并没有认真听过几次课。从我个人的学习情况来看，基本就是上完课当天去听陈越老师在MOOC上的课程链接，然后自己整理笔记，整理完之后再看看作业题(ps.bjj老师每年的作业题都基本一样，所以如果平时作业分数想高一点的话……)

    > ​对于project，这学期ads同组有一个非常强的大佬基本carry了代码工作，我和另一个同学就是写写注释、文档之类的活，对于文档，我做了一份[报告模板](https://github.com/lhmd/ZJU-course/tree/master/%E9%AB%98%E7%BA%A7%E6%95%B0%E6%8D%AE%E7%BB%93%E6%9E%84%E4%B8%8E%E7%AE%97%E6%B3%95%E5%88%86%E6%9E%90/%E6%8A%A5%E5%91%8A%E6%A8%A1%E6%9D%BF)每次展示的PPT是用reveal.js做的，这里附上我做的PPT[链接1](https://lhmd.top/MyReveal/ADS_P8/#/) [链接2](https://lhmd.top/MyReveal/ADS_P3/#/)，这种方法可以快速产生简洁帅气的PPT，我还是很喜欢的，如果有同学想学的话可以参考[xy的笔记链接](https://note.isshikih.top/others/reveal-md2Slides/).

    > 考前补天：借用wrt的一句话，ads如果考前你还在看知识点，已经可以准备明年的考试了。ads适当做一些题目是很重要的，刷刷历年卷能极大的提高自己对题目的熟悉程度，考场上面猜也好猜~还有推荐一下我自己的[笔记链接](https://github.com/lhmd/ZJU-course/tree/master/%E9%AB%98%E7%BA%A7%E6%95%B0%E6%8D%AE%E7%BB%93%E6%9E%84%E4%B8%8E%E7%AE%97%E6%B3%95%E5%88%86%E6%9E%90/%E7%AC%94%E8%AE%B0).

    摘编自[Miracle96的CC98经验帖](https://www.cc98.org/topic/6082358)：

    > 提前学习动态规划等经典算法，做做 leetcode 题。
    
    > 1.教考分离的情况较为严重。

    > 针对期末复习，**一定要把陈越钦定的ppt过一遍(因为这些是考点，而老师课上讲的并不一定是考点)**。不懂的地方结合杨洋的智云。最后刷资源中提到的历年卷。从难度来看，前半学期数据结构的部分关键是理解每个操作是怎么实现的，然后能在草稿纸上画出来即可。后半学期开始变得玄学，特别是Local search和近似算法这块的题目变化很多，难度很大，不过很多题目都是算法导论的课后习题改编的的。最后两章并行计算和外排序虽然听起来也很难，但是考的都是固定的模板，如果只想追求分数的话记住每种方法的复杂度即可。

    > 2.相对不重视代码，而重视对时间复杂度的分析

    > 实际上ADS的考点和OI/ACM差别还是挺大的。因此即使以前搞过也不能掉以轻心，需要记忆算法复杂度的结论和理解分析方法（比如势能分析一定要理解）。后半部分的近似算法等也跟OI关系不大，很多纯数学的推导。

    > 先过一遍课本知识，每天看一章，如cyll的PPT、wyy的笔记、[笔记: 修佬](https://note.isshikih.top/cour_note/D2CX_AdvancedDataStructure/) (但是后半部分,特别是近似算法,local search,随机算法,并行计算不全)、[Zhou Jianjun佬的考前突击](https://zhoutimemachine.github.io/note/courses/ads-final-review/)

    > 考前跟按考点整理的历年卷习题复习一遍：[xyx-1](https://www.yuque.com/xianyuxuan/coding/ads_exam_1) $\quad$ [xyx-2](https://www.yuque.com/xianyuxuan/coding/ads_exam_2)

    > 一些[历年卷](https://github.com/RyanFcr/ZJU_Course/tree/main/%E5%A4%A7%E4%BA%8C%E6%98%A5%E5%A4%8F/%E9%AB%98%E7%BA%A7%E6%95%B0%E6%8D%AE%E7%BB%93%E6%9E%84%E4%B8%8E%E7%AE%97%E6%B3%95%E5%88%86%E6%9E%90ADS/%E6%9C%9F%E6%9C%AB)

???+ tips "教学大纲 & 评分细则"
    数据结构：（占$\dfrac13$）

    * Balanced Search Trees: AVL Tree, Splay Tree, B+ Tree, Red-Black Tree
    * Leftist Heaps, Skew Heaps, Binomial Queue
    * Inverted File Index（看起来简单实则极易丢分）

    算法：
    
    1. Exact Algorithms<br>
        * Divide and Conquer<br>
        * Backtracking<br>
        * Dynamic Programming

    2. Heuristic Algorithms<br>
        * Greedy Algorithms<br>
        * Local Search (find a solution, then making subtle modification to find an optimal solution)

    3. Approximation Algorithms<br>
        * NP-Completeness<br>
        * Approximation Algorithms<br>
        * Randomized Algorithms

    4. Other Algorithms<br>
        * Parallel Algorithms<br>
        * External Sorting

    Grading Policy：（平时分60'，不溢出）

    * 作业10'
    * 讨论10'
    * Project 30' (2-3人，Presentation)
    * MidTerm(10*，可以被Final Term覆盖)
    * Final Term (40*)
