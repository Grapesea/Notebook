???+ warning "期末补天tips from [xyx-2](https://www.yuque.com/xianyuxuan/coding/ads_exam_2)"

## 概述

贪心算法是在问题的每个阶段，选取在 **greedy criterion** 意义下最优的决定. 这个决定不会在后面解决子问题时被修改，因此这个决定应能保证可行性. **贪心算法取得最优解当且仅当问题的部分最优等同于整体最优.** 同时，有时最优解的取得需要花费大量时间，所以贪心可以视作近似最优的解法使用.

贪心算法实际上将问题分为两部分：做一次选择，然后解决子问题. 因此证明贪心算法的思路就是：

* 首先证明 greedy choice 的正确性，即证明总存在一个 optimal solution，它当前做的选择与贪心选择相同. 可以考虑的方法是将 optimal solution 转化为一个贪心选择，或者证明贪心选择此时不差于某一个最优解.
* 其次证明，子问题的一个最优解与当前贪心选择结合后的解是原问题的一个最优解

???+ tips "概念辨析"

    * Greedy algorithm works only if the local optimum is equal to the global optimum. (T)
    * In a greedy algorithm, a decision made in one stage is not changed in a later stage. (T)
    * To prove the correctness of a greedy algorithm, we must prove that an optimal solution to the original problem always makes the greedy choice, so that the greedy choice is always safe. (F)
        
        应该将"always makes the greedy choice"改成"can make the greedy choice".
        

## Activity Selection Problem (ASP)

对于一个活动序列$S = \{a_1,a_2,\cdots,a_n\}, a_i = [s_i,f_i)$表示起始和结束时间. 称$a_i,a_j$是兼容的（compatible），如果$s_i \geq f_j \text{或者} s_j \leq f_i$（即活动时间段没有重合）. 求最大兼容活动子序列（即活动数量最多）.

DP思路：$O(N^2)$.

正确的贪心思路之一是不断选取没有冲突且最早结束的activity. 与之对称的方法是，不断选取最晚开始的时间.

**定理**：如果$a_m$是子问题$S_k$中最早结束的，那么$a_m$一定属于$S_k$的某个最大兼容子序列.

???+ tips "证明"

    Let $A_k$ be the optimal solution set, and aef is the activity in $A_k$ with the earliest finish time.

    If $a_m$ and $a_{ef}$ are the same, we are done!  Else replace $a_{ef}$ by $a_m$ and get $A_{k'}$.

    Since $f_m \leq f_{ef}$, $A_{k'}$ is another optimal solution.

**算法效率是$O(N\log N)$.**

如果给活动带上权值，则DP仍然成立，但Greedy会失效，有2-approximation的算法.

两个判断题：

* Let S be the set of activities in Activity Selection Problem. Then the earliest finish activity am must be included in all the maximum-size subset of mutually compatible activities of S. (F)
* Let S be the set of activities in Activity Selection Problem. Then there must be some maximum-size subset of mutually compatible activities of S that includes the earliest finish activity. (T)

二者之间的区别是任意与存在. 我们已经通过上面的证明得到，任何一组可行的最优解，一定存在一种替换方案（或者已经包含最早结束的活动从而不需要进行替换），使得最早结束的活动跟某些活动替换之后，能够得到另一组可行的最优解.

## Huffman code

Huffman Code(哈夫曼编码)是用于文件压缩的一种前缀码(Prefix code)编码方法. 字符仅放置在哈夫曼树的叶节点上，且树为满二叉树（所有节点要么是叶节点，要么有两个子节点）。这种结构确保解码时无歧义——任何字符的编码都不是其他字符编码的前缀。例如，若 $a=0、u=110、x=10、z=111$，解码序列`00010110010111`时，可准确识别为`aaa x u a x z`.

定义字符频率(frequency) 是字符串中某种字符出现的次数，比如`aaaxuaxz`中,$f(a) = 4,  f(u) = 1,  f(x) = 2,  f(z) = 1$.

构建算法是，每一个字符初始形成一个单节点树，用一个堆维护所有树的频率，每次取出频率最小的两棵树作为一个根节点的左右子树合成一棵新树（根节点权重是二者之和），并将其加入堆中，直到堆中只有一棵树，这棵树就是 Huffman 编码树.

这样的树有两个特点：所有字符都在叶子结点，保证任何一个字符的编码不为另一个字符的前缀；不存在只有 1 个儿子的结点.

按照上面的算法，假设字符总数是$c$，时间复杂度是$O(c\log c)$.

Huffman 码的核心是**最小化总编码代价**，其计算公式为 $\sum(\text{字符深度}\times\text{字符频率})$（深度即编码长度）. 通过将高频字符分配短编码 、低频字符分配长编码 ，实现总代价最小. 例如，字符`a`频率为 $10$（深度 $3$）、`e`频率为 $15$（深度 $2$），则代价为 $3\times 10 + 2\times 15 = 60$.

???+ tips "pseudocode"
    ```c
    void Huffman ( PriorityQueue  heap[ ],  int  C )
    {   consider the C characters as C single node binary trees,
        and initialize them into a min heap;
        for ( i = 1; i < C; i++ ) {
            create a new node;
            /* be greedy here */
            delete root from min heap and attach it to left_child of node;
            delete root from min heap and attach it to right_child of node;
            weight of node = sum of weights of its children;
            /* weight of a tree = sum of the frequencies of its leaves */
            insert node into min heap;
        }
    }
    ```

举例：

<center><img src = "../figures/greedy/huffeg.png" style="zoom: 50%;"/></center>

???+ tips "贪心正确性证明"
    <center><img src = "../figures/greedy/pr1.png" style="zoom: 50%;"/></center>
    <center><img src = "../figures/greedy/pr2.png" style="zoom: 50%;"/></center>

???+ tips "2025fall-zgc-mid"

    <center><img src = "../figures/greedy/zgcmid-1.png" style="zoom: 50%;"/></center>

    > 喜欢Huffman编码吗？考前不复习，场上两行泪.

## PTA习题

???+ tips "xyx-2"

    <center><img src = "../figures/greedy/xyx-2-1.png" style="zoom: 50%;"/></center>

    反例：$[1,2], [4,5], [1,3], [2,5,6]$，如果按照Greedy 1的思路走是$[1,2], [4,5] \quad [1,3] \quad [2.5,6]$三组，但是按照Greedy 2的思路只需要2组：$[1,2], [2.5,6]\quad [1,3], [4,5]$.

???+ tips "5.2-1"

    <center><img src = "../figures/greedy/5.2-1.png" style="zoom: 50%;"/></center>

    选C.

    反例： 考虑硬币面额集合 $S = \{1, 4, 5\}$（$k=3$），目标金额 $n = 8$.
    
    贪心算法： 选最大的 $5 \to 8-5=3$,选最大的 $4$ (不能) $\to$ 选 $1, 1, 1$，于是方案：5, 1, 1, 1 (共 4 枚硬币).
    
    最优解： 选 $4, 4$. 方案：4, 4 (共 2 枚硬币). 由于贪心算法给出的解 (4枚) 不是最优解 (2枚)，所以陈述 (III) 是错误的.

???+ tips "5.5-1"
    设有 $n$ 个独立的作业 $\{1,2,\cdots,n\}$ ，由 $m$ 台相同的机器 $\{1,2,\cdots,m\}$ 进行加工处理；作业 $i$ 所需的处理时间为 $t_i (1\leq i\leq n)$，每个作业均可在任何一台机器上加工处理，但未完工前不允许中断，任何作业也不能拆分成更小的子作业.

    该多机调度问题要求给出一种贪心法作业调度方案，把$n$个作业按用时长从大到小顺序安排在最先空闲的机器上加工处理.

    ```c
    #include<stdio.h>
    #include<stdlib.h>
    #define N 100  //作业数上限
    int n;   //作业数
    int m;   //机器数
    struct NodeType
    {
        int no;         //作业序号
        int t;          //执行时间
        int mno;        //机器序号
    };
    struct NodeType A[N];
    struct NodeType machine[N];   //机器最后一个作业，（结束时间） 
    int cmp(const void *a, const void *b) // 排序比较函数 
    {
        return  -(((struct NodeType *)a)->t - ((struct NodeType *)b)->t);    // 从大到小 
    }

    struct NodeType get_min(struct NodeType machine[]) 
    {   // 选择最先空闲机器
        struct NodeType e = machine[0];
        int min = machine[0].t, index = 0, i;
        for( i=1; i<m; i++)
                if(machine[i].t < min) {
                    min = machine[i].t; 
                    e = machine[i]; 
                    /* Blank 1 */;
                }
        e.mno = index+1;   // 最先空闲机器号 
        return e;
    }

    void solve()          //求解多机调度问题
    {
        struct NodeType e;
        int i,j;
        if (n<=m)
            return;
        qsort(A, n, sizeof(struct NodeType), cmp); // 快速排序 

        for (i=0; i<m; i++)
        {
            A[i].mno=i+1;
            printf("%d %d %d-%d\n",
                    A[i].mno, A[i].t, 0, A[i].t);
            machine[i]=A[i];
        }

        for (j=m; j<n; j++)
        {   e = /* Blank 2 */; 
            printf("%d %d %d-%d\n",
                    e.mno, A[j].t, e.t, e.t+A[j].t);
            machine[e.mno-1].t /* Blank 3 */;    
        }
    }

    int main()
    {   int i;
        scanf("%d %d",&n, &m);

        for(i=0; i<n; i++)
            scanf("%d %d", &A[i].no, &A[i].t);
        solve();
        return 0;
    }
    ```

    输入格式：
    第一行输入作业数$n$和机器数$m$，用一个空格分隔；接着的$n$行输入作业编号和处理时长（均为正整数，用空格分隔）.

    输出格式：
    按照处理的作业顺序输出$n$行，每行输出机器编号、处理时长、占用时间区间，用空格分隔.

    输入样例：
    ```plaintext
    5 2
    1 2
    2 5
    3 4
    4 2
    5 3
    ```

    输出样例：

    ```plaintext
    1 5 0-5
    2 4 0-4
    2 3 4-7
    1 2 5-7
    1 2 7-9
    ```

    答案：
    1.`index = i` 2.`get_min(machine)` 3.`+= A[j].t`

???+ tips "2020mid"

    <center><img src = "../figures/greedy/2020mid1.png" style="zoom: 50%;"/></center>
    <center><img src = "../figures/greedy/2020mid2.png" style="zoom: 50%;"/></center>
