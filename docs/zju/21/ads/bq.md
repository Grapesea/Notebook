## Lec 5 Binomial Queue

!!! tips "资源"
    [Wintermelon的笔记](https://wintermelonc.github.io/WintermelonC_Docs/zju/compulsory_courses/ADS/ch5/)
    $\quad$
    [wiki](https://en.wikipedia.org/wiki/Binomial_heap)
    $\quad$
    [修佬的笔记](https://note.isshikih.top/cour_note/D2CX_AdvancedDataStructure/Lec05)

二项队列是一群heap的集合，其中每个heap都是1个二项队列.

首先定义二项树：

> A binomial tree, $B_k$, of height $k$ is formed by attaching a binomial tree, $B_{k – 1}$, to the root of another binomial tree, $B_{k – 1}$.

其图示如下：

<center><img src = "../figures/ads/bt0.png" style = "zoom:30%"/></center>

于是有：

> $B_k$ consists of a root with $k$ children, which are $B_0,B_1,\cdots,B_{k-1}$. $B_k$ has exactly $2^k$ nodes.  The number of nodes at depth $d$ is $C_k^d$.

接下来引出二项队列的定义：

> A binomial queue is not a heap-ordered tree, but rather a collection of heap-ordered trees, known as a forest.  Each heap-ordered tree is a binomial tree.

也就是说，二项队列是类似二进制加和下二项树的集合，因此这一表示是唯一的，比如$size = 13$的二项队列，其二进制下为：

$$13 = 2^3 + 2^2 + 2^0 = (1101)_2$$

于是构成为：

<center><img src = "../figures/ads/bq0.png" style = "zoom:50%"/></center>

### Findmin

只需要找每个根节点中的min就行了，时间复杂度$O(\log N)$.

### Merge

> 在理解二项队列过程中，可以试图从两个纬度同时理解这些操作：

> 1. 树/堆的纬度，具体观察数据的转移与变化过程；<br>
> 2. 二进制的纬度，将$k$阶二项树抽象为 bit vector 第$k$位的 1，从二进制加法的角度理解；

<center><img src = "../figures/ads/bqmerge.jpg" style = "zoom:50%"/></center>

### Insertion

类似之前的heap，插入操作看作是与一个结点的二项堆的merge.

<center><img src = "../figures/ads/bqinsert.jpg" style = "zoom:50%"/></center>

If the smallest nonexistent binomial tree is $B_i$ , then $Tp = Const \times (i + 1)$. Performing $N$ Insertions on an initially empty binomial queue will take $O(N)$ worst-case time.  Hence the average time is $O(1)$.

### DeleteMin

这是一个综合性操作：

1. Findmin

2.

### PTA习题

??? tips "(2.3-7) Multiple Answers"

    Right after we perform some operation (Merging, Insertion or DeleteMin) on a Binomial queue, we may have to merge some pairs of the resulting Binomial trees to make the resulting forest a Binomial queue.<br>
    Suppose that $B_{i1},B_{i2},B_{i3}$ of size $2^{k−1},2^{k-1},2^k(k\geq 1)$ respectively are Binomial trees to merge. Consider the case that $B_{i1}$ is merged with $B_{i2}$, and the resulting Binomial tree is then merged with $B_{i3}$. We call this case “cascading merge”.<br>
    Which of the following statements about “cascading merge” is/are correct?

    A.We may have to perform “cascading merge” right after deleting the minimum key of a Binomial queue.<br>
    B.We may have to perform “cascading merge” right after merging two Binomial queues of the same size.<br>
    C.We must perform “cascading merge” right after inserting a key into a Binomial queue of odd size.<br>
    D.Consider the case that we perform consecutive insertions into a Binomial queue. Assume that we have performed “cascading merge” after inserting a key. Then in the next 3 insertions, we do not have to perform “cascading merge”.

    答案是AD，B不可能出现cascading，因为

??? tips "(2.3-8) Multiple Answers"

    Consider a binomial queue Q of n nodes with binomial trees $B_1,\cdots,B_k$. To delete the minimum key from Q, there are the following four steps to go.

    Step 1: Find the minimum key. Assume the minimum key is in $B_j, 1\leq j\leq k$.<br>
    Step 2: Remove $B_j$ from $Q$. The resulting queue is $Q'$.<br>
    Step 3: Construct a binomial queue $Q''$ using the subtrees rooted at the children of the root of $B_j$.<br>
    Step 4: Merge Q' with Q''.

    Of which step(s), the worst-case running time is Θ(logn)?
    
    A. Step 1.$\quad$ B. Step 2.$\quad$ C. Step 3.$\quad$ D. Step 4.
