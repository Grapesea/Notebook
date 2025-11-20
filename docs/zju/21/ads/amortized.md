这一想法的来源是我们希望估计某个数据结构经过一系列操作的平均花费时间

Aggregate Analysis：找到时间开销最大的一种情形，计算$n$次操作之后的开销$T(n)$，则amortized cost是$\dfrac{T(n)}{n}$.

!!! tips "举例"
    一个具有Multipop函数的大小为$k$的栈，从空栈开始只能选择push 1, pop 1, multipop三种操作，所以aggregate cost就是先压入$n-1$个元素，再进行一次Multipop，开销是$2n-2$，所以$\dfrac{T(n)}{n} = O(1)$.

## Splay Tree中的应用

现在我们试图证明splay tree中，$T_{\text{amortized}} = O(\log{n})$.

首先证明zig/zig-zag/zig-zig操作的开销上限（摊还成本）分别为：

$$\text{zig}:~~ \hat{c_i} \leq 1+(R_2(X)-R_1(X))$$

$$\text{zig-zag}: \hat{c_i} \leq 2(R_2(X)-R_1(X))$$

$$\text{zig-zig}: \hat{c_i} \leq 3(R_2(X)-R_1(X))$$

推导如下：

???+ tips "手写的推导过程"
    <center><img src = "../figures/ads/zig1.jpg" style="zoom: 25%;"/></center>
    <center><img src = "../figures/ads/zigzag.jpg" style="zoom: 30%;"/></center>
    <center><img src = "../figures/ads/zigzig.jpg" style="zoom: 30%;"/></center>

而假设$X$的高度是$H(X)$的情况下，可能的旋转次数是

$$k = \begin{cases} \dfrac{H(X)}{2} & H(X)\text{是偶数}\\ \dfrac{H(X)-1}{2} + 1 & H(X)\text{是奇数}\end{cases}$$

即在高度为奇数时进行$\dfrac{H(X)-1}{2}$次的zig-zig/zig-zag，再进行1次zig将$X$转到root位；

在高度为偶数时进行$\dfrac{H(X)}{2}$次的zig-zig/zig-zag.

于是对于root为$T$的Splay Tree，想要找到它的$X$节点并进行splay操作，开销的摊还成本最大是$3(R(T)-R(X))+1 = O(\log(N))$，此时进行了1次zig和一堆zig-zig/zig-zag.

**Splay Tree的搜索、插入、删除操作的摊还复杂度都是$O(\log N)$.**

### PTA作业题整理

??? notes "1.1-3"

    For a Splay tree that is non-empty in the initial state, the amortized cost of $m$ finite operations is $O(m \log n)$, assuming that the maximum number of nodes in the Splay tree is $n$.

    是错的，这个界限不够精确，正确的表述应该是：

    对于初始包含$n_0$个节点的Splay树，执行$m$次操作（操作过程中最多有$n$个节点），总的摊还代价是$O((m+n_0)\log ⁡n)$或$O(m \log n + n_0 \log n)$. 如果初始树包含$n_0$个节点，这些节点的初始势能需要计算在内，而常见的$\Phi = \sum\limits_{x \in T} \log(\text{size}(x))$，初始势能约为$O(n_0 \log n_0)$

    所以，对于任意初始状态的Splay树（包含 $n_0 \leq n$个节点），$m$次操作的摊还代价是$O((m + n) \log n)$.

??? notes "1.2-3"

    For a Splay tree contains $k$ nodes in the initial state, assuming that the maximum number of nodes in the Splay tree is $n$. What’s the amortized cost of $m$ operations? ($k \gg m$)

    A.$O(m \log(n+k))$<br>
    B.$O(mn)$<br>
    C.$O(m\log n)$<br>
    D.$O(m\log k)$
    
    答案是C，需要注意的是$k \ll m$，所以A不是很对.

## 杂题

??? tips "1.2-2"

    <center><img src = "../figures/ads/1.2-2.png" style="zoom: 60%;"/></center>

    

??? tips "2025fall-yy-mid"

    <center><img src = "../figures/ads/yymid4.png" style="zoom: 60%;"/></center>

    答案是D，因为

??? tips "2024mid"

    <center><img src = "../figures/ads/2024mid1.png" style="zoom: 60%;"/></center>

    来自豆包：

    摊还成本（Amortized Cost）：是对数据结构一系列操作的 “最坏情况平均” 时间分析。通过为每个操作分配摊还成本，保证所有操作的总摊还成本 ≥ 总实际成本，属于最坏情况驱动的平均分析。<br>
    平均成本（Average Cost）：通常基于随机输入模型，是操作在 “随机输入” 下的期望时间成本，属于概率驱动的期望分析。<br>
    两者没有 “摊还成本从不小于平均成本” 的必然关系。例如，某些场景下摊还成本可能低于平均成本（若平均成本是基于高概率坏情况的期望，而摊还分析通过操作间的成本摊分得到了更优的最坏平均）。因此题目说法错误，答案为F。
