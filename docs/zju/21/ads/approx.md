???+ info "参考资源"

    <a href="reference/lec17.pdf" download="np.pdf">MIT6.046J(2015 Spring)-Lec17</a>
    $\quad$
    [HobbitQia助教哥哥的笔记](https://note.hobbitqia.cc/ADS/)
    $\quad$
    [Starstone的笔记本](https://starstone3.github.io/incourse/ADS/Approximation/)

    [wikipedia](https://zh.wikipedia.org/wiki/%E8%BF%91%E4%BC%BC%E7%AE%97%E6%B3%95)

## 近似算法基本定义

近似算法是基于$\textbf{P} \neq \textbf{NP}$假设的，为最优化问题寻找近似解的算法. 该类算法找到的近似解与最优解之间的差值需能证明不超过某个值（后面会记作近似比）.

已经证明是$\textbf{NP}\text{-completeness}$的时间复杂度极高的优化问题，学界广泛认为不具备多项式时间算法，所以很难获得精确解. 于是转而使用近似算法来获得局部区间的近似最优.

**近似比(Approximation Ratio):**An algorithm has an approximation ratio of $\rho(n)$ if, for any input of size $n$, the cost $C$ of the solution produced by the algorithm is within a factor of $\rho(n)$ of the cost $C^*$ of an optimal solution:

$$\max(\dfrac{C}{C^*},\dfrac{C^*}{C}) \leq \rho(n)$$

称对应的算法是$\rho(n)$-approximation algorithm.

**近似范数(Approximation Scheme)**: An approximation scheme for an optimization problem is an approximation algorithm that takes as input not only an instance of the problem, but also a value $\epsilon > 0$ such that for any fixed $\epsilon$, the scheme is a $(1+ \epsilon)$-approximation algorithm.

对于最小化问题，如果算法解$C$与最优解$C^{*}$满足$C \leq (1+\epsilon)C^*$，
则称为$(1+\epsilon)$-近似算法.

对于最大化问题，算法解$C$与最优解$C^{*}$满足$C \geq (1-\epsilon)C^*$，$\epsilon$称为误差参数，越小则解越接近最优.

**PTAS(polynomial-time approximation scheme,多项式时间近似算法)**: an approximation scheme which for any fixed $\epsilon > 0$, the scheme runs in time polynomial in the size $n$ of its input instance.

一个优化问题有PTAS，意味着对于任意给定的$\epsilon > 0$，存在算法$A_{\epsilon}$是一个$(1+\epsilon)$-近似算法，其中运行时间关于输入规模$n$是多项式.

形式化表示：运行时间$T(n, \epsilon) = O(n^{f(\epsilon)})$，其中$n$是输入规模，$f(\epsilon)$是关于$\epsilon$的任意函数（可以非常大，但对固定的$\epsilon$，$T(n, \epsilon)$关于$n$是多项式.

**FPTAS**: 完全多项式时间近似方案，定义更为严苛：在上面的基础上，要求运行时间关于$n$和$\dfrac1\epsilon$都是多项式.

??? tips "PTAS/FPTAS举例"

    PTAS但不是FPTAS: $O(n^{\frac{2}{\epsilon}})$  
    
    FPTAS: $O(\dfrac{1}{\epsilon^2}n^3)$

### PTA习题

??? tips "6.1-7/8/9"
    <center><img src = "../figures/approx/1.789.png" style="zoom: 50%;"/></center>

## 实际应用

### Approximate Bin Packing

这是一个很接近[Project 5 Three-Partition](../ads/proj/5.md)的$\textbf{NP}-\text{hard}$问题，描述如下：

> Given $N$ items of sizes  $S_1 , S_2 , \cdots , S_N$ , such that $0 < S_i \leq 1, \forall 1 \leq i \leq N$. Pack these items in the fewest number of bins, each of which has unit capacity.

#### Next Fit Algorithm

策略：只考虑上一个打开的箱子。如果新物品能放入上一个箱子，就放入；否则，立即打开一个新箱子，并将新物品作为新的``上一''物品.

```pseudocode
void NextFit ( )
{   read item1;
    while ( read item2 ) {
        if ( item2 can be packed in the same bin as item1 )
            place item2 in the bin;
        else
            create a new bin for item2;
        item1 = item2;
    } /* end-while */
}
```

定理：Let $M$ be the optimal number of bins required to pack a list I of items. Then next fit never uses more than $2M – 1$ bins. There exist sequences such that next fit uses $2M – 1$ bins.

证明：反证，用不等式构造矛盾.

#### First Fit Algorithm

策略：扫描所有已打开的箱子，将新物品放入第1个足够大的箱子中. 如果所有已开箱子都不够大，则创建一个新箱子.

```pseudocode
void FirstFit ( )
{   while ( read item ) {
        scan for the first bin that is large enough for item;
        if ( found )
            place item in that bin;
        else
            create a new bin for item;
    } /* end-while */
}
```

效率: 可以实现为 $O(N \log N)$ 的时间复杂度.

是不稳定的算法，如果在一个序列中所需的箱子数量是\(M\)，去掉一个箱子之后，所需的箱子数
也可能$>M$.

举例：

\(\text{Bin Size} =1, L = \{0.55,0.7,0.55,0.1,0.45,0.15,0.3,0.2\}\), \(L' = \{0.55,0.7,0.55,0.45,0.15,0.3,0.2\}\)

#### Best Fit Algorithm

策略：扫描所有已打开的箱子，将新物品放入其中放入后最接近capcity的箱子中. 如果所有已开箱子都不够大，则创建一个新箱子.

相比First Fit而言，是稳定的.

#### Online Algorithm

Place an item before processing the next one, and can NOT change decision.

也就是说获得一个输入之后必须马上决策，无法看到后面的输入.

No on-line algorithm can always give an optimal solution. **There are inputs that force any on-line bin-packing algorithm to use at least $\dfrac53$ the optimal number of bins.**

举例：

#### Offline Algorithm

View the entire item list before producing an answer.

#### PTA习题

??? tips "6.2-2/3"
    <center><img src = "../figures/approx/2.23.png" style="zoom: 50%;"/></center>

### The Knapsack Problem(背包问题)

### The K-center Problem(K中心问题)

给定平面上的一系列site（即点），在平面中找出\(k\)个不同的 center，记\(\text{site}_i\)到离它最近的 center的距离为\(\text{dis}_i\)，求\(\max\{\text{dis}_i\}\)的最小值.

#### PTA习题

??? tips "6.2-4"
    <center><img src = "../figures/approx/2.4.png" style="zoom: 50%;"/></center>

### 杂题

#### PTA习题

??? tips "6.2-5"
    <center><img src = "../figures/approx/2.5.png" style="zoom: 50%;"/></center>
