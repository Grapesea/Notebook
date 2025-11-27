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

    PTAS但不是FPTAS: $O(n^{\frac{2}{\epsilon}})$  FPTAS: $O(\dfrac{1}{\epsilon^2}n^3)$

### PTA习题

??? tips "6.1-7/8/9"

    <center><img src = "../figures/approx/1.789.png" style="zoom: 50%;"/></center>

## 实际应用

### Approximate Bin Packing

#### Next Fit Algorithm

#### PTA习题

??? tips "6.2-2/3"

    <center><img src = "../figures/approx/2.23.png" style="zoom: 50%;"/></center>

### The Knapsack Problem(背包问题)

### The K-center Problem(K中心问题)

#### PTA习题

??? tips "6.2-4"

    <center><img src = "../figures/approx/2.4.png" style="zoom: 50%;"/></center>

### 杂题

#### PTA习题

??? tips "6.2-5"

    <center><img src = "../figures/approx/2.5.png" style="zoom: 50%;"/></center>
