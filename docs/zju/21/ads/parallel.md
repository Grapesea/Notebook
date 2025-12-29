???+ info "推荐资源"

    [Parallel](https://brucejqs.github.io/MyNotebook/blog/Computer%20Science/ADS/Chapter%2014/)
 
## Parallel Algorithm的基础模型

### 机器并行与算法并行

幻灯片首先区分了两种层面的并行：

* **机器并行 (Machine Parallelism):** 硬件层面，比如多核处理器、流水线技术（Pipelining）或者超长指令字（VLIW）.
* **算法并行 (Parallel Algorithms):** 这是程序员和理论计算机科学家关心的，我们需要一个抽象的数学模型（即**PRAM**）来设计和分析算法，而不必纠结于具体的硬件细节. 

PRAM 模型 (Parallel Random Access Machine)是并行计算中最经典的理论模型，

* **结构：** 拥有 $n$ 个处理器 ($P_1 \sim P_n$) 和一个巨大的共享内存 (Shared Memory).
* **交互：** 所有处理器都可以同时读写这块共享内存.
* **理想化假设：** 访问内存的时间是单位时间（Unit time），忽略了现实中缓存、总线竞争等复杂因素.
* **指令：** 使用 `pardo` (parallel do) 关键字，表示后面的循环是所有处理器同时并行执行的.

??? tips "举例"

    执行单个语句：`c:=a+b`时：

    <center><img src = "../figures/parallel/1.png" style="zoom: 50%;"/></center>

    执行循环语句：

    ```pseudocode
    for P_i, 1 <= i <= n  pardo
        A(i) := B(i)
    ```

    由于是并行的，所以时间开销是$O(1)$.

    <center><img src = "../figures/parallel/2.png" style="zoom: 50%;"/></center>

### Memory Conflicts

当多个处理器试图同时访问同一个内存地址时，Memory conflict就产生了. PRAM 模型定义了三种不同的规则来处理这种冲突：

1. **EREW (Exclusive-Read Exclusive-Write):** 最严格的模式. 同一时间，一个内存单元只能被一个处理器读，也只能被一个处理器写. 
2. **CREW (Concurrent-Read Exclusive-Write):** 允许大家同时**读**同一个数据（比如大家都读同一个配置参数），但同一时间只能有一个人**写**. 
3. **CRCW (Concurrent-Read Concurrent-Write):** 最宽松的模式，允许同时读和写. 但如果大家同时写，谁的数据会留下来？这又细分为：

    * *Arbitrary rule:* 随机选一个，谁写入成功纯看运气. 
    * *Priority rule:* 处理器编号最小的（或优先级最高的）写入成功. 
    * *Common rule:* 只有当所有处理器试图写入的值**完全相同**时，才允许写入. 

## The Summation Problem（求和问题）

最简单的例子：计算数组$A$中所有数字的和. 

传统做法 (Sequential):一个接一个加，$A[1]+A[2]$，然后 $+A[3]$ ... 时间复杂度是$O(N)$. 

并行做法 (Parallel):采用 **树状归约 (Tree Reduction)** 的方式. 

* 第一轮：$P_1$算$A[1]+A[2]$，$P_2$算$A[3]+A[4]$...同时进行. 
* 第二轮：将上一轮的结果再两两相加. 
* 这就构成了一棵二叉树. 

??? tips "pseudocode"

    ```pseudocode
    for i in range(1,n): (pardo)
        B(0,i) = A(i)

    for h in range(1,\log n): 
        for i in range(1,n/2^h): (pardo)
            B(h,i) = B(h-1, 2i-1) + B(h-1, 2i)
    output B(log n, 1)
    ```

## Work-Depth 模型

为了衡量并行算法的好坏，我们不再只看单一的“时间复杂度”，而是看两个指标：

* Work(总工作量$W = T_1$): 整个算法执行的所有基本运算的总次数. 也就是树中**所有节点**的总数. 

* Depth(深度/关键路径$D = T_{\infty}$): 算法中依赖关系的最长链条长度. 也就是树的**高度**. 

### Brent's Theorem (布伦特定理)

现实中我们有 $p(1 < p < \infty)$ 个处理器. 那么运行时间$T_p$是多少？

精确计算$T_p$很麻烦，因为涉及任务调度. 但是，我们可以通过 **Brent's Theorem** 给出一个上下界：

$$\dfrac{W}{p} \leq T_p \leq \dfrac{W}{p}+D$$

上界 $\dfrac{W}{p}+D$ 中，$\dfrac{W}{p}$ 是并行处理的部分，$D$是无法并行的瓶颈（树高）. 也就是说，只要调度合理，$p$个处理器的运行时间不会超过平均分摊的工作量加上必须串行的深度. 

### 性能分析

从work load和worst-case两个角度分析，其中

$$W(n) = \text{total number of operations}, T(n) = \text{worst-case running time}$$

即：

* $W(n)$ 表示并行优化之后整个算法所需要的操作的数量级
* $T(n)$ 表示每个处理器处理自己的并行的子任务的复杂度最大值（即最坏复杂度）

根据Brent's Theorem可以导出以下的**WD-presentation Sufficiency Theorem**：

> **如果有一个工作量是 $W(n)$ ，时间是 $T(n)$ 的并行算法，则算法的开销为$O(\dfrac{W(n)}{P(n)} + T(n))$.**

## 前缀和问题（Prefix-Sums）

输入是 $n$ 个数，记作 $A[1], A[2], \cdots, A[n]$，希望获得 $\forall 1 \leq k \leq n, \sum\limits_{i=1}^k A[i]$.

考虑平衡二叉树

<center><img src = "../figures/parallel/3.png" style="zoom: 50%;"/></center>

规定前缀和$C(h,i) = \sum\limits_{k=1}^{\alpha} A[k]$，其中$(0,\alpha)$是二叉树的节点$(h,i)$最右侧路径的叶子节点的位置（容易发现$\alpha = 2^{h-1}+i$）.

<center><img src = "../figures/parallel/3-2.png" style="zoom: 50%;"/></center>

则转移方程：

$$C(h,i) = \begin{cases}
    B(h,i) & i = 1 \\
    C(h+1, \dfrac{i}{2}) & i \text{为偶数} \\
    C(h+1, \dfrac{i-1}{2}) + B(h, i) & i \text{为大于1的奇数}
\end{cases}$$

??? tips "pseudocode"

    ```python
    for P_i, i in range(1,n): pardo
        B(0,i) = A(i)
    for h in range(1,log(n)):
        d_h = n//(2**h)
        for i in range(1,d_h): pardo
            B(h, i) = B(h - 1, 2 * i - 1) + B(h - 1, 2 * i)

    for h in range(log(n),0,-1):
        d_h = n//(2**h)
        for i in range(2,d_h,2): pardo
            C(h, i) := C(h + 1, i // 2)
        for i = 1: pardo
            C(h, 1) = B(h, 1)
        for i in range(3,d_h,2): pardo
            C(h, i) = C(h+1, (i-1)//2) + B(h, i)
    for P_i, i in range(1,n): pardo
        print(C(0, i))
    ```

这样$T(n) = O(\log n), W(n) = O(n)$.

## Merging Problem

将两个非递减的数组$A(1),A(2),…,A(n)$和数组$B(1),B(2),…,B(m)$合并成为另一个非递减的数组$C(1),C(2),…,C(n+m)$.

采用partition的方法，将输入数据尽量平均地分成$p$个独立小任务，同时并行处理这些小任务（对单个小任务采取顺序处理）.

考虑把merge转换成ranking问题. 首先定义$RANK(j,A)$，其实际意义是$B(j)$如果直接插入到$A[]$中，它应该放在的位置：

$$RANK(j, A) = \begin{cases}
i &  A(i) < B(j) < A(i + 1), 1 \leq i < m \\
0 &  B(j) < A(1) \\
n &  B(j) > A(n)
\end{cases}$$

于是ranking problem可以这样描述：

我们将A,B一起加入ranking，分别求出 $RANK(i, B)\quad \forall 1 \leq i \leq n$ 和 $RANK(j, A)\quad \forall 1 \leq j \leq m$.

在以下的示例中，相比原先的两种做法：

<center><img src = "../figures/parallel/4.png" style="zoom: 50%;"/></center>

并行排序做到了：整体$D = O(\log n), W = O(p\log n) = O(n)$.

<center><img src = "../figures/parallel/5.png" style="zoom: 60%;"/></center>

## Maximum Finding

如果把上面问题中的+改成找max：

### 基础算法：Compare All Pairs

这是最基础的并行最大值算法，利用了**Common CRCW PRAM**模型（多个处理器可以同时写同一个内存单元，但写入的值必须相同）. 

原理：

1. 初始化数组 $B(1),B(2),…,B(m)$ 全为 0. 
2. 并行地对所有可能的数对进行比较. 
3. 如果 $A[i] < A[j]$，则说明$A[i]$肯定不是最大值，将$B[i]$标记为 1. 
4. 最后，只有 $B[i]$ 仍为 0 的那个索引对应的 $A[i]$ 是最大值. 

复杂度推导：

* 深度 $D = O(n)$：所有比较是同时进行的，只需要一步. 
* 工作量 $W = O(n^2)$：因为有 $n^2$ 对组合需要比较.
* **局限性：虽然极快，但工作量太大，不适合处理大规模数据**. 

### 双对数范式 (Doubly-logarithmic Paradigm)

为了平衡速度和工作量，这里引入了分治思想. 

**第一阶段：递归分治 (Partition by $\sqrt n$)**

原理：将 $n$ 个元素分成 $\sqrt n$ 个组，每组有 $\sqrt n$ 个元素. 

1. 递归地在每个组内找最大值（得到 $\sqrt n$ 个局部最大值 $M_i$）. 
2. 对这 $\sqrt n$ 个局部最大值，使用上面的“双两比较”法找全局最大值. 

于是：

* $D(n) \le D(\sqrt{n}) + O(1)\Longrightarrow D(n) = O(\log \log n)$. 
* $W(n) = \sqrt{n} \cdot W(\sqrt{n}) + O((\sqrt{n})^2) \Longrightarrow W(n) = O(\log \log n)$. 

时间降到了极低的双对数级，但工作量仍略高于线性. 

**第二阶段：优化至线性工作量 (Partition by $h = \log \log n$)**

为了让 $W = O(n)$ ，先通过简单的串行扫描或小组并行处理，减小后续处理的规模. 

1. 将数组分成 $n/h$ 组，每组大小为 $h = \log \log n$. 
2. 对每组内部进行串行查找，耗时$O(h)$. 
3. 剩下的 $n/h$ 个元素再用上述双对数算法处理. 

**最终结果**：$W = O(n)$，达到了**工作量最优**. 

### 随机采样算法 (Random Sampling)

这是最高级的方法，旨在通过随机性在 $O(1)$ 深度内以**极高概率**完成任务，且保持线性工作量. 

首先进行**随机采样**，从 $n$ 个元素中随机选出 $n^{\frac{7}{8}}$ 个元素放入集合 $B$. 

之后采取**分块并行**：将 $B$ 分成 $n^{\frac34}$ 个块，每块大小为 $n^{\frac18}$. 对每块内部使用 $O(1)$ 的“双两比较”法找最大值（因为 $(n^{1/8})^2 = n^{1/4}$，总工作量 $n^{3/4} \cdot n^{1/4} = n$ ，符合线性要求），得到 $n^{\frac34}$ 个候选者.

继续对这 $n^{\frac34}$ 个候选者重复类似操作，直到选出一个临时最大值 $M$ . 

最后进行过滤与重试：

* 用 $M$ 过滤原数组$A$，只留下比 $M$ 大的元素. 
* 由于 $M$ 是从足够大的样本中选出的，极高概率出现的情况是，剩下的元素数量非常少. 如果的确如此，再次调用 $O(1)$ 算法即可收尾. 

容易知道 $D = O(1)$：在 CRCW 模型下，步骤固定，不随 $n$ 增长；$W = O(n)$：每一步的分组和比较设计都控制在 $O(n)$ 以内，并且有以下定理：该算法以 $1 - 1/n^c$ 的概率（即几乎肯定）在常数时间内找到最大值. 这就保证该算法的可行性.