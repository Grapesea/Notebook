## parallel Algorithm的基础模型

### 机器并行与算法并行

幻灯片首先区分了两种层面的并行：

* **机器并行 (Machine Parallelism):** 硬件层面，比如多核处理器、流水线技术（Pipelining）或者超长指令字（VLIW）.
* **算法并行 (Parallel Algorithms):** 这是程序员和理论计算机科学家关心的，我们需要一个抽象的数学模型（即**PRAM**）来设计和分析算法，而不必纠结于具体的硬件细节. 

PRAM 模型 (Parallel Random Access Machine)是并行计算中最经典的理论模型，

* **结构：** 拥有 $n$ 个处理器 ($P_1 \sim P_n$) 和一个巨大的共享内存 (Shared Memory).
* **交互：** 所有处理器都可以同时读写这块共享内存.
* **理想化假设：** 访问内存的时间是单位时间（Unit time），忽略了现实中缓存、总线竞争等复杂因素.
* **指令：** 使用 `pardo` (parallel do) 关键字，表示后面的循环是所有处理器同时并行执行的.

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
* 第一轮：$P_1$算$A[1]+A[2]$，$P_2$算A[3]+A[4] ... 同时进行. 
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

现实中我们有$p (1 < p < \infty) $ 个处理器. 那么运行时间$T_p$是多少？

精确计算$T_p$很麻烦，因为涉及任务调度. 但是，我们可以通过 **Brent's Theorem** 给出一个上下界：

$$\dfrac{W}{p} \leq T_p \leq \dfrac{W}{p}+D$$

上界$\dfrac{W}{p}+D$中，$\dfrac{W}{p}$是并行处理的部分，$D$是无法并行的瓶颈（树高）. 也就是说，只要调度合理，$p$个处理器的运行时间不会超过平均分摊的工作量加上必须串行的深度. 

### 性能分析

从work load和worst-case两个角度分析，其中

$$W(n) = \text{total number of operations}, T(n) = \text{worst-case running time}$$

