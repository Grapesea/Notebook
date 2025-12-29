???+ info "参考资源"

    [UCB CS188(2025Spring)-Local Search](https://inst.eecs.berkeley.edu/~cs188/textbook/search/local.html)
    $\quad$
    [HobbitQia助教哥哥的笔记](https://note.hobbitqia.cc/ADS/)
    $\quad$
    [Starstone的笔记本](https://starstone3.github.io/incourse/ADS/localsearch/)

## 定义

首先对local进行解释，我们在一个可行的组（feasible set, $\mathcal{FS}$）里面定义了neighborhoods，一个local optimum就是neighborhoods中的最佳解决方案（best solution）.

这样我们的搜索策略就是，从一个可行的solution开始，在neighborhood之内寻找一个更好的solution. 如果不存在更好的改进，则这个solution就是local optimum.

**Neighbor Relation**:  $S \sim S'$ : $S'$ is a neighboring solution of $S - S'$ can be obtained by a small modification of $S$.

$N(S)$: neighborhood of $S$ – the set $\{ S': S \sim S' \}$.

??? tips "pseudocode"

    ```c
    SolutionType Gradient_descent()
    {   
        Start from a feasible solution S in FS;
        MinCost = cost(S);
        while (1) {
            S' = Search( N(S) ); /* find the best S' in N(S) */
            CurrentCost = cost(S');
            if ( CurrentCost < MinCost ) {
                MinCost = CurrentCost;    
                S = S;
            }
            else  break;
        }
        return S;
    }
    ```

## The Vertex Cover Problem (顶点覆盖问题-优化方面)

### 问题描述

区别于NP一节中的Vertex Cover存在性判定问题（**给定无向图 $G = (V, E)$ 和整数 $K$，判断是否存在子集 $V' \subseteq V$，满足两个条件：$|V'| \leq K$（顶点覆盖的大小不超过 $K$）；对每条边 $(u, v) \in E，u \in V'$ 或 $v \in V'$（每条边的至少一个端点属于 $V'$，即 $V'$ 覆盖所有边）**），local search这一节的Vertex Cover Problem关注的是优化，即给定无向图$G = (V, E)$中找到最小的顶点覆盖 $V'$（即 $|V'|$ 最小），使得所有的边的两个顶点中至少有一个顶点落在该子集中.

这个问题中，我们关心的参数分别是：

* $\mathcal{FS}: \text{all the vertex covers}$;
* $\text{cost}(S) = |S|;
* S \sim S'$: $S'$ can be obtained from $S$ by (adding or) deleting a single node. （假定初始全部顶点的覆盖最多有$|V|$个顶点，从这个解开始删除）

<center><img src="../figures/local/case.png" style="zoom: 50%;" /></center>

这一优化问题具有 2-近似算法（如贪心选择最大度顶点，或局部搜索的近似比分析）. 例如，贪心算法每次选择度数最大的顶点加入覆盖，删除其关联边，重复直到所有边被覆盖.

### 改进

若局部最优解不是全局最优（如某些图中，局部搜索无法找到最小覆盖）时，梯度下降算法就会出现问题，此时可以通过Metropolis算法或者模拟退火算法

#### Metropolis算法

随机选择当前解的一个邻居解，遇到两个可能的情况:

* 若邻居解更优（改进当前解），则直接更新；
* 若邻居解更差（$\Delta \text{cost} \geq 0$，无改进），则以概率 $P = e^{-\Delta \text{cost}/(kT)}$ 接受该“坏解”. 通过这种方式，尝试跳出局部最优.

而第2种情况又会有2种case:

* case0. 局部最优附近存在两个对称的坏解（如“加 1”和“减 1”后的状态，$\Delta \text{cost}$ 相近）
* case1. 局部最优解周围存在更差的邻居解（$\Delta \text{cost} \geq 0$）

对于case 1，有一定概率可以跳出local optimum得到正确解. 只要
当温度 $T$ 设置合理时，算法会以一定概率接受这些坏解，从而跳出当前局部最优的“陷阱”，探索更广阔的解空间，甚至找到全局最优.

但是对case 0，有可能在$\pm 1$之间无限震荡. 当温度 $T$ 过高时，接受坏解的概率几乎为 1，算法会频繁在这两个坏解之间切换，无法收敛到稳定的局部或全局最优，形成“无限震荡”.

从上面的分析中也可以看出，温度选择非常重要. 如果陷入了两种极端中：

* $T$ 很高时 ：$e^{-\Delta \text{cost}/(kT)} \approx 1$，几乎总是接受坏解. 此时算法容易“上坡”（跳到更差的解），但也易在局部最优的“底部”（如 case 0 的对称坏解）之间来回震荡. 因总是接受坏解，无法稳定.
* $T$ 接近 0 时 ：$e^{-\Delta \text{cost}/(kT)} \approx 0$，几乎不接受坏解，使得算法退化为“梯度下降法”，即只接受更优的解，无法跳出局部最优.

```c
SolutionType Metropolis(){   
    Define constants k and T;
    Start from a feasible solution S \in FS ;
    MinCost = cost(S);
    while (1) {
        S_ = Randomly chosen from N(S); 
        CurrentCost = cost(S_);
        if ( CurrentCost < MinCost ) {
            MinCost = CurrentCost;    
            S = S_;
        }
        else {
            With a probability exp(-\delta cost / kT), let S = S_;
            else break;
        }
    }
    return S;
}
```

#### 模拟退火算法(Simulated Annealing)

是Metropolis的进一步延申.

模拟退火算法旨在结合随机游走（随机移动到邻近状态）和爬山算法，从而获得一种完整且高效的搜索算法. 在模拟退火算法中，我们允许移动到那些会降低目标函数值的状态，并在每个时间步随机选择一个移动.

如果该移动能使目标函数值更高，则总是被接受; 如果该移动能使目标函数值更低，则以一定的概率被接受. 该概率由温度参数（初始化一个温度随时间的序列$T = \{T_1,T_2,\cdots\}$）决定，初始温度较高（允许更多“坏”的移动），并按照一定的“时间表”递减. 理论上，如果温度下降得足够慢，模拟退火算法将以接近 1 的概率达到全局最大值.

```c
SolutionType SimulatedAnnealing(){
    current = problem.initialstate
    for (t = 1; ; t++){
        T = Ttable[t];
        if (T == 0) 
            return current;
        next = a randomly selected successor of current;
        Delta_E = next.val - current.val;
        if (Delta_E > 0)
            current = next;
        else
            current = next with a probability exp(Delta_E/T);
    }
}
```

???+ tips "相关问题"

    * 支配集问题：在无向图 $G=(V, E)$ 中，支配集 $D$ 是顶点集 $V$ 的一个子集，使得图中的任意一个顶点 $v$要么属于 $D$，要么与 $D$ 中的至少一个顶点相邻.
    * 最大独立集问题：在无向图 $G=(V, E)$ 中，独立集$I$是顶点集 $V$ 的一个子集 ，使得其中任意两个顶点之间都没有边相连. 找到包含顶点数最多的独立集，即最大独立集.
    * 最大团问题：团（Clique）是顶点集 $V$ 的一个子集 $C$，使得 $C$ 中任意两个不同的顶点之间都有边相连（即诱导子图是一个完全图）. 找到图中规模最大的团，即最大团.

## Hopfield  Neural Networks (神经网络问题)

给定图$G=(V,E)$（边权$w$可正可负），定义每个节点 $u$ 的状态 $s_u$取值为$\pm 1$，每条边 $e = (u, v)$有一个整数权重 $w_e$（正或负）.

定义：

* Configuration $S$中的一条edge $e = (u,v)$是"好的(good)"，如果 $w_es_us_v < 0$（即 $w_e < 0$ 时 $s_u = s_v$）；否则是"坏的(bad)"；

* 节点$u$ 是satisfied，如果对于包含$u$的所有边构成的集合$E$，good edge的权重总和大于bad edge，即：

    $$\sum\limits_{\{\forall v \mid e = (u,v) \in E\}} w_eS_uS_v \leq 0$$

* Configuration $S$是stable的，如果所有的node都是satisfied.

    比如下面这张图里的config就是satisfied：

    <center><img src="../figures/local/satis.png" style="zoom: 50%;" /></center>

### State-flipping Algorithm (状态翻转算法)

从任意配置 $S$ 开始，不断翻转不满意节点的状态，直到所有节点都满意.

```c
ConfigType State_flipping(S_init){
    S = S_init;
    while (!IsStable(S)){
        u = get_unsatisfied_node(S);
        u.state = -u.state;
    }
    return S;
}
```

**该算法在最多$\sum|w_e|$次迭代后终止**，因为每次翻转都会增加好边权重之和，且该和有上界$\sum|w_e|$.

证明：

<center><img src="../figures/local/sfpr.png" style="zoom: 50%;" /></center>

实际应用上，可用于解决组合优化问题（如最大割问题），但可能无法找到全局最优解. 但是得出来的所有目标是让 $\phi = \sum\limits_{e\text{ is good}} |w_e|$ 最大的局部最优解必定是stable configuration.

该算法是否为多项式时间算法目前尚无定论.

## Maximum Cut Problem

对于一个所有边有正整数权重$w_e$的无向图$G = (V,E)$，找到一个节点的分割方式$(A,B)$，使得所有经过这个割的边的权重之和最大. 即让

$$w(A,B) = \sum\limits_{u\in A,v\in B}w_{uv}$$

最大.

实际上这是Hopfield问题的特殊形式，因为$\forall w_e>0$，并且可以证明，这里的local optimum是$\dfrac12$：

??? tips "证明"

    由$(A,B)$是local optimal partition，得到

    $$\sum\limits_{v\in A}w_{uv} \leq \sum\limits_{v\in B}w_{uv}, \quad \forall u \in A$$

    对所有$u \in A$进行求和，得到：

    $$2 \sum\limits_{(u,v)\subseteq A}w_{uv} = \sum\limits_{u\in A}\sum\limits_{v\in A}w_{uv} \leq \sum\limits_{u\in A}\sum\limits_{v\in B}w_{uv} = w(A,B)$$

    同理

    $$2 \sum\limits_{(u,v)\subseteq B}w_{uv} \leq w(A,B)$$

    所以

    $$w(A^*,B^*) \leq \sum\limits_{(u,v)\subseteq A}w_{uv} + \sum\limits_{(u,v)\subseteq B}w_{uv} + w(A,B) \leq 2w(A,B) \quad \hfill \ensuremath{\blacksquare}$$

### Big-improvement-flip

选取的节点必须满足在flip之后能够将目标函数值（如割值）增加至少 $\dfrac{2\epsilon}{|V|} w(A,B)$ 的权值，其中$w(A,B)$ 表示当前割值，$|V|$ 是图中节点的数量，$\epsilon$ 是一个预先设定的参数.

这样的算法是具有性能保证的：

* 终止时，算法返回的割 $(A,B)$ 满足 $(2+\epsilon)w(A,B) \geq w(A^*,B^*)$，其中 $(A^*,B^*)$ 是全局最优割；
* 时间复杂度 ：该算法在最多 $O(\dfrac{n}{\epsilon} \log W)$ 次翻转后终止，其中 $n$ 是节点数量，$W$ 是图中边的最大权重.

### （疑似不会考）A better local

> 实质上是Local Beam Search.

<center><img src="../figures/local/betterlocal.png" style="zoom: 50%;" /></center>

## PTA习题

??? tips "7.2-1"

    <center><img src="../figures/local/2.1.png" style="zoom: 50%;" /></center>

    助教说一般蒙的话可以选Minimum Spanning Tree，因为是其中简单的一种树.

    具体而言，
