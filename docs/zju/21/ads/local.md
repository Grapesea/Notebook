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

    ```pseudocode
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

## The Vertex Cover Problem (顶点覆盖问题)

Given an undirected graph $G = (V, E)$, find a **minimum** subset $S$ of $V$ such that for each edge $(u, v)$ in $E$, either $u$ or $v$ is in $S$.

翻译：在无向图$G = (V, E)$中找到最小的顶点子集，使得所有的边的两个顶点中至少有一个顶点落在该子集中.

这个问题中，我们关心的参数分别是：$\mathcal{FS}: \text{all the vertex covers}$, $\text{cost}(S) = |S|, S \sim S'$: $S'$ can be obtained from $S$ by (adding or) deleting a sing

<center><img src="../figures/local/case.png" style="zoom: 50%;" /></center>

???+ tips "相关问题"

    * 支配集问题：在无向图 $G=(V, E)$ 中，支配集 $D$ 是顶点集 $V$ 的一个子集，使得图中的任意一个顶点 $v$要么属于 $D$，要么与 $D$ 中的至少一个顶点相邻.
    * 最大独立集问题：在无向图 $G=(V, E)$ 中，独立集$I$是顶点集 $V$ 的一个子集 ，使得其中任意两个顶点之间都没有边相连. 找到包含顶点数最多的独立集，即最大独立集.
    * 最大团问题：团（Clique）是顶点集 $V$ 的一个子集 $C$，使得 $C$ 中任意两个不同的顶点之间都有边相连（即诱导子图是一个完全图）. 找到图中规模最大的团，即最大团.