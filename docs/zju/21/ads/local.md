???+ info "参考资源"

    [UCB CS188(2025Spring)-Local Search](https://inst.eecs.berkeley.edu/~cs188/textbook/search/local.html)
    $\quad$
    [HobbitQia助教哥哥的笔记](https://note.hobbitqia.cc/ADS/)
    $\quad$
    [Starstone的笔记本](https://starstone3.github.io/incourse/ADS/localsearch/)

## 定义

首先对local进行解释，我们在一个可行的组（feasible set）里面定义了neighborhoods，一个local optimum就是neighborhoods中的最佳解决方案（best solution）.

这样我们的搜索策略就是，从一个可行的solution开始，在neighborhood之内寻找一个更好的solution. 如果不存在更好的改进，则这个solution就是local optimum.

**Neighbor Relation**:  $S \sim S'$ : $S'$ is a neighboring solution of $S - S'$ can be obtained by a small modification of $S$.

$N(S)$: neighborhood of $S$ – the set $\{ S': S \sim S' \}$.

```pseudocode
SolutionType Gradient_descent()
{   Start from a feasible solution S in FS ;
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
