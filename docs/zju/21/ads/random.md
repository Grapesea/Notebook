???+ info "参考资源"

    [Starstone的笔记本](https://starstone3.github.io/incourse/ADS/Random/)
    $\quad$
    [Yale-Randomized](https://www.cs.yale.edu/homes/aspnes/classes/469/notes.pdf)
    $\quad$
    [SJTU-CS3341-Randomized笔记](https://jhc.sjtu.edu.cn/~kuanyang/teaching/CS3341/notes/lec01.pdf)
    
相比本学期其他数据结构和算法考虑优化的是平均效率和摊还效率，randomized algorithm更关心算法的期望效率.

## Hiring problem

雇佣1个秘书，一共$N$个候选者，可以按照任意顺序进行面试，总共花费$N$天完成面试.

假设面试成本与雇佣成本分别是$C_i,C_h (C_i \ll C_h)$，雇佣一个人后，即使第二天就面试到一个更好的从而开除上一个，仍然需要支付雇佣的成本. 按照这样的设定，如果一共雇佣过$M$个秘书，总共的开销是$O(NC_i+MC_h)$.

我们的目标是找到一个算法，使得期望成本最小.

### Naive Solution

直接遍历，考虑最坏情形是后一个人始终比前一个人优秀，从而不得不花费$NC_h$的成本.

??? tips "pseudocode"

    ```pseudocode
    int Hiring ( EventType C[ ], int N )
    {   /* candidate 0 is a least-qualified dummy candidate */
        int Best = 0;
        int BestQ = the quality of candidate 0;
        for ( i=1; i<=N; i++ ) {
            Qi = interview( i ); /* Ci */
            if ( Qi > BestQ ) {
                BestQ = Qi;
                Best = i;
                hire( i );  /* Ch */
            }
        }
        return Best;
    }
    ```

### Randomized Solution

考虑$X = \text{number of hires}$，用$X_i = \begin{cases} 1 & \text{雇佣} \\ 0 & \text{不雇佣}\end{cases}$，从而

$$E(X_i) = \dfrac{1}{i} \Longrightarrow E(X) = E(\sum\limits_{i=1}^nX_i) = \sum\limits_{i=1}^nE(X_i) = \sum\limits_{i=1}^n\dfrac1i = \ln n + \gamma_n + \epsilon$$

所以最终成本是$C_h\ln n+NC_i$.

pseudocode跟上面的大体上是一样的，但是多了一个randomized permutation algorithm的部分：

```pseudocode
void PermuteBySorting ( ElemType A[ ], int N )
{
    for ( i=1; i<=N; i++ )
        A[i].P = 1 + rand()%(N3); 
        /* makes it more likely that all priorities are unique */
    Sort A, using P as the sort keys;
}
```

### Online Hiring Algorithm

根据[维基百科](https://zh.wikipedia.org/wiki/%E7%A7%98%E6%9B%B8%E5%95%8F%E9%A1%8C)的陈述，上面的randomized实际上是不能使用的，因为我们没办法做到随机抽取一个人，反而则更加了程序的最坏开销.

于是我们引入了截断准则，即在前$k$个人里面选择一个最好的，只要后面的人中有比他更优秀的，我们就结束面试.

???+ tips "pseudocode"

    ```C
    int OnlineHiring ( EventType C[ ], int N, int k )
    {
        int Best = N;
        int BestQ = - inf;
        for ( i=1; i<=k; i++ ) {
            Qi = interview( i );
            if ( Qi > BestQ )   
                BestQ = Qi;
        }
        for ( i=k+1; i<=N; i++ ) {
            Qi = interview( i );
            if ( Qi > BestQ ) {
                Best = i;
                break;
            }
        }
        return Best;
    }
    ```

接下来计算$k$的值，使得我们找到最优秀的人的概率最高：

定义事件$S_i = \{\text{第i个人最优秀且刚好被选中了}\}$，则$S_i = A_i \cap B_i$，其中$A_i = \{\text{第i个人是最优秀的}\}, B_i = \{\text{第k+1-i-1位都没有被选中}\}$，且二者独立.

于是$P(S_i) = P(A_i \cap B_i) = P(A_i) P(B_i) = \dfrac{1}{N} \dfrac{k}{i-1}$，得

$$P(\text{Best_Found}) = \sum\limits_{i=k+1}^N P(S_i) = \sum\limits_{i=k+1}^N \dfrac{1}{N} \dfrac{k}{i-1} = \dfrac{k}{N} \sum\limits_{i=k}^{N-1} \dfrac{1}{i}$$

从而由积分放缩

$$\int^{N}_k \dfrac1x\mathrm{d}x < \sum\limits_{i=k}^{N-1} \dfrac{1}{i} < \int^{N-1}_{k-1} \dfrac1x\mathrm{d}x$$

得到：

$$\dfrac{k}{N}\ln \dfrac{N-1}{k-1}<\sum\limits_{i=k}^{N-1} \dfrac{1}{i}< \dfrac{k}{N}\ln \dfrac{N}{k}$$

在$k = \dfrac{N}{e}$附近概率最大.

## Quick Sort

我们已经学过deterministic quicksort，可以通过[usfca画板](https://www.cs.usfca.edu/~galles/visualization/ComparisonSort.html)和[资料1](https://www.geeksforgeeks.org/dsa/quick-sort-algorithm/),[wiki]()回顾一下.

??? tips "C++代码"

    ```cpp
    int partition(vector<int>& arr, int low, int high){
        int pivot = arr[high]; //pivot可以随便选取
        int i = low-1;
        for (int j = low; j <= high-1; j++){
            if (arr[j] < pivot){
                i++;
                swap(arr[i],arr[j]);
            }
        }
        swap(arr[i+1],arr[high]);
        return i+1;
    }
    void quicksort(vector<int>& arr, int low, int high){
        if (low < high){
            int pivot = partition(arr,low,high);
            quicksort(arr,low,pivot-1);
            quicksort(arr,pivot+1,high);
        }
    }
    ```

其基础性质是：

* $\Theta(N^2)$ worst-case running time
* $\Theta(N \log N)$ average case running time, assuming every input permutation is equally likely

如果我们考虑Randomized Algorithm来解决快排退化的问题，就需要随机选择其中的pivot（枢轴），并追加两个定义：

* **Central splitter** := the pivot that divides the set so that each side contains at least $\dfrac n4$.
* **Modified Quicksort** := always select a central splitter before recursions

此时每次随机选择1个pivot的概率是：$P_{CS} = \dfrac12$

选取次数$X$的期望值推导：

$$P(X = k) = (\dfrac12)^k \Longrightarrow E(X) = \sum\limits_{i=1}^{+\infty} i(\dfrac12)^i = 2$$

在上面的取法中我们不难发现，把问题切成小问题时，我们至少抛弃了$\dfrac14$的子问题大小，但是在计算总的时间复杂度上仍然相当棘手. 因为每次递归切分的比例不一样（虽然保证了至少切掉$\dfrac14$，但具体是切掉 30% 还是 50% 是不确定的），直接加总所有步骤的时间会非常混乱.

**引入 Type j 的目的是为了对这些大小不一的子问题进行“分类”或“分层”，以便于统计总工作量.**其定义如下：

如果一个子问题的大小 $S$ 满足 $N(\dfrac34)^{j+1} \leq |S| \leq N(\dfrac34)^{j}$，我们就把它标记为 Type j.

我们可以把 Type j 理解为**子问题的“代”或者“层级”**，其中 Type 0 是原始问题的较大子问题，Type 1 是切分一次后变小的问题，以此类推. 这实际上是利用了 **Central Splitter** 的性质：每次切分，子问题的规模**至多**变为原来的$\dfrac34$.

因为每一层Type j的工作量是$(\dfrac34)^{j+1}$，并且每次规模缩小$3/4$导致层数大约是$\log_{4/3}N$，所以总工作量是$O(N\log N)$级别的.

所以我们完成了期望值的推导，也可以看出这跟递归树的分析非常相近.

## PTA习题

??? tips "7.1-4,5"

    <center><img src = "../figures/random/7.1-4,5.png" style="zoom: 50%;"/></center>

    4的正确表述是，如果$b = (b_1,b_2,\cdots,b_n)$表示$a$排完序之后的结果，那么任意两个元素被比较过的次数最多是1，并且$b_i$和$b_j$被比较过的概率是$\dfrac{2}{j−i+1}, j>i$,如果$b_i$或者$b_j$被当作了pivot.

??? tips "7.3-1"

    <center><img src = "../figures/random/7.3-1.png" style="zoom: 50%;"/></center>

    A错是显然的，B的反例是当第二大的数在前$k$个中，且最大的数在末尾的数列.

    C的推导：记第1个值是$A[0]$. 如果它就是max，那么最终返回的结果一定不是max，概率是$\dfrac1n$; 否则：

    $$P(\text{Find Max}) = $$

??? tips "Final Practice 1 1-1"

    <center><img src = "../figures/random/f1-1.png" style="zoom: 50%;"/></center>

    并没有“好的”输入这种事情，因为随机化消除了输入的特性，期望值不会因此而改变. 任意输入序列，对应的效率期望值是恒定的，永远是$O(n\log n)$.
