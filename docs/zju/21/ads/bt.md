
## Turnpike Reconstruction Problem

给定$\dfrac{N^2-N}{2}$个距离值，重建$N$个点的坐标，使得这些点两两距离恰好是给定的距离集合. 假设$x_1= 0$.

处理方法采用回溯法，过程：

1. 固定 $x_1 = 0，x_N = max$;
2. 每次取最大剩余距离$D_{max}$;
3. 尝试将新点放在左端($x = D_{max}$)或右端($x = x_N - D_{max}$);
4. 检查新点到已放置点的距离是否都在剩余距离集合中;
5. 可行则递归，否则回溯.

伪代码如下：

```
Turnpike(D[], N):
    x[1] = 0
    x[N] = FindMax(D)
    Delete(D, x[N])
    return Place(x, D, N, 2, N-1)

Place(x, D, n, left, right):
    if D is empty:
        return true
    
    D_max = FindMax(D)
    
    // 尝试放在左端
    if CheckDistances(x, D_max, left):
        x[left] = D_max
        RemoveDistances(D, x, left)
        if Place(x, D, n, left+1, right):
            return true
        RestoreDistances(D, x, left)  // 回溯
    
    // 尝试放在右端
    if CheckDistances(x, x[n] - D_max, right):
        x[right] = x[n] - D_max
        RemoveDistances(D, x, right)
        if Place(x, D, n, left, right-1):
            return true
        RestoreDistances(D, x, right)  // 回溯
    
    return false

CheckDistances(x, pos, index):
    for i = 1 to index-1:
        if |x[i] - pos| not in D:
            return false
    return true
```

??? tips "C语言实现-Claude 4.5 Sonnet"

    ```c
    #include <stdio.h>
    #include <stdlib.h>
    #include <stdbool.h>
    #include <math.h>

    #define MAXN 105

    int dist[MAXN * MAXN / 2];  // 距离数组
    int dist_count[10005];       // 距离计数(用于多重集合)
    int x[MAXN];                 // 点的坐标
    int N;                       // 点的个数

    // 检查距离是否存在
    bool check_exist(int d) {
        return dist_count[d] > 0;
    }

    // 删除距离
    void remove_dist(int d) {
        dist_count[d]--;
    }

    // 添加距离
    void add_dist(int d) {
        dist_count[d]++;
    }

    // 检查新点pos与已放置点的距离是否都存在
    bool check_distances(int pos, int left, int right) {
        for (int i = 1; i < left; i++) {
            if (!check_exist(abs(x[i] - pos)))
                return false;
        }
        for (int i = right + 1; i <= N; i++) {
            if (!check_exist(abs(x[i] - pos)))
                return false;
        }
        return true;
    }

    // 删除新点与已放置点的所有距离
    void remove_all_distances(int pos, int left, int right) {
        for (int i = 1; i < left; i++)
            remove_dist(abs(x[i] - pos));
        for (int i = right + 1; i <= N; i++)
            remove_dist(abs(x[i] - pos));
    }

    // 恢复距离(回溯)
    void restore_all_distances(int pos, int left, int right) {
        for (int i = 1; i < left; i++)
            add_dist(abs(x[i] - pos));
        for (int i = right + 1; i <= N; i++)
            add_dist(abs(x[i] - pos));
    }

    // 找最大距离
    int find_max() {
        for (int i = 10000; i >= 0; i--) {
            if (dist_count[i] > 0)
                return i;
        }
        return -1;
    }

    // 回溯放置点
    bool place(int left, int right) {
        if (left > right)
            return true;  // 所有点已放置
        
        int d_max = find_max();
        if (d_max == -1)
            return true;
        
        // 尝试放在左端
        if (check_distances(d_max, left, right)) {
            x[left] = d_max;
            remove_all_distances(d_max, left, right);
            
            if (place(left + 1, right))
                return true;
            
            restore_all_distances(d_max, left, right);
        }
        
        // 尝试放在右端
        int pos = x[N] - d_max;
        if (check_distances(pos, left, right)) {
            x[right] = pos;
            remove_all_distances(pos, left, right);
            
            if (place(left, right - 1))
                return true;
            
            restore_all_distances(pos, left, right);
        }
        
        return false;
    }

    bool reconstruct() {
        // 初始化距离计数
        for (int i = 0; i < 10005; i++)
            dist_count[i] = 0;
        
        int num_dist = N * (N - 1) / 2;
        int max_dist = 0;
        
        for (int i = 0; i < num_dist; i++) {
            dist_count[dist[i]]++;
            if (dist[i] > max_dist)
                max_dist = dist[i];
        }
        
        // 固定第一个和最后一个点
        x[1] = 0;
        x[N] = max_dist;
        remove_dist(max_dist);
        
        return place(2, N - 1);
    }

    int main() {
        scanf("%d", &N);
        int num_dist = N * (N - 1) / 2;
        
        for (int i = 0; i < num_dist; i++)
            scanf("%d", &dist[i]);
        
        if (reconstruct()) {
            for (int i = 1; i <= N; i++)
                printf("%d ", x[i]);
            printf("\n");
        } else {
            printf("No solution\n");
        }
        
        return 0;
    }
    ```

这个算法的时间复杂度最坏情况为$O(2^N)$，因为每个位置有两种选择（左或右）；但实际运行时通常远小于$O(2^N)$，因为剪枝效果好.

空间复杂度是$O(N^2)$，因为存储$\dfrac{N(N-1)}{2}$个距离；递归栈深度：$O(N)$

代码实现的关键点是设置了一个桶，使用数组计数实现多重集合，$O(1)$时间检查和删除距离.

### PTA习题

???+ notes "3.3-2"
    In a turnpike reconstruction problem, the distance set is given as $\{1, 1, 2, 4, 4, 5, 5, 5, 6, 6, 7, 9, 10, 11, 12\}$. In now backtracking state(a node in the backtracking tree), we temporarily identify four points: $x_1=0,x_2=12,x_3=1,x_4=2$, which next try is possible？

    A.$x_5=3$ $\quad$ B.$x_5=4$ $\quad$ C.$x_5=5$ $\quad$ D.$x_5=6$ $\quad$ E.$x_5=7$ $\quad$ F.$x_5=8$ $\quad$ G.$x_5=9$ $\quad$ 

    答案是

## Alpha-Beta Pruning

算法伪代码：

```cpp
function AlphaBeta(state, depth, α, β, isMaxPlayer):
    if state是终局 or depth = 0:
        return 评估值
    
    if isMaxPlayer:
        maxEval = -∞
        for each child in state的后继状态:
            eval = AlphaBeta(child, depth-1, α, β, false)
            maxEval = max(maxEval, eval)
            α = max(α, eval)
            if β ≤ α:  // β剪枝
                break
        return maxEval
    else:
        minEval = +∞
        for each child in state的后继状态:
            eval = AlphaBeta(child, depth-1, α, β, true)
            minEval = min(minEval, eval)
            β = min(β, eval)
            if β ≤ α:  // α剪枝
                break
        return minEval
```

剪枝效果：

1. **不影响结果**：找到的最优解与完整Minimax相同
2. **大幅减少搜索节点**：
    最坏情况：$O(b^d)$（无剪枝效果）<br>
    最好情况：$O(b^(d/2))$（剪枝一半深度）<br>
    $b =$ 分支因子，$d =$ 树深度
3. **节省时间**：对于井字棋等简单游戏效果明显，对于复杂游戏（如国际象棋）至关重要.
