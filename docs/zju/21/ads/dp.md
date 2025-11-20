???+ into "参考资源"

    《算法导论》[P359开始（英文版）](https://www.cs.mcgill.ca/~akroit/math/compsci/Cormen%20Introduction%20to%20Algorithms.pdf)或者P204开始（中文版）.

    [Algorithm Design](https://www.cs.princeton.edu/~wayne/kleinberg-tardos/) 看Chap6.

    [代码随想录的动态规划部分](https://programmercarl.com/%E5%8A%A8%E6%80%81%E8%A7%84%E5%88%92%E7%90%86%E8%AE%BA%E5%9F%BA%E7%A1%80.html#%E7%AE%97%E6%B3%95%E5%85%AC%E5%BC%80%E8%AF%BE)

动态规划主要是考虑状态转移的构建方法，按照课后作业的问题、wyy的讲义和Algorithm Design、算法导论的内容进行笔记梳理.

## 加权独立集合问题

考虑一个无向图$G$，其上所有点都在同一条线上，每个点都有一个非负权重. 称$G$的独立集合是顶点互不相邻的子集. 我们需要找到具有最大顶点权重和的独立集合.

首先考虑最优子结构是如何构造的，设$G_n(V,E)$具有边$(v_1,v_2),\cdots,(v_{n-1},v_n)$，最优解是$S_n$，此时总权值之和是$W_{n}$.

* 如果$v_n \notin S$，则$S$是$G_{n-1}$的最优解；<br>
* 如果$v_n \in S$，由限制条件，$v_{n-1} \notin S$，则$W_{n} = W_{n-2}+\omega_n$.

于是可以导出最优子结构是

$$W_{n} = \max \{W_{n-1},W_{n-2}+\omega_n\} \Longrightarrow W_{i} = \max \{W_{i-1},W_{i-2}+\omega_i\}.$$

时间复杂度：$O(n)$.

???+ tips "代码"

    ```cpp
    class Solution{
        public:
        vector<int> maxsum(vector<int> w,int n){
            vector<int> A(n+1,0);
            A[0] = 0;
            A[1] = w[0];
            for (int i = 2; i <= n; i++)
                A[i] = max(A[i-1],A[i-2]+w[i-1]);
            return A;
        }
        vector<int> A = maxsum(const vector<int>& w, int n);
        vector<int> Sol(vector<int> A, vector<int> w, int n){ //解的重构函数
            vector<int> S;
            int i = n;
            while (i >= 2){
                if (A[i-1] >= A[i-2] + w[i-1]){
                    i = i-1;
                }else{
                    S.push_back(i-1);
                    i = i-2;
                }
            }
            if (i == 1)
                S.push_back(0);
            return S;
        }
    }
    ```

???+ tips "思考题1"

    算法递推仍然正确，只需要考虑初始条件的修改：$W_0 = 0; W_1 = \max\{W_0,\omega_1\}$ 
    
    最终答案会变成$\max(0, W_n)$（允许空集）

???+ tips "思考题2"

    <center><img src = "../figures/dp/1.png" style = "zoom:60%"/></center>

    答案：2，5

### PTA习题

??? tips "4.7-1 Missile Interception(最长递减子序列问题)"

    ```cpp
    #include<iostream>
    #include<vector>

    using namespace std;

    int main(){
        int N;
        vector<int> height(2000);
        vector<int> count(2000,1);
        cin >> N; 
        for (int i = 0; i < N; i++)
            cin >> height[i];

        for (int i = 1; i < N; i++)
            for (int j = 0; j < i; j++)
                if (height[j] >= height[i])
                    count[i] = max(count[i],count[j]+1);

        int maxcnt = 1;
        for (int i = 1; i < N; i++)
            maxcnt = max(maxcnt,count[i]);
        cout << maxcnt << endl;
    }
    ```

## 矩阵相乘

现在需要对4个矩阵进行乘法操作：

$$M_{1(10\times20)} \times M_{2(20\times50)} \times M_{3(50\times1)} \timesM_{4(1\times100)}$$

需要找到最佳的顺序，使得开销时间最小.

<center><img src = "../figures/dp/matrix_mul.jpg" style = "zoom:60%"/></center>

伪代码如下：

```c
void OptMatrix( const long r[ ], int N, TwoDimArray M ) 
{   int i, j, k, L; 
    long ThisM; 
    for(i = 1; i <= N; i++)   
        M[i][i] = 0; 
    for(k = 1; k < N; k++ ){ /* k = j - i */ 
        for( i = 1; i <= N - k; i++) { /* For each position */ 
            j = i + k;    
            M[i][j] = Infinity; 
            for( L = i; L < j; L++ ) { 
                ThisM = M[i][L]+ M[L+1][j]+ r[i-1]* r[L]* r[j]; 
                if ( ThisM < M[i][j] )  /* Update min */ 
                    M[i][j] = ThisM; 
            }  /* end for-L */
        }  /* end for-Left */
    }
}
```

时间复杂度：$O(N^3)$.

## Optimal Binary Search Tree

将$N$个word($w_i$对应的被搜索到的概率是$p_i$，单词序上 $w_1< w_2 < \cdots <w_N$ ) 放入一个BST中，找到最佳的顺序使得所有word被搜索到的期望时间之和最小.

首先可以看出，期望时间之和运算公式是$T(N) = \sum\limits_{i=1}^N p_i(1+d_i)$.

<center><img src = "../figures/dp/tree.jpg" style = "zoom:60%"/></center>

## All-Pairs Shortest Path

单源算法：$|V|$次，$T=O(|V|^3)$.

伪代码：

```cpp
/* A[ ] contains the adjacency matrix with A[ i ][ i ] = 0 */ 
/* D[ ] contains the values of the shortest path */ 
/* N is the number of vertices */ 
/* A negative cycle exists iff D[ i ][ i ] < 0 */ 
void AllPairs(vector<vector<int>> A, vector<vector<int>> D, int N ) 
{   

}
```

## Product Assembly

生产线选择问题

代码：

???+ tips "DP代码以及路径重建代码"
    ```cpp
    vector<vector<int>> f(2,vector<int>(N+1));
    f[0][0] = 0; f[1][0] = 0;
    for (stage = 1; stage <= N; stage++){
        for (line = 0; line <= 1; line++){
            f[line][stage] = f[line][stage-1]+t_process[line][stage-1];
        }
    }
    solution = min(f[0][n],f[1][n]);
    ```

    ```cpp
    vector<vector<int>> f(2,vector<int>(N+1));
    f[0][0] = 0;
    f[1][0] = 0;
    for (stage = 1; stage <= N; stage++){
        for(line = 0; line <=1; line++){
            f_stay = f[line][stage-1] + t_process[line][stage-1];
            f_move = f[1-line][stage-1] + t_transit[1-line][stage-1];
            f[line][stage] = min(f_stay,f_move);
        }
    }
    line = f[0][N] < f[1][N] ? 0:1;
    for (stage = n; stage > 0; stage --){
        plan[stage] = line;
        line = L[line][stage];
    }
    ```

## PTA习题

??? tips "2025fall-ch-mid"

    <center><img src = "../figures/dp/chmid3-3.png" style="zoom: 50%;"/></center>

    答案：`int j = 0; j < i; j++`, `dp[i] = max(dp[i], dp[j]+1)`
