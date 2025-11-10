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
