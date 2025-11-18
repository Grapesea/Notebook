???+ info "教程地址"

    [动态规划理论基础](https://www.programmercarl.com/%E5%8A%A8%E6%80%81%E8%A7%84%E5%88%92%E7%90%86%E8%AE%BA%E5%9F%BA%E7%A1%80.html)

动态规划要点：

* 确定dp数组与问题中状态的映射关系；
* 找到状态转移的递推公式；
* 考虑好初始状态；
* 确定遍历顺序；
* 用样例检验一下代码逻辑是否正确.

## 基础1-10

??? tips "[509.斐波那契](https://leetcode.com/problems/fibonacci-number/)"

    ```cpp
    class Solution {
    public:
        int fib(int n) {
            if (n == 0 || n == 1)
                return n;
            vector<int> dp(n+1);
            dp[0] = 0;
            dp[1] = 1;
            for (int i = 2; i <= n; i++)
                dp[i] = dp[i-1] + dp[i-2];
            return dp[n];
        }
    };
    ```

    这样做的时间空间复杂度均为\(O(n)\)，而递归时间复杂度是\(O(2^n)\).

    70.同理，略.

??? tips "[746.Min Cost Climbing Stairs](https://leetcode.com/problems/min-cost-climbing-stairs/description/)"

    首先，可以把cost数组理解成跳跃后的花费.

    ```cpp
    class Solution {
    public:
        int minCostClimbingStairs(vector<int>& cost) {
            vector<int> dp(cost.size()+1);
            dp[0] = 0;
            dp[1] = 0;
            for (int i = 2; i <= cost.size(); i++){
                dp[i] = min(dp[i-1] + cost[i-1], dp[i-2] + cost[i-2]);
            }
            return dp[cost.size()];
        }
    };
    ```

    时间空间复杂度均为\(O(n)\).

??? tips "[62.Unique Path I](https://leetcode.com/problems/unique-paths) & [63. Unique Path II](https://leetcode.com/problems/unique-paths-ii/)"

    这2个是较为简单的动规.

    ```cpp
    class Solution {
    public:
        int uniquePaths(int m, int n) {
            vector<vector<int>> dp(m, vector<int>(n, 0)); // Initialize a m \times n array with all elements filled with 0.
            for (int i = 0; i < m; i++) dp[i][0] = 1;
            for (int j = 0; j < n; j++) dp[0][j] = 1;
            for (int i = 1; i < m; i++) {
                for (int j = 1; j < n; j++) {
                    dp[i][j] = dp[i - 1][j] + dp[i][j - 1];
                }
            }
            return dp[m - 1][n - 1];
        }
    };
    ```

    还有一个数论方法，但是需要注意溢出的处理：

    ```cpp
    class Solution {
    public:
        int uniquePaths(int m, int n) {
            long long numerator = 1; // 分子
            int denominator = m - 1; // 分母
            int count = m - 1;
            int t = m + n - 2;
            while (count--) {
                numerator *= (t--);
                while (denominator != 0 && numerator % denominator == 0) {
                    numerator /= denominator;
                    denominator--;
                }
            }
            return numerator;
        }
    };
    ```

    63这题要注意数组初始化，我一开始没意识到，然后出问题了.

    ```cpp
    class Solution {
    public:
        int uniquePathsWithObstacles(vector<vector<int>>& obstacleGrid) {
            int m = obstacleGrid.size();
            int n = obstacleGrid[0].size();
            vector<vector<int>> dp(m,vector<int>(n,0));
            if (obstacleGrid[0][0]) return 0;
            if (m == 1 && n == 1) return 1;
            int i = 1, j = 1;
            int f = 1;
            while (i < m){
                if (obstacleGrid[i][0]) f = 0;
                dp[i][0] = f;
                i++;
            }
            f = 1;
            while (j < n){
                if (obstacleGrid[0][j]) f = 0;
                dp[0][j] = f;
                j++;
            }
            for (int i = 1; i < m; i++)
                for (int j = 1; j < n; j++)
                    dp[i][j] = (obstacleGrid[i][j] ? 0 : (dp[i-1][j] + dp[i][j-1]));
            return dp[m-1][n-1];
        }
    };
    ```

??? tips "[343.Integer Break](https://leetcode.com/problems/integer-break/)"

    ```cpp
    class Solution {
    public:
        int integerBreak(int n) {
            vector<int> dp(n+1,1);
            for (int i = 3; i <= n; i++){
                for (int j = 1; j <= i/2; j++)
                    dp[i] = max(dp[i], max((i - j) * j, dp[i - j] * j)); //这里不能忘记加上对(i - j) * j的取max.
            }
            return dp[n];
        }
    };
    ```

??? tips "[96. Unique Binary Search Trees](https://leetcode.com/problems/unique-binary-search-trees/)"

    ```cpp
    class Solution {
    public:
        int numTrees(int n) {
            vector<int> dp(n+1,0);
            if (n == 1) return 1;
            dp[0] = 1;
            dp[1] = 1;
            dp[2] = 2;
            for (int i = 3; i <= n; i++)
                for (int j = 0; j < i; j++)
                    dp[i] += (dp[j] * dp[i-j-1]);
            return dp[n];
        }
    };
    ```

## 0-1背包问题

??? tips "ADS-hw5-PTA"

    这是0-1背包的基础板子.

    ```cpp
    #include<iostream>
    #include<vector>
    #include<algorithm>
    using namespace std;
    int main(){
        int N,V;
        cin >> N >> V;
        vector<int> value(N);
        vector<int> weight(N);
        for (int i = 0; i < N; i++){
            cin >> weight[i] >> value[i];
        }

        vector<vector<int>> dp(N,vector<int>(V+1,0));
        for (int i = 0; i < N; i++)
            dp[i][0] = 0;
        for (int i = 0; i < value[0];i++)
            dp[0][i] = 0;
        for (int i = weight[0];i <= V;i++)
            dp[0][i] = value[0];
        for (int i = 1; i < N; i++){
            for (int j = 1; j <= V; j++){
                if(j >= weight[i])
                    dp[i][j] = max(dp[i-1][j], dp[i-1][j-weight[i]]+value[i]);
                else
                    dp[i][j] = dp[i-1][j];
            }
        }
        cout << dp[N-1][V] << endl;
    }
    ```
