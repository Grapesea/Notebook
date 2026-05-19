# Dynamic Programming

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

## House Robber

[198. House Robber](https://leetcode.com/problems/house-robber/)

??? tips "sol"

    ```c
    int max(int* nums, int* sum, int pos){
        return (sum[pos-2] + nums[pos] > sum[pos-1]) ? sum[pos-2] + nums[pos] : sum[pos-1];
    }
    
    int rob(int* nums, int numsSize) {
        int* sum = (int*) malloc(numsSize * sizeof(int));
        sum[0] = nums[0];
        if (numsSize == 1) return sum[0];
    
        sum[1] = (nums[0] < nums[1]) ? nums[1] : nums[0];
        if (numsSize == 2) return sum[1];
        sum[2] = (nums[0] + nums[2] > nums[1]) ? nums[0] + nums[2] : nums[1];
    
        for (int i = 3; i < numsSize; i++){
            sum[i] = max(nums, sum, i);
        }
        return sum[numsSize-1];
    }
    ```

[House Robber II](https://leetcode.com/problems/house-robber-ii/)

这里需要注意的是max函数传入时`st`参数也需进入，否则会丢失信息造成样例错误.

??? tips "sol"

    ```c
    int max(int* nums, int st, int* sum, int pos){
        if (sum[pos-2] + nums[st + pos] > sum[pos-1])
            return sum[pos-2] + nums[st + pos];
        else 
            return sum[pos-1];
    }
    
    int rob_s(int* nums, int st, int ed){
        int numsSize = ed - st + 1;
        
        int* sum = (int*) malloc(numsSize * sizeof(int));
        sum[0] = nums[st];
        if (numsSize == 1) {
            int result = sum[0];
            free(sum);
            return result;
        }
        
        sum[1] = (nums[st] < nums[st+1]) ? nums[st+1] : nums[st];
        if (numsSize == 2) {
            int result = sum[1];
            free(sum);
            return result;
        }
        
        if (nums[st] + nums[st+2] > nums[st+1])
            sum[2] = nums[st] + nums[st+2];
        else
            sum[2] = nums[st+1];
        
        for (int i = 3; i < numsSize; i++)
            sum[i] = max(nums, st, sum, i);
        
        int result = sum[numsSize-1];
        free(sum);
        return result;
    }
    
    int rob(int* nums, int numsSize) {
        if (numsSize == 0) return 0;
        if (numsSize == 1) return nums[0];
        
        int result1 = rob_s(nums, 0, numsSize-2);
        int result2 = rob_s(nums, 1, numsSize-1);
        
        return result1 > result2 ? result1 : result2;
    }
    ```

[House Robber III](https://leetcode.com/problems/house-robber-iii/)

树形dp：用`size=2`的sum数组进行dp，sum[0]表示不取，sum[1]表示取走，后序遍历整棵树来获得最终信息.

??? tips "sol"

    ```c
    /**
    * Definition for a binary tree node.
    * struct TreeNode {
    *     int val;
    *     struct TreeNode *left;
    *     struct TreeNode *right;
    * };
    */
    
    int *rob_t(struct TreeNode *node){
        int* sum = (int*) malloc(sizeof(int) * 2);
        memset(sum, 0, sizeof(int) * 2);
        if (!node) return sum;
        int* left = rob_t(node->left);
        int* right = rob_t(node->right);
        sum[0] = fmax(left[0],left[1]) + fmax(right[0],right[1]); 
        //fmax: return the maximum between 2 float numbers.
        sum[1] = node->val + left[0] + right[0];
        // 0表示不偷当前节点，1表示偷当前节点.
        return sum;
    }
    
    int rob(struct TreeNode* root) {
        int* dp = rob_t(root);
        return fmax(dp[0],dp[1]);
    }
    ```

## 股票交易

[121. 买卖股票的最佳时机](https://leetcode.com/problems/best-time-to-buy-and-sell-stock/)

创建了一个二维dp数组，其中pricesSize个行，2个列. 列用于表示交易或者不交易之后的最优利润值.

??? tips "sol"

    ```c
    int maxProfit(int* prices, int pricesSize) {
        if (pricesSize == 0) return 0;
    
        int** dp = (int**) malloc(sizeof(int*) * pricesSize);
        for(int i = 0; i < pricesSize; i++){
            dp[i] = malloc(sizeof(int)*2);
        }
    
        dp[0][0] = -prices[0];
        dp[0][1] = 0;
        for (int i = 1; i < pricesSize; i++){
            dp[i][0] = fmax(-prices[i], dp[i-1][0]);
            dp[i][1] = fmax(prices[i] + dp[i][0], dp[i-1][1]);
        }
        return dp[pricesSize - 1][1];
    }
    ```

[122. 买卖股票的最佳时机II](https://leetcode.com/problems/best-time-to-buy-and-sell-stock-ii/description/)

??? tips "sol"

    ```c
    
    ```