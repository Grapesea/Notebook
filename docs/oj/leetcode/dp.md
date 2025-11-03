???+ info "教程地址"

    [动态规划理论基础](https://www.programmercarl.com/%E5%8A%A8%E6%80%81%E8%A7%84%E5%88%92%E7%90%86%E8%AE%BA%E5%9F%BA%E7%A1%80.html)

动态规划要点：

* 确定dp数组与问题中状态的映射关系；
* 找到状态转移的递推公式；
* 考虑好初始状态；
* 确定遍历顺序；
* 用样例检验一下代码逻辑是否正确.

??? tips "509.斐波那契"

    [地址](https://leetcode.com/problems/fibonacci-number/)

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

??? tips "746.Min Cost Climbing Stairs"

    [地址](https://leetcode.com/problems/min-cost-climbing-stairs/description/)

    首先，可以把cost数组理解成

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
