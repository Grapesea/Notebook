回溯必定伴随着递归.

模板：

```pseudocode
void backtracking(参数) {
    if (终止条件) {
        存放结果;
        return;
    }

    for (选择：本层集合中元素（树中节点孩子的数量就是集合的大小）) {
        处理节点;
        backtracking(路径，选择列表); // 递归
        回溯，撤销处理结果
    }
}
```

??? tips "77.Combinations"

    [地址](https://leetcode.com/problems/combinations/)

    这个回溯有点难懂……考虑用树来理解，每一层相当于一个选择，放入path之后接着枚举，
    退出之后回溯到上一层并把刚刚得到的放到path中.

    ```cpp
    class Solution {
    private:
        vector<vector<int>> result;
        vector<int> path;
        void backtracking(int n, int k, int startIndex) {
            if (path.size() == k) {
                result.push_back(path);
                return;
            }
            for (int i = startIndex; i <= n; i++) { // 优化的地方
                path.push_back(i); // 处理节点
                backtracking(n, k, i + 1);
                path.pop_back(); // 回溯，撤销处理的节点
            }
        }
    public:

        vector<vector<int>> combine(int n, int k) {
            backtracking(n, k, 1);
            return result;
        }
    };
    ```

    这里还有一个剪枝：如果for循环选择的起始位置之后的元素个数**已经不足**需要的元素个数，那么就没有必要搜索了.

    于是可以将for的终止条件改成`i <= n - (k - path.size()) + 1`.

??? tips "216.Combination Sum III"

    [地址](https://leetcode.com/problems/combination-sum-iii/)

    ```cpp
    class Solution {
    private:
        vector<vector<int>> result;
        vector<int> path;
        int sum;
        auto backtracking(int target, int k, int sum, int start){
            if (path.size() == k) {
                if(sum == target) result.push_back(path);
                return;
            }
            for (int i = start; i <= 9; i++){
                sum += i;
                path.push_back(i);
                backtracking(target, k, sum, i+1);
                sum -= i;
                path.pop_back();
            }

        }
    public:
        vector<vector<int>> combinationSum3(int k, int n) {
            backtracking(n,k,0,1);
            return result;
        }
    };
    ```

    这里可以做一些剪枝，比如在`sum > target`的时候直接返回即可，因为已经不可能达成了.
