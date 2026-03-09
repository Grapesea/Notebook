### 二分查找

704. 复健，本身极水，但没想到被位运算暗算了（注意运算优先级，`>>`优先级低于`+`）。

```c++
class Solution {
public:
    int search(vector<int>& nums, int target) {
        int left = 0, right = nums.size() - 1;
        while (left <= right){
            int mid = left + ((right - left) >> 1);  // 需要加括号
            if (nums[mid] > target){
                right = mid - 1;
            }else if(nums [mid] < target){
                left = mid + 1;
            }else{
                return mid;
            }
        }
        return -1;
    }
};
```

35 34 

