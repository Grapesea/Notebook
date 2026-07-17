# Math

[数学章节](https://leetcode.cn/quest/maths-quest/)

I-2

这个很有意思，最高效的如下：

```cpp
int cal(int n){
    return (n * (n + 1)) / 2;
}
class Solution {
public:
    int pivotInteger(int n) {
    	if (n == 1){return 1;}
    	if (n == 0){return -1;}
        int res = cal(n);
        for (int i = n-1;i > 0;i--){
			if (res - cal(i) == cal(i-1)){
				return i;
			}
        }
        return -1;
    }
};
```

我的虽然过了但是效率很低：

```cpp
class Solution {
public:
    int sum(int st, int ed){
        return (st+ed)*(ed-st+1) / 2;
    }
    int pivotInteger(int n) {
        for (int i = 1; i <= n; i++){
            if (sum(1,i) == sum(i, n)){
                return i;
            }
        }
        return -1;
    }
};
```

---

I-II 测试：

```cpp
class Solution {
public:
    int reverse(int x) {
        long res = 0;  // 用 long 防止溢出
        int temp = x;
        while (temp != 0) {
            res = res * 10 + temp % 10;
            temp /= 10;
        }
        // 超出 int 范围则返回 0
        if (res > INT_MAX || res < INT_MIN) return 0;
        return static_cast<int>(res);
    }
};
```

这里恶心的点是溢出处理，需要先用long储存，然后再static_cast转化成int.

---

