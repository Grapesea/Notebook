???+ info "参考资料"

    [修佬的笔记](https://note.isshikih.top/cour_note/D2CX_AdvancedDataStructure/Lec07)

> 绝望的文盲决定使用代入法乱凑瞎蒙.

分治法的核心公式如下:

$$T(n) = aT(\dfrac{n}{b}) + f(n) \qquad f(n) = [\text{Work for the merge}],a \geq 1, b > 1$$

## 时间复杂度递推计算

???+ tips "举例"

    $T(N) = 2T(N/2)+cN \Longrightarrow T(N) = O(N\log N).$

    $T(N) = 2T(N/2)+cN^2 \Longrightarrow T(N) = O(N^2).$

### 代入法

对于比较简单的情况是采用“先猜后证”的思路，首先估计出数量级然后放缩.

???+ notes "eg."

    求出$T(n)$的时间复杂度:
    
    $$T(n) = 2T(\lfloor\sqrt n\rfloor) + \log n$$

    推导：$T(n) = \log n \log\log n$，因为

但是有些情况下，直接证并不容易. 此时可以像做某些数学证明题一样，加强命题.

### 递归树

$T(N) = 3T(N/4) + \Theta(N^2) \Longrightarrow T(N) = O(N^2).$

$T(N) = T(N/3) + T(2N/3) + cN \Longrightarrow O(N\log N).$

### 主定理及其推广

$$T(n) = aT(\dfrac{n}{b}) + f(n) \qquad f(n) = [\text{Work for the merge}],a \geq 1, b > 1$$

#### 主定理

<center><img src = "../figures/dc/mt.png" style = "zoom:60%"/></center>

#### 主方法

对于形如$T(N) = aT(N/b)+f(N)$，有：

1. $\exists \epsilon > 0, f(N) = O(N^{\log_ba-\epsilon})\Longrightarrow T(N) = \Theta(N^{\log_ba})$;
2. $f(N) = \Theta(N^{\log_ba})\Longrightarrow T(N) = \Theta(N^{\log_ba}\log N)$;（这里的$\epsilon$很有灵性，因为根据数学分析的知识，$f(N)$的规模严格大于$N^{\log_ba}$与任意对数的乘积）
3. $\exists \epsilon > 0, f(N) = \Omega(N^{\log_ba+\epsilon})\text{且} af(N/b)<cf(N), c < 1 , \forall N>N_0 \Longrightarrow T(N) = \Theta(f(N))$.

### PTA习题

??? tips "3.2-3"

    Assume that $T(1) = \Theta(1)$. Given $T(n) = T(\sqrt{n}) + T(\sqrt[3]n) + T(\sqrt[6]n) + \log n$, which of the following statements is correct?

    A. $T(n) = \Theta(n\sqrt n)$<br>
    B. $T(n) = \Theta(n\log n)$<br>
    C. $T(n) = \Theta(\log^2 n)$<br>
    D. $T(n) = \Theta(\log\log n)$<br>
    E. $T(n) = \Theta(\log n \log\log n)$<br>
    F. $T(n) = \Theta(\sqrt n \log\log n)$<br>

    选E.

??? tips "2025fall-ch-mid"

    Which of the following asymptotic upper bounds is correct?<br>
    A.$T(n)=2T(n−1)+1$. Then $T(n)=O(n^2)$.<br>
    B.$T(n)=T(n/5)+T(7n/10)+n$. Then $T(n)=O(n\log n)$<br>
    C.$T(n)=4T(n/2)+n^2/\log n$. Then $T(n)=O(n^2)$<br>
    D.$T(n)=3T(n/3)+n/\log n$. Then $T(n)=O(n\log \log n)$

??? tips "xyx-1"

    <center><img src = "../figures/dc/xyx-1.png" style = "zoom:60%"/></center>

    来自豆包：

    <center><img src = "../figures/dc/xyx-2.png" style = "zoom:60%"/></center>

## 实际应用案例

### PTA习题

??? tips "3.3-1"

    <center><img src = "../figures/dc/1.png" style = "zoom:60%"/></center>

??? tips "2024mid"

    <center><img src = "../figures/dc/2024mid4-1.png" style = "zoom:60%"/></center>

    <center><img src = "../figures/dc/2024mid4-2.png" style = "zoom:60%"/></center>

    <center><img src = "../figures/dc/2024mid4-3.png" style = "zoom:50%"/></center>

    答案：

    `a, mid + 1, r`<br>
    `a[i] < a[j]`<br>
    `ans += j - mid - 1`<br>
    `tmp[++cnt] = a[j++]`<br>
    `a[i] = tmp[i - l + 1]`

    以下来自豆包：

    要理解这些填空的作用，需结合**归并排序求逆序对**的分治思想（分、治、合三步，同时统计跨区间的逆序对），逐个分析如下：

    1. `MergeSort(a, mid + 1, r)`
    这是归并排序**“分”步骤**的递归调用，用于处理右半区间 `[mid+1, r]`。
    - 左半区间已通过 `MergeSort(a, l, mid)` 递归处理，右半区间递归处理后，左右两部分各自有序，为后续“合”步骤（统计逆序对、合并数组）做准备。

    2. `a[i] < a[j]`
    这是归并排序**“合”步骤**的元素比较条件，用于判断左半区间元素 `a[i]` 和右半区间元素 `a[j]` 的大小关系。
    - 若 `a[i] < a[j]`，说明这两个元素**不构成逆序对**（因为 `i < j` 且 `a[i] < a[j]`），因此将左元素 `a[i]` 放入临时数组 `tmp`，并后移左指针 `i`。

    3. `ans += j - mid - 1`
    这是**统计逆序对**的关键步骤（结合归并的有序性）。
    - 当 `a[i] < a[j]` 时，左元素 `a[i]` 小于右元素 `a[j]`。此时右半区间中 `[mid+1, j-1]` 的元素已被处理，而左半区间 `[i, mid]` 的元素后续会与右半区间剩余元素比较，这里通过 `j - mid - 1` 统计相关逆序对数量（利用区间长度的推导，保证计数正确）。

    4. `tmp[++cnt] = a[j++]`
    这是归并排序**“合”步骤**的元素存储操作，对应 `a[i] > a[j]` 的分支（`else` 逻辑）。
    - 当 `a[i] > a[j]` 时，说明 `a[j]` 与左半区间 `[i, mid]` 的所有元素构成逆序对（因为左半区间有序，`a[i] <= a[i+1] <= ... <= a[mid]`，均大于 `a[j]`）。此时将右元素 `a[j]` 放入临时数组 `tmp`，并后移右指针 `j`。

    5. `a[i] = tmp[i - l + 1]`
    这是归并排序**“合”步骤**的数组复制操作，用于将临时数组 `tmp` 中的有序元素复制回原数组 `a`。
    - 临时数组 `tmp` 存储的是区间 `[l, r]` 合并后的有序元素，原数组的索引 `i`（范围 `[l, r]`）与 `tmp` 的索引关系为 `i - l + 1`（因为 `tmp` 从下标1开始存储，需通过偏移量对齐）。

    综上，这些填空围绕**归并排序的分治逻辑**和**逆序对的统计规则**展开，最终将时间复杂度从暴力法的 $O(n^2)$ 优化到 $O(n\log n)$，体现了分治算法的高效性。

??? tips "2021mid"

    <center><img src = "../figures/dc/2021mid-1.png" style = "zoom:60%"/></center>

    应该是$f(N) = O(N^{\log_b a}) \Longrightarrow T(N) = O(N^{\log_b a}\log N)$.
