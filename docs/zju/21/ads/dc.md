分治法的核心公式如下:

$$T(n) = aT(\dfrac{n}{b}) + f(n) \qquad f(n) = [\text{Work for the merge}],a \geq 1, b > 1$$

## 时间复杂度递推计算

### 代入法

对于比较简单的情况是采用“先猜后证”的思路，首先估计出数量级然后放缩.

???+ notes "eg."

    求出$T(n)$的时间复杂度:
    
    $$T(n) = 2T(\lfloor\sqrt n\rfloor) + \log n$$

    推导：$T(n) = \log n \log\log n$，因为

但是有些情况下，直接证并不容易. 此时可以像做某些数学证明题一样，加强命题.

### 主定理及其推广

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

## 实际应用案例

### PTA习题

??? tips "3.3-1"

    <center><img src = "../figures/dc/1.png" style = "zoom:60%"/></center>
