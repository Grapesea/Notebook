## Coppersmith方法(sagemath的使用)

摘自自己的crypto lab3 report

参考文档：[Dense univariate polynomials over ZZ, implemented using NTL - Polynomials](https://doc.sagemath.org/html/en/reference/polynomial_rings/sage/rings/polynomial/polynomial_modn_dense_ntl.html#sage.rings.polynomial.polynomial_modn_dense_ntl.small_roots)

[Coppersmith算法解决RSA加密问题-先知社区](https://xz.aliyun.com/news/13209)

沉寂已久的Coppersmith出现了，我以为lab2就会用到的，然后想得过于复杂折磨死了自己，但现在还在做单变量Coppersmith的阅读理解.

!!! tips

    Coppersmith方法的理论基础

    * Coppersmith引理：

        对mod N下度数为$d$的首一多项式$f$，若$n$是$N$的因子，$n N^{\beta}, 0 < \beta \leq 1$，则可以**在多项式时间内**求出mod N下$\vert x_0\vert < N^{\frac{\beta^2}{d}}$的根.

        * $n = N: \vert x_0\vert < N^{\frac{1}{d}}$
        * RSA中，$p \approx N^{0.5}$，所以可以求出$ \vert x_0\vert < N^{\frac{1}{4d}}$.

    * 单变元的Coppersmith方法：

        假设我们有定义在mod M下度数为$d$的整系数首一多项式$f(x) = x^d + \sum\limits_{i = 0}^{d-1} a_ix^i$，如果已知存在$x_0$是$F(x)$的根，即$F(x)\equiv 0 (\operatorname{mod} M)$且满足$\vert x_0\vert < M^{\frac{1}{d}}$，则求确切解$x_0$用到以下的Howgrave-Graham Lemma：

        定义$X$是$\vert x_0\vert$取值的上界，将$F(x)$表示为行向量$b_F = (a_0,a_1x,\cdots, a_dx^d)$，只要找到$x$使得$\|b_F\|< \dfrac{M}{\sqrt{d+1}}$，则$x$就是所求的根（这一定理可以用Cauchy不等式+绝对值不等式证明）

    * Coppersmith Attack：

        本质是通过LLL找到一个小系数的多项式来满足上述引理的条件：

        考虑如下的$d-1$个多项式：$G_i(x) = Mx^i, 0\leq i < d$，由于每个$G_i$都满足$G_i(x_0) \equiv 0(\operatorname{mod} M)$，所以线性组合之后也能满足$F(x_0) \equiv 0 (\operatorname{mod} M)$，于是目标变成了找到使得$\|b_F\|\leq \dfrac{M}{\sqrt{d+1}}$的$F$.

        构造格：$$L = \begin{bmatrix} M & 0 & \cdots & 0 & 0 \\ 0 & Mx & \cdots & 0 & 0 \\ \cdots & \cdots & \cdots & \cdots &\cdots \\ 0 & 0 & \cdots & Mx^{d-1} & 0 \\ a_0 & a_1x & \cdots & a_{d-1}x^{d-1} & a_dx^d \end{bmatrix}$$

        使用LLL算法之后得到了结果$F'$满足$F'(x_0) \equiv 0 (\operatorname{mod} M)$且$b_{F}$较小. 但是这个范围只是初步的，与Coppersmith的界还有一定的距离.（后面的分析略，涉及到shift polynomial等操作）

    应用上，**Sagemath的`small_root()`函数，是单变元方法的集成.**

### 校巴137-Crush on Proust

Coppersmith下的RSA，但是题目描述很谜语人：

Et en amour, il est plus facile de renoncer à un sentiment que de perdre une habitude.
在爱情中，放弃一种感情比改掉一个习惯更容易。

```python
from Crypto.Util.number import getPrime
from gmpy2 import next_prime
from random import getrandbits

flag = ?

p=getPrime(1024)
q=next_prime(p+(p&((1<<600)-1))^getrandbits(200))
n=p*q
e=65537
 
m=int(flag.hex(),16)
assert m<n
c=pow(m,e,n)

with open("output.txt","w") as f:
    f.write("n = "+str(n)+"\nc = "+str(c))
```

output.txt中就是$n,c$的值.



### 校巴134-Magic Mod

不会做，以后有时间了再看看（：


