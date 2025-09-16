
## DSA Review

摘自自己的crypto lab1 report

!!! tips

    DSA签名算法的过程

    密钥选取：

    1. 首先指定素数$p,q$，其中$p$的长度是$L$，$q$的长度是$N<L$；

    2. 现在我们用以下方法找到合适的$g$：

    遍历$h = 2 \to p-2$的所有值，令$g = h^{\frac{p-1}{q}}\%p$且$g^k\equiv 1(\operatorname{mod} p)$的最小正整数解是$q$；

    3. 再选一个私钥$0<x<q$，取满足以下条件的$0<y<p$：$y = g^x (\operatorname{mod}p)$；

    这样就完成了公钥$p,q,g,y$和私钥$x$的选择。

    签名过程：

    1. 随机选择临时密钥$k(0<k<q)$（且不能重用，否则就会像这个题目一样被攻击）；

    2. $\begin{cases} r \equiv (g^k \% p) \% q & (\operatorname{mod}q) \\ s \equiv (H(m) + xr) k^{-1}\%q & (\operatorname{mod} q)\end{cases}$

    于是签名结果就是$(r,s)$

    验证过程：

    1. 计算辅助值，$w=s^{-1}(\operatorname{mod}q)$

    2. 计算辅助值，$u_1=H(m)w$ (mod $q$)

    3. 计算辅助值，$u_2=rw$ (mod $q$)

    4. 计算$v=(g^{u_{1}}y^{u_{2}}\operatorname{mod}p)$ (mod $q$)

    5. 如果$v = r$，则校验成功。



温习一下[DSA基础攻击题](https://zjusec.com/challenges/85)：

我的破解思路：

当$m_1 = m_2$时，有$H(m_1) = H(m_2)$，设为$H(m)$

两个签名变为：$$\begin{cases}s_1 \equiv k_1^{-1}(H(m) + xr_1) & (\operatorname{mod} q)\\
s_2 \equiv (k_1+1)^{-1}(H(m) + xr_2) & (\operatorname{mod} q)\end{cases}$$

化简得：$4(x(r_1 - r_2) + s_2)(s_1 - s_2)^{-1}s_1 \equiv H(m) + xr_1 (\operatorname{mod} q)$

解得 $x \equiv (H(m) - s_2s_1(s_1 - s_2)^{-1})[(r_1 - r_2)s_1(s_1 - s_2)^{-1} - r_1]^{-1} (\operatorname{mod} q)$

[DSA Revenge](https://zjusec.com/challenges/118)：

类似上题DSA的$k$复用情况，我的破解思路：

当$m_1 = m_2$时，有$H(m_1) = H(m_2)$，设为$H(m)$

两个签名变为：$$\begin{cases}s_1 \equiv (k>>160)^{-1}(H(m) + xr_1) & (\operatorname{mod} q)\\
s_2 \equiv [(ak+b)\%c>>160]^{-1}(H(m) + xr_2) & (\operatorname{mod} q) \end{cases}$$

解得 $x \equiv ??? (\operatorname{mod} q)$

需要看论文


