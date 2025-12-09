## Chap 6 统计量与抽样分布

### 样本与统计量

$X_1,X_2,\cdots,X_n$是来自总体$X$的样本，如果$g(X_1,X_2,\cdots,X_n)$是其函数，且不含其他未知参数，则称$g$为统计量.

重要统计量列举：

* 样本均值：$\bar{X} = \dfrac{1}{n}\sum\limits_{i=1}^n X_i$
* 样本方差：$S^2 = \textcolor{red}{\dfrac{1}{n-1}}\sum\limits_{i=1}^n (X_i-\bar{X})^2$
* 样本标准差：$S = \sqrt{\dfrac{1}{n-1}\sum\limits_{i=1}^n (X_i-\bar{X})^2}$
* 样本$k$阶原点矩：$A_k = \dfrac{1}{n}\sum\limits_{i=1}^nX_i^k$
* 样本$k$阶中心矩：$B_k = \dfrac{1}{n}\sum\limits_{i=1}^n(X_i-\bar{X})^k$

### $\chi^2,t,F$分布

#### Gamma函数性质列举

$$\Gamma(x) = \int^{\infty}_0 t^{x-1}e^{-t}\mathrm{d}t$$

性质：

* $\Gamma(\dfrac12) = \sqrt{\pi}$
* $\Gamma(s+1) = s\Gamma(s)$

不过这个在概统做题中使用很少.

#### $\chi^2,t,F$分布定义

实际应用中的选择：

| 情况 | 使用的分布 |
|------|-----------|
| 已知 $\sigma$，推断 $\mu$ | 正态分布 |
| 未知 $\sigma$，推断 $\mu$ | $t$分布 |
| 推断 $\sigma^2$ | $\chi^2$分布 |
| 比较两个$\sigma^2$ | $F$分布 |

#### 习题

## Chap 7 参数估计

## Chap 8 假设检验
