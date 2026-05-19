## Chap 1 概率论的基本概念

## Chap 2 随机分布及其概率分布

## Chap 3 多维随机变量及其分布

### 二维离散型随机变量

定义：$P(X = x_i,Y = y_i) = p_{ij},\quad i,j = 1,2,...$为$(X,Y)$的联合概率分布律（联合分布律），也可以列表来表示.

性质：$p_{ij} \geq 0$; $\quad \sum\limits_i \sum\limits_j p_{ij} = 1$.

边际分布律：$P(X = x_i) = \sum\limits_{j=1}^{+\infty} p_{ij} = p_{i\cdot}$ $\quad$ $P(Y = y_i) = \sum\limits_{i=1}^{+\infty} p_{ij} = p_{\cdot j}$

条件分布：当$P(Y = y_j) \neq 0$时，$P(X = x_i|Y = y_j) = \dfrac{P(X = x_i, Y = y_j)}{P(Y = y_j)} = \dfrac{p_{ij}}{p_{\cdot j}}$。

同理$P(Y = y_j|X = x_i) = \dfrac{P(X = x_i, Y = y_i)}{P(X = X_i)} = \dfrac{p_{ij}}{p_{i\cdot}}$

### 二维随机变量的分布函数

定义：对于二维随机变量$(X,Y)$，称

$$F(x,y) = P(X\leq x, Y \leq y)$$

是关于$(X,Y)$的联合概率分布函数.

性质：

1.

## Chap 4 随机变量的数字特征

### 数学期望

定义式：

1. 离散型：随机变量$X$的概率分布列：$P(X = x_i) = p_i,\quad (i = 1,2,...,)$. 若级数$\sum\limits_{i=1}^{+\infty}x_ip_i$绝对收敛，则记该级数为期望$E(X)$.
2. 连续型：$X$的密度函数是$f(x)$. 若$\int_{-\infty}^{+\infty}|x|f(x)\mathrm{d}x < +\infty$，则记$E(X) = \int_{-\infty}^{+\infty}xf(x)\mathrm{d}x$为期望.

结论：

* Poisson Distribution的期望就是$\lambda$，即$\quad \textcolor{red}{X \sim P(\lambda), \lambda > 0\rightarrow E(X) = \lambda}.$
* Exponential Distribution的期望就是$\dfrac1\lambda$，即$\quad \textcolor{red}{X \sim E(\lambda), \lambda > 0\rightarrow E(X) = \lambda}.$
* Standard Distribution的期望是$0$，即$\quad \textcolor{red}{X \sim N(0,1)\rightarrow E(X) = 0}.$

### 随机变量函数的数学期望

*标准化随机变量（标准化变量）：

$$X^* = \dfrac{X-E(X)}{\sqrt{\operatorname{Var}(X)}}$$

是无量纲数，$E(X^*) = 0,\operatorname{Var}(X^*) = 1$

这样操作可以消除计量单位不同造成的分布数据上的影响.

*变异参数(coefficient of variation)：

$$Cv = \dfrac{\sqrt{\operatorname{Var}(X)}}{E(X)}$$

反映了随机变量$X$在以它的中心位置做标准时，值的离散程度.

这2个概念在统计学中的应用也很广泛，按下不表，只列出来公式：

### 协方差与相关系数

???+ info "另一个角度的理解-内积空间"

    这一小节的性质很难不让人联想到线代II中提到过的“内积空间”，现在作一些一一映射的理解：
    
    $X,Y$-两个向量空间，可以简单理解成三维空间中两条直线；
    
    内积的定义-协方差计算式；
    
    $X,Y$相关-

​

$X,Y$独立$\Longrightarrow$ $E(XY) = E(X)E(Y) \Longrightarrow E[(X-E(X))(Y-E(Y))] = 0$

定义式：$X,Y$的协方差是

$$\operatorname{Cov}(X,Y) = E[(X-E(X))(Y-E(Y))]$$

计算式：

1. 离散型：

$$\operatorname{Cov}(X,Y) =\sum\limits_{i=1}^{+\infty}\sum\limits_{j=1}^{+\infty}(x_i-E(X))(y_i-E(Y))p_{ij}$$

2. 连续型：

$$\operatorname{Cov}(X,Y) =\int_{-\infty}^{+\infty}\int_{-\infty}^{+\infty}(x_i-E(X))(y_i-E(Y))f(x,y)\mathrm{d}x\mathrm{d}y$$

整合结果：

$$\operatorname{Cov}(X,Y) = E(XY) - E(X)E(Y)$$

<br/>

定理：

$$\operatorname{Var}(\sum\limits_{i=1}^n X_i) = \sum\limits_{i=1}^n \operatorname{Var}(X_i) + 2\sum\limits_{1\leq i < j \leq n}\operatorname{Cov}(X_i,X_j) $$

??? notes "eg 4.3.2 配对问题"

一堆定理：（注意跟内积性质的对比）

1. $\operatorname{Cov}(X,Y) = \operatorname{Cov}(Y,X)$;
2. $\operatorname{Cov}(X,X) = \operatorname{Var}(X)$;
3. $\operatorname{Cov}(aX,bY) = ab\operatorname{Cov}(X,Y),\quad a,b \in \mathbb{R}$;
4. $\operatorname{Cov}(X_1 + X_2,Y) = \operatorname{Cov}(X_1,Y) + \operatorname{Cov}(X_2,Y)$;
5. $\operatorname{Cov}(X,Y) = 0 \Longleftarrow X,Y \text{独立}$，但反之不然;
6. $\operatorname{Var}(X)\operatorname{Var}(Y) \neq 0$时，$(\operatorname{Cov}(X,Y))^2 \geq \operatorname{Var}(X)\operatorname{Var}(Y)$，取等：$\exists c_1,c_2 \in \mathbb{R}, Y = c_1X + c_2$.（这非常像商空间的前置概念-平移）

<br/>

相关系数：

对于随机变量$X,Y$，当$E(X^2),E(Y^2)$都存在且$\operatorname{Var}(X),\operatorname{Var}(Y)$均为非零实数时，定义$X,Y$的相关系数为：

$$\rho_{XY} = \dfrac{\operatorname{Cov}(X,Y)}{\sqrt{\operatorname{Var}(X)}\sqrt{\operatorname{Var}(Y)}}$$

联系上面的标准化处理，$\rho_{XY} = \operatorname{Cov}(X^*,Y^*),\text{其中}X^* = \dfrac{X-E(X)}{\sqrt{\operatorname{Var}(X)}},Y^* = \dfrac{Y-E(Y)}{\sqrt{\operatorname{Var}(Y)}}$.

$\rho = 0$表明$X,Y$不相关，或者零相关，其等价判别方法：

1. $\operatorname{Cov}(X,Y) = 0;$
2. $E(XY) = E(X)E(Y)$;
3. $\operatorname{Var}(X+Y) = \operatorname{Var}(X)+ \operatorname{Var}(Y)$.

有一个三角关系：

$X,Y$方差存在 $\Longrightarrow$ $X,Y$不相关 $\not\Longrightarrow$ $X,Y$独立；

$X,Y$相关 $\Longrightarrow$ $X,Y$不独立；

??? notes "eg 4.3.6"

但是某些情况下又是等价的，如二元正态分布中：

??? notes "eg 4.3.7"

### 课后习题整理

??? notes "B33-矩阵与正态分布"

    已知三维正态变量 $\mathbf{X} = (X_1, X_2, X_3)^T \sim N(\mathbf{a}, \mathbf{B})$，其中 $\mathbf{a} = (0, 0, 1)^T$，$\mathbf{B} = \begin{pmatrix} 1 & 2 & -1 \\ 2 & 16 & 0 \\ -1 & 0 & 4 \end{pmatrix}$.<br>
    (1) 写出 $\mathbf{X}$ 的每个分量的分布；<br>
    (2) 判别 $X_1, X_2, X_3$ 的相关性与独立性；<br>
    (3) 若 $Y_1 = X_1 - X_2, Y_2 = X_2 - X_3$，求 $\mathbf{Y} = (Y_1, Y_2)^T$ 的分布；

## Chap 5 大数定律及中心极限定理
