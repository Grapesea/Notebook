# Chap2-Perceptron(感知机)

感知机原理：

$$y = \begin{cases}0 & (w_1x_1 + w_2x_2 \leq \theta) \\ 1 & (w_1x_1 + w_2x_2 > \theta)\end{cases}$$

其中$w_1,w_2$为权重，$x_1,x_2$为输入信号，$y$为输出信号，$\theta$为阈值.

传入信号总和大于阈值时称为激活，输出1；否则输出0.

---

感知机可以表示`AND`, `NAND`, `OR`.

```py
def AND(x1, x2):
    w1, w2, theta = 0.5, 0.5, 0.7
    tmp = w1*x1 + w2*x2
    if tmp <= theta:
        return 0
    else:
        return 1
```

---

导入权重与偏置：

$y = \begin{cases}0 & (w_1x_1 + w_2x_2 + b \leq 0) \\ 1 & (w_1x_1 + w_2x_2 + b > 0)\end{cases},\quad b = -\theta$

```python
import numpy as np
x = np.array([0,1])
w = np.array([0.5, 0.5])
b = -0.7

mul = x*w 				# = np.array([0., 0.5])
prod = np.sum(mul)		 # = 0.5
res = np.sum(w*x) + b    # = -0.2
```

于是`AND`的实现：

```python
def AND(x1, x2):
	x = np.array([x1, x2])
    w = np.array([0.5, 0.5])
    b = -0.7
    return 0 if (np.sum(w*x) + b <= 0) else 1
```

`NAND`:

```python
def NAND(x1, x2):
	x = np.array([x1, x2])
    w = np.array([-0.5, -0.5])
    b = 0.7
    return 0 if (np.sum(w*x) + b <= 0) else 1
```

`OR`:

```python
def OR(x1, x2):
	x = np.array([x1, x2])
    w = np.array([0.5, 0.5])
    b = -0.2
    return 0 if (np.sum(w*x) + b <= 0) else 1
```

---

局限性：异或门无法实现 ---> 多层感知机

```python
def XOR(x1, x2):
    s1 = NAND(x1, x2)
    s2 = OR(x1, x2)
    y = AND(s1, s2)
    return y
```

