# Chap4-神经网络的学习

损失函数：描述神经网络性能的“恶劣程度”

均方误差：

$$E = \dfrac{1}{2}\sum\limits_{k}(y_k-t_k)^2$$

其中$t_k$是监督数据，$k$是数据的维度.

```python
y = [0.1, 0.05, 0.6, 0.0, 0.05, 0.1, 0.0, 0.1, 0.0, 0.0] # 认为是各种值的可能性
t = [0,0,1,0,0,0,0,0,0,0] # 实际值

def mean_squared_error(y, t):
    return 0.5 * np.sum((y-t) ** 2)
```

---

交叉熵;

$$E = -\sum\limits_k t_k \log y_k$$

```python
def cross_entropy_error(y, t):
    delta = 1e-7
    return -np.sum(t * np.log(y + delta))
```

加上delta是为了防止无定义的情况发生.