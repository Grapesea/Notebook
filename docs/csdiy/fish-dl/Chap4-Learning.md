# Chap4-神经网络的学习

## 损失函数与交叉熵

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

结果实例：

```python
>>> import numpy as np
>>> def cross_entropy_error(y, t):
...     delta = 1e-7
...     return -np.sum(t * np.log(y + delta))
...
>>> y = [0.1, 0.05, 0.6, 0.0, 0.05, 0.1, 0.0, 0.1, 0.0, 0.0]
>>> t = [0,0,1,0,0,0,0,0,0,0]
>>> cross_entropy_error(np.array(y), np.array(t))
0.510825457099338
>>> y = [0.1, 0.05, 0.1, 0.0, 0.05, 0.1, 0.0, 0.6, 0.0, 0.0]
>>> cross_entropy_error(np.array(y), np.array(t))
2.302584092994546
```

如果是所有训练数据的损失函数的总和，假设共$N$个向量，$t_{nk}$表示第$n$个向量的第$k$个元素，则：

$$E = \dfrac1N \sum\limits_{n}\sum\limits_{k}t_{nk}\log y_{nk}.$$

mini-batch学习：从训练集中随机选取小批量个数的数据作为近似数据，再开始学习.

```python
import sys, os
sys.path.append(os.pardir)
import numpy as np
from dataset.mnist import load_mnist
(x_train, t_train), (x_test, t_test) = load_mnist(normalize=True, one_hot_label=True)

print(x_train.shape)
print(t_train.shape)
```

随机抽取数据：

```python
train_size = x_train.shape[0]
batch_size = 10
batch_mask = np.random.choice(train_size, batch_size)
x_batch = x_train[batch_mask]
t_batch = t_train[batch_mask]
```

交叉熵计算：

```python
def cross_entropy_error(y, t):
	if y.ndim == 1:
 		t = t.reshape(1, t.size) # 要改size
 		y = y.reshape(1, y.size)
 	batch_size = y.shape[0]
 	return -np.sum(t * np.log(y + 1e-7)) / batch_size
```

这里`reshape`的原因是保持`y.shape[0]`语义仍然是`batch_size`而非类别数量.

```python
reshape 前：          reshape 后：
                      
[0.1, 0.05, 0.6]     [[0.1, 0.05, 0.6]]
shape = (3,)          shape = (1, 3)
shape[0] = 3 ❌       shape[0] = 1 ✅
          ↑                     ↑
        类别数               样本数
```

设定损失函数是因为，直接将识别精度作为指标会让参数在绝大多数地方的导数变为0，导致参数无法更新.

## 梯度法

通过不断地沿梯度方向前进，逐渐减小函数值的过程就是梯度法（gradient method）.

寻找最小值的梯度法：梯度下降

寻找最大值：梯度上升

更新方法：（其中$\eta$表示学习率，是预先设置好的超参数）

$$x_0 = x_0 - \eta \dfrac{\partial f}{\partial x_0}$$

$$x_1 = x_1 - \eta \dfrac{\partial f}{\partial x_1}$$

```python
def gradient(f, x):
    h = 1e-4
    grad = np.zeros_like(x) # 生成和x形状相同的数组
    for idx in range(x.size):
        tmp_val = x[idx]
        x[idx] = tmp_val + h
        fxh1 = f(x) # f(x+h)
        
        x[idx] = tmp_val - h
        fxh2 = f(x) # f(x-h)
        
        grad[idx] = (fxh1 - fxh2) / (2*h)
        x[idx] = tmp_val
    return grad

def gradient_descent(f, init_x, lr = 0.01, step_num = 100):
    x = init_x
    for i in range(step_num):
        grad = gradient(f, x)
        x -= lr * grad
    return x
```

随便选一个函数开始计算：

```python
>>> def function_2(x):
...     return x[0]**2 + x[1]**2
...
>>> init_x = np.array([-3.0, 4.0])
>>> gradient_descent(function_2, init_x = init_x, lr = 0.1, step_num = 100)
array([-6.11110793e-10,  8.14814391e-10])
```

`lr`太大或者太小都无法收敛得比较好，所以调参数是很重要的.

神经网络的偏导：

$$W = \begin{pmatrix} w_{11} & w_{12} & w_{13} \\ w_{21} & w_{22} & w_{23}\end{pmatrix} \Longrightarrow \dfrac{\partial L}{\partial W} = \begin{pmatrix} \frac{\partial L}{\partial w_{11}} & \frac{\partial L}{\partial w_{12}} & \frac{\partial L}{\partial w_{13}} \\ \frac{\partial L}{\partial w_{21}} & \frac{\partial L}{\partial w_{22}} & \frac{\partial L}{\partial w_{23}}\end{pmatrix}$$

代码实现：

```python
import sys, os
sys.path.append(os.pardir)
import numpy as np
from common.functions import softmax, cross_entropy_error
from common.gradient import numerical_gradient

class simpleNet:
    def __init__(self):
        self.W = np.random.randn(2,3)
        
    def predict(self, x):
        return np.dot(x, self.W)
    
    def loss(self, x, t):
        z = self.predict(x)
        y = softmax(z)
        loss = cross_entropy_error(y, t)
        return loss    
```



输出：

```bash
[[ 0.04951721  0.16745684 -0.21697405]
 [ 0.07427581  0.25118526 -0.32546107]]
```



---

两层Net：参见CS231N

