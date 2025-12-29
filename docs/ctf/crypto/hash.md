## [cryptohack](https://cryptohack.org/challenges/hashes/)

密码学意义上安全的hash function需要能抵御以下三种攻击：

1. Pre-image attacks (**原像攻击**)：对于给定的hash函数输出$x$，不可能找到原消息$m_0$使得$hash(m_0) = x$，即不可逆向还原.

2. Second pre-image resistance（**第二原像抗性**）：给定消息$m_1$，不可能找到$m_2$满足$hash(m_1) = hash(m_2)$.

3. Collision resistance (**抗碰撞性**): 不可能找到两个消息 $m_1, m_2$ 使得 $hash(m_1) = hash(m_2)$.

如果已知原像攻击，那么也已知第二原像攻击和碰撞攻击. 但是如果已知碰撞攻击，并不能一定能对哈希函数发起原像攻击.

事实上哈希函数不可能完全抵御这些攻击，就像对称和非对称密码的协议可以被暴力破解一样. 即使是完美的单向函数，由于输出长度固定，也存在无限多个输入可以产生任意选定的输出. 因此，加密哈希函数的目标是**设计出能够使上述问题在假设攻击者拥有足够计算能力的情况下"足够"难以解决**的算法.

### Probability

**Jack's Birthday Hash:**

11bits长度的密文hash输出，至少多少个secret能使collision的概率上升到$50\%$？

设$k$个secret，则有collision的概率是：

$$P(\text{collision}) = 1 - P(\text{no collision}) = 1 - (1-\dfrac1n)^k$$

所以：

```python
n = 1 << 11
P = 1
for k in range(1, n):
    P_c = 1 - pow((1 - 1/n), k)
    if P_c > 0.5:
        print(k)
        break
```

**Jack's Birthday Confusion:**

这是典型的生日问题. 我们不关心碰撞到哪一个特定的值，只要这组秘密中出现了collision即可.

$i$ 个秘密均不冲突的概率：第 1 个秘密可以选任何值；第 2 个秘密为了不撞，只能选剩下的 $n-1$ 个值；第 $i$ 个秘密只能选剩下的 $n-(i-1)$ 个值……

所以公式为：

$$P(\text{no collision}) = \frac{n}{n} \cdot \frac{n-1}{n} \cdot \frac{n-2}{n} \dots \frac{n-i+1}{n} = \frac{n!}{n^i(n-i)!}$$

至少存在一次碰撞的概率：

$$P(\text{collision}) = 1 - \frac{n!}{n^i(n-i)!}$$

```python
from math import factorial
n = 2048
for i in range(n):
	# Calculate the probability using the formula
	prob = 1 - factorial(n) / (factorial(n - i)*pow(n,i)) 
 	# factorial是阶乘的意思.
	# Check if the probability exceeds 0.75
	if prob > 0.75:
		print(i)
		break
```

### Collision

[题解1,2](https://cryptohack.org/challenges/collider/solutions/)

??? tips "题解2解释得比较清楚"

    > The scenario of this problem is about a document system, where we add documents. If we take a look at the code, then we will see that the flag is given to us only if we enter two different documents with the same hash, when there is a collision.

    > If we search about md5 collisions, we will find that there are a lot of articles and attacks and we can quickly find sets of different strings that produce the same hashes. One such set is the following:

    > `d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70` and `d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70`

    > So, when prompted we input the following JSONs: `{"document":"d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70"}` and `{"document":"d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70"}`

    > The first document is accepted in the document system, however the second one returns the following:

    > `{"error": "Document system crash, leaking flag: crypto{m0re_th4n_ju5t_p1g30nh0le_pr1nc1ple}"}`

??? tips "Writeup-1，来自题解1"

    ```python
    import socket 
    # Hashes from https://en.wikipedia.org/wiki/MD5#Collision_vulnerabilities
    msg1 = 'd131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70'
    msg2 = 'd131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70'

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('socket.cryptohack.org', 13389))
        print(s.recv(1024).decode())
        s.sendall(f'{{"document": "{msg1}"}}'.encode())
        print(s.recv(1024).decode())
        s.sendall(f'{{"document": "{msg2}"}}'.encode())
        print(s.recv(1024).decode()) 
    ```