---
title: Crypto笔记
date: 2025-07-01
layout: post
categories: [CTF]
mermaid: true 
mathjax: true
---

> ##### TIP: 工具准备
>
> Resource List:
>
> [CTF Wiki-Crypto](https://ctf-wiki.org/crypto/introduction/)
>
> [ZJU校巴](https://zjusec.com/)
>
> [CryptoHack](https://cryptohack.org/)
>
> [NSSCTF](https://www.nssctf.cn/index)
>
> 课堂导论Slides：
> [Crypto基础 - 2025安全攻防实践](https://courses.zjusec.com/slides/crypto-lec1/#/)
>
> [Crypto专题1 - 2025安全攻防实践](https://courses.zjusec.com/slides/crypto-lec2/)
>
> [Crypto专题2 - 2025安全攻防实践](https://courses.zjusec.com/slides/crypto-lec3/)
>
> 工具类：
>
> [随波逐流信息安全网](http://1o1o.xyz/index.html)
>
> [Factordb](factordb.com)
>
> [CTF在线工具-在线UUencode编码\|UU编码\|UUencode解码\|UUencode编码原理\|UUencode编码算法](http://www.hiencode.com/uu.html)
>
> [CTF中那些迷惑人的”base64“_ctf base64](https://blog.csdn.net/q20010619/article/details/120770872)
>
> [Keyword Cipher: Free Online Monoalphabetic Substitution Tool \| Educational Cryptography](https://caesarcipher.org/ciphers/keyword)
>
> payload import开头：
>
> ```python
> import hashlib
> import itertools
> import string
> import re
> import gmpy2
> import math
> import requests  # 如果在WSL中需要删掉这行
> from pwn import *
> import numpy as np
> from math import isqrt, gcd
> from fractions import Fraction
> from Crypto.Util.number import long_to_bytes, bytes_to_long
> import sympy
> from Crypto.Cipher import AES
> # from sage.all import *
> ```
{: .block-tip }

## 环境准备

不知道为什么本地网络经常刷新，有时一下子不能连接上靶机.

* 如果WSL里面nc失效，报错为`name resolution failure`

  首先确认基本网络连接：

  ```bash
  ping 8.8.8.8
  ping google.com
  ```

  查看当前DNS设置：

  ```bash
  cat /etc/resolv.conf
  ```

  如果DNS服务器不正确或缺失，可以临时修改：

  ```bash
  sudo nano /etc/resolv.conf
  ```

  添加公共DNS服务器：

  ```bash
  nameserver 8.8.8.8
  nameserver 8.8.4.4
  nameserver 1.1.1.1
  ```

  刷新DNS缓存：

  ```bash
  sudo systemctl restart systemd-resolved
  # 或者
  sudo service networking restart
  ```

* 如果GitHub突然git clone不下来，显示`recv failure: connection was reset`

  修改`C:\Windows\System32\drivers\etc`路径下的hosts文件，添加：

  ```bash
  140.82.112.3 github.com
  140.82.112.3 api.github.com
  185.199.108.153 assets-cdn.github.com
  185.199.108.154 github.githubassets.com
  185.199.108.133 raw.githubusercontent.com
  185.199.108.133 gist.githubusercontent.com
  185.199.108.133 cloud.githubusercontent.com
  185.199.108.133 camo.githubusercontent.com
  185.199.108.133 avatars.githubusercontent.com
  185.199.108.133 avatars0.githubusercontent.com
  185.199.108.133 avatars1.githubusercontent.com
  185.199.108.133 avatars2.githubusercontent.com
  185.199.108.133 avatars3.githubusercontent.com
  185.199.108.133 user-images.githubusercontent.com
  ```

  感觉是watt toolkit干的好事，会给我设置一堆回环地址（笑

## RSA Review

> 资源：[buuctf中的RSA刷题 - 骁隆's Blog](https://www.onctf.com/posts/d38358f9.html)
>
> [『CTF』史上最全 RSA 题目总结 - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/web/287854.html)
>
> Dan Boneh. Twenty years of attacks on the RSA cryptosystem. *Notices of the American Mathematical Society (AMS)*, 46(2):203–213, 1999.
>
> 工具：RsaCtfTools
>

> 以下摘自自己的crypto lab2 report：

根据[cryptohack](https://cryptohack.org/challenges/rsa/)的指导，按部就班学习一下RSA加密算法的过程：

> ##### TIP: RSA加密基础
>
> * 概念与定义：
>
>    **约定记号：$x=y (\operatorname{mod} N)$表明$x$的满足情况之下最小且唯一性；$x\equiv y (\operatorname{mod} N)$表明$x$只要是使得等式成立的任意值即可.**
>
>    首先引入模幂（Modular Exponentiation）的概念：
>
>    这是一次取幂再取模操作之后的余数，Python中记作`pow(base, exponent, modulus)`，即$remainder = base^{exponent} (\operatorname{mod}modulus)$
>
>    这个操作的正逆向难度不同，即从base, exponent, modulus推出remainder易，但知道了remainder在内的任意三个信息则较难推出剩余信息。
>
>    模幂（Modular Exponentiation）和大素数分解（prime factorisation）叠加在一起就能制造出**陷门**（Trap Door, a function that is easy to compute in one direction, but hard to do in reverse unless you have the right information）
>
>   <br/>
>
> * 公钥$(e,N)$的生成：
>
>    我们考虑$N = p \times q$作为modulus，其中$p,q$都是素数；$e$是幂，所以公钥对就是$(N,e)$.
>
>    常见的$e$值是65537，也就是`0x10001`.
>
>    现在我们输入一条待加密信息$m$，用公钥经过模幂计算就可以得到加密文本.
>
>    ```python
>     p = 17
>     q = 23
>     e = 65537
>     m = 12
>     cipher = pow(m, e, p*q)
>     print(cipher)
>    ```
>
>    私钥$(d,N)$（Private Key）:在数值上是满足$d \equiv e^{-1} (\operatorname{mod}\phi(N))$这一方程的**任一正整数解**.
>
>   <br/>
>
> * 还原message：
>
>    拥有了加密后的信息$c$，所有公钥和私钥信息，想要还原$message$，应该怎么做呢？
>
>    首先注意到$e \times d \equiv 1 (\operatorname{mod} \phi (N))$，于是$\exists k \in Z, e \times d = 1 + k\phi(N)$
>
>    由于$c = m^e (\operatorname{mod} \phi(N))$，所以$c^d \equiv (m^e)^d \equiv m^{ed} \equiv m^{1+k\phi(N)} \equiv m (\operatorname{mod} N)$，
>
>    其中后半部分是由欧拉定理得到的：$(m,N) = 1 \Longrightarrow m^{\phi(N)} \equiv 1(\operatorname{mod}N) \Longrightarrow m^{k\phi(N)} \equiv 1(\operatorname{mod}N)$ 
>
>    于是$m = c^d(\operatorname{mod} N)$，这就是我们希望的答案.
>
>   <br/>
>
> * hash函数的引入：
>
>    现在我们想要给别人传送信息$m$，又不希望被非目标人员解开.
>
>    我们引入Hash函数$H(m)$（常用的有SHA256, MD5 etc.）
>
>    首先用朋友的公钥$(N_0,e_0)$加密出$c$：$c = m^{e_0} (\operatorname{mod} N_0)$
>
>    然后“签名”：对$H(m)$使用自己的私钥$(N_1,d_1)$加密出新信息$S$：$S = H(m)^{d_1} (\operatorname{mod} N_1)$
>
>    此时对方如果想要解密，可以：$m = c^{d_0} (\operatorname{mod} N_0)$
>
> * 验证：
>
>    使用自己的公钥$(N_1,e_1)$解密：如果$H'(m) = S^{e_1} (\operatorname{mod} N_1)$与$H(m)$相等，则验证通过.
>
{: .block-tip }

### 低指数攻击(校巴-5)

```bash
Hint: Textbook RSA，信息没有任何 padding！

密文
c=431396049519259356426983102577521801906916650819409770125821662319298730692378063287943809162107163618549043548748362517694341497565980142708852098826686158246523270988062866178454564393347346790109724455155942667492571325721344535616869

模数
n=0x6270470b5e45bb464233683c38eeb03d17d54e0127038c9d286b00ac54946cfa1aa05c33610ec439c449b31f705c9e470ab6443cd090f9d88fab68f016c41bc00b9a1def40e77d836252ff03db2a525742e49b824d375216370d1cd810a60e2eac1824f306205c144b54c5f010ae17c8c88e76d1b41f13313cbd7e1b37822a0d

公钥
e=3

明文
m=flag的每个字节按16进制拼起来的大数
```

非常简单的低指数攻击，只要暴力枚举再开根号就行. payload如下：

```python
# https://zjusec.com/challenges/5

import gmpy2
from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes

c=431396049519259356426983102577521801906916650819409770125821662319298730692378063287943809162107163618549043548748362517694341497565980142708852098826686158246523270988062866178454564393347346790109724455155942667492571325721344535616869
n=0x6270470b5e45bb464233683c38eeb03d17d54e0127038c9d286b00ac54946cfa1aa05c33610ec439c449b31f705c9e470ab6443cd090f9d88fab68f016c41bc00b9a1def40e77d836252ff03db2a525742e49b824d375216370d1cd810a60e2eac1824f306205c144b54c5f010ae17c8c88e76d1b41f13313cbd7e1b37822a0d

def calc(c,n):
    for i in range(1000000):
        a, b = gmpy2.iroot(c + i * n, 3)
        if b == 1:
            m = a
            return long_to_bytes(m)

print(calc(c,n))
```

### Another RSA(校巴-12)

```bash
Modulus n =
0x009d70ebf2737cb43a7e0ef17b6ce467ab9a116efedbecf1ead94c83e5a082811009100708d690c43c3297b787426b926568a109894f1c48257fc826321177058418e595d16aed5b358d61069150cea832cc7f2df884548f92801606dd3357c39a7ddc868ca8fa7d64d6b64a7395a3247c069112698a365a77761db6b97a2a03a5

Public Exponent e = 65537

Ciphertext c =
0x004252980300fe636e910c79458b55eb7e94cce920895ab1681b93b843021260bb274d78f48d1ed0e31c430c2798837db12885b70a4b841881bf3d86be357cc975114b584ebf3128a3eca4e160a22d2fe8a566577fede45a57d2f488120984410615e1de06c869450848e95e3d72b83f44404f9449b287c2c8bb707a4122c6e4ba

There is a 'Key Generation Service' running at 10.214.160.13 port 25286
Maybe one can make use of it?
```

首先nc目标ip，然后分别输入$d = 3,5,7$，将获得的$e_1,e_2,e_3$列出来，凑一下$\phi(N)$的结果.

```python
import hashlib
import itertools
import string
import re
import gmpy2
import math
import requests 
from pwn import *
import numpy as np
from math import isqrt, gcd
from fractions import Fraction
from Crypto.Util.number import bytes_to_long, long_to_bytes

n = 0x9d70ebf2737cb43a7e0ef17b6ce467ab9a116efedbecf1ead94c83e5a082811009100708d690c43c3297b787426b926568a109894f1c48257fc826321177058418e595d16aed5b358d61069150cea832cc7f2df884548f92801606dd3357c39a7ddc868ca8fa7d64d6b64a7395a3247c069112698a365a77761db6b97a2a03a5
e = 65537
c = 0x004252980300fe636e910c79458b55eb7e94cce920895ab1681b93b843021260bb274d78f48d1ed0e31c430c2798837db12885b70a4b841881bf3d86be357cc975114b584ebf3128a3eca4e160a22d2fe8a566577fede45a57d2f488120984410615e1de06c869450848e95e3d72b83f44404f9449b287c2c8bb707a4122c6e4ba

d1 = 3
d2 = 5
d3 = 7
e1 = 0x68f5f2a1a25322d1a95f4ba79ded9a7266b649ff3d48a1473b8857ee6b01ab60060aaf5b39b5d82821ba7a5a2c47b6ee45c0b10634bd856e55301976b64f5901af936a824aff344351a0947a63fa07f8017930fe407cad6cdfba1896efbee03f78c73aff12b38f5ae9171158bcf2e4cb35d310744661c3fae101c3f7b7d133f3
e2 = 0x7df3eff52930902ecb3f2795f0b6b95614dabf32498a5b224770698480686740074005a0aba703635bac92d29b8941eaba1a6e07727d06846639b8280df8d13539174c9c59ff0b83fb8d7ef944c5a3299b5e3acab3c8d01c3fac1d81ec7ea6b290ef13987cd778d37e1bae6a7c56ac270d63ad5854755193746884c2dc94a4bd
e3 = 0x59f76241669066fcda51ae8fabf03b3d7c9c3f6d0ff51c86330726cc5bb849c0052dbae07a9bddd9417b444d4a869ccc3bc9bc4e76594dcc4904a81c9c440326043536b8d2919a82d8407f4455b1bdb001434e90c98f70142d7af0815fc82ded42f3e96ceb75564dec5cea4c0fab9f899bd97bd160e615b277b85ed4546a2c87

result = gcd(gcd(d1*e1-1, d2*e2-1),d3*e3-1) // 2 # 凑出来的

print(result)
print(n)
print()
assert(result < n)

n0 = n - result + 1

p = (n0 + isqrt(n0*n0 - 4*n)) // 2
q = (n0 - isqrt(n0*n0 - 4*n)) // 2

print(p)
print(q)

d = gmpy2.invert(e, (p-1)*(q-1))
m = pow(c, d, n)
print(long_to_bytes(m))
```

凑了一下结果是需要//2的，于是得到了$\phi(N)$，顺便解出flag：`b'AAA{koharu_dafa_is_good_qq_qun_386796080}`

### RSA_Adventure(校巴-98)

PoW之后：

```bash
Hint:
To get the flag, you need to solve a series of challenges, good luck!
And please encode your input answers with HEX (remove '0x').

[$] challenge 1
[+] e = 0x3
[+] n1 = 0x6e391e3924dba84d28ef7ee0b49a5ea9991591fbf3cce913ef4b4111cb3313f22b5f3d05433706617b4819ae205b21d586805628be9348dd27129a01eb91b2ff2d5134b96861789843f429d927bf24b020519c9937177a032d4a3c83686054de85a60a420ce8c9500a9706377f29b204032966e5fc17e7a2110642329e85d373
[+] c1 = 0x19c0a2fe455cebda05a129ce4511edaa5f39126aa08608418df2d98ec200fbde6fedba08a0a39e831f4f968bdcfc7cc9b129fc88e5c1cd90072e8c2873b79dbaf49e9cfea329d1d099f4451ada837344775fac8bc0becf46915a908c7c12bfdd1086b5e1e5170c4428a53324375169bba0d254d218111750510b78edae7b57ba
[+] n2 = 0xdcddcd297c792915ea16fcee4830ca2b25671656816b2beaf459799bf7b4f8433a037519ef3c76610b391eb7ba29d46aaea0e592cb775abd866dcaa15892622640cb8b5ec610854022099374ec90b07a4d1c49e5c413935d812fe580ee1e91c2a0c93ed745f556beebdad54760b917e9ebe1a46a532daeb4aa293ea241bf8aa5
[+] c2 = 0x3ff911a7c233dd8b7f6edd8e860c58084460ea14c9e5636824ad024dac8b239103d96e5077ffa732caeb06140da5a1db87a60cd30d32c7ae92bf66dc44e58813bd61067ed7d264abd24e9ccc7556b43bf1096006343ba3b055a73e7ab910a983720320876847b8e7b85af7577eecf0bf48dbd268a9fcd691b951aaeb97489cd7
[+] n3 = 0x8693c6a7c927b35e96a73cef38e9954d0094efbc5e5a94dcb2cb571f9e79341d6f80866917250966362fc1b63c55d23c87effa68120479286964773ec2005f25e1a0db6a4d13c9e3fd33c820ee14c1b5667033326f4537beb11fdb85ec590739b71a10129c918f5c66d637584156327d34bfbb1433f2a23d61b1b38134caf4bf
[+] c3 = 0x3d6b5bb390fd7bb3711a8ce988923d6aeaecb8dee37423e56b414540a3ee3d8a0de7315ec1ff9a3fc77234bb9efdd02cb54dcd8dcab73bd1405985cbbc79cac7d436a5f0067bd6fdf83adc7ef219ff4a3ae0159aedfb87f2357e30dd978fb13cb17a4b0b69fb37b21d8dad80426c6b830dc47489a70407003eb0fab99b3e064b
[+] assert ci == pow(m, e, ni)
[+] your job: guess m
[-] m =
```

这是低指数攻击，CRT即可.

第二关：

```bash
[$] challenge 2
[+] m = getrandbits(510)
[+] e = 0x6
[+] p = 0x93583c8f314318f1887e4533d5f1662fad416584cf6c777c4b441af66615c198296a69c5d8943b47762a08eef859cc5264a972621f09e424357e9f7631647903
[+] q = 0xdd4e2477b3b7446e10e91441422dad64bd9a623fefa64c4a21afe05e4d116c98e7731b40a9e8199821008c9c73042609476320d70f67d2c8069c7e9c9fd84561
[+] c = 0x95c3a23b202808e3653be27692027cac0cd53f4b2d71cef8f9e212c78c5e713fa3c306462ce349ee79f510454fb3f57e20c6367c98f979eacc7c37abe8154814ac100c50113dabd10d2093b5e1a57ff0180db8c6dfd78b41b7c436c1f68347acb9c2a2a2561e86a4ed560aeca666fb7073fbabe56a089575dfbf95739a0c041
[+] assert c == pow(m, e, p*q)
[+] your job: guess m
[-] m =
```

>  [RSA常见题型二（e与φ(n)不互素） - xiehou~ - 博客园](https://www.cnblogs.com/llh-just/p/19000659)

试了两次，$e,p,q$不变，只有$c$每次都变.

这个题就比较有意思了，一开始想水一水结果猛地发现$e$是6，所以上网查一下不互素的方法：

这里$$gcd(e,p-1) \neq 1, gcd(e,q-1) \neq 1$$，所以考虑有限域开方解密：

> ##### TIP: 有限域开方解密
>
{: .block-tip }

payload:

```python
n = p*q
if len(hex_numbers) >= 2:
    c = int(hex_numbers[3].replace('0x', ''), 16)
    print(f"\033[91mGet c: {c}\033[0m")

# print(gmpy2.gcd(e,p-1), gmpy2.gcd(e,q-1))  2,2
d_ = gmpy2.invert(3,(p-1)*(q-1))
res = pow(c,d_,n)
m = gmpy2.iroot(res,2)[0]
print(m)

conn.sendline(hex(m)[2:])
```



第三关：

```bash
[DEBUG] Received 0xec bytes:
    b'Good!\n'
    b'[$] challenge 3\n'
    b'[+] e = 0x3\n'
    b'[+] n = 0x4a471ffda8b4d8d223f6b64884b798a8a8356e6d024f92c46a9171c8841b\n'
    b'[+] c = 0x243f8c3665c4d0bf633fcfbe1a215c2b454f76498780fac9337c9f043ebe\n'
    b'[+] assert c == pow(m, e, n)\n'
    b'[+] your job: guess m\n'
    b'[-] m = \n'
```

水，yafu分解一下就行了.

```python
n = 0x4a471ffda8b4d8d223f6b64884b798a8a8356e6d024f92c46a9171c8841b
e = 3
p = 800336709776908303691579 # pow = 1
q = 800336709776908303690799 # pow = 2
phi = (p-1)*(q-1)*q
d = gmpy2.invert(e,phi)
m = pow(c,d,n)
```



第四关：

```python
Good!
[$] challenge 4
[+] e = 0x10001
[+] n = 0x81a8a5d31d394cf22be1279821b393cf40fc50bfee4720c5a37d4adcca081733d4386a528d156db3c8e9a464c1d16057e656af4fd9b23ec162b2732758646f62c7349ddf384d415b177e7e4f9177d381da8ba389ea19c86baad6d4e18095cdb8221117260d7bb790bc8b5a8902022dc4f4614be72709d382be0f185ed474805b
[+] dp = 0x46b50ee343445e826f0405f22a61902efeed47dd29e69b351ccb0e7d6377981c29dc6277a98934375f50de7309299fe92772110f855ee0d3af948185ee473c17
[+] c = 0x43f1fb184075e53ec3de6260c6cf7ccb0c0642e7fe5c4776117614625bc52f840b515c14430cf76b4cef9f2b122649058b1f9e21c72f8a11404b00b9b8cae8882aff7ccc5ec42c128da96386f70c0e2302ffe819d69bfdb530ad3b1fd17099e82e07a5804ee859d16bdfcd2b088a4e8d777ac3822db50057e31ba35aae338200
[+] assert dp == d%(p-1)
[+] assert c == pow(m, e, n)
[+] your job: guess m
[-] m =
```

$n,e,d_p$都不变，只有$c$在变化.

做一下数学运算：

$$\begin{cases} de = 1 + k(p-1)(q-1) \\ d = d_p + k_1(p-1) \end{cases} \Longrightarrow de = 1 + k(p-1)(q-1) = ed_p+ek_1(p-1) $$

$$\Longrightarrow ed_p\equiv 1 (\operatorname{mod}p-1)$$

接下来对$ed_p-1$进行质因数分解. 使用yafu：

```bash
***factors found***

P1 = 2
P1 = 3
P2 = 89
P3 = 389
P3 = 563
P4 = 1429
P18 = 169968591513043511
P25 = 3667981971308739542102537
P26 = 15755982260070350867116411
P81 = 147841219862878791677613767939084109134052890161976374292828659446291852336876599

ans = 1
```

接下来暴力枚举来计算$p,q$：

```python
n = 0x81a8a5d31d394cf22be1279821b393cf40fc50bfee4720c5a37d4adcca081733d4386a528d156db3c8e9a464c1d16057e656af4fd9b23ec162b2732758646f62c7349ddf384d415b177e7e4f9177d381da8ba389ea19c86baad6d4e18095cdb8221117260d7bb790bc8b5a8902022dc4f4614be72709d382be0f185ed474805b
# print(int(n))

e = 65537
dp = 0x46b50ee343445e826f0405f22a61902efeed47dd29e69b351ccb0e7d6377981c29dc6277a98934375f50de7309299fe92772110f855ee0d3af948185ee473c17
# assert dp == d%(p-1)
# assert c == pow(m, e, n)
# print(e*dp-1)

li = [2,3,89,389,563,1429,169968591513043511,3667981971308739542102537,15755982260070350867116411,147841219862878791677613767939084109134052890161976374292828659446291852336876599]

for k in range(1024):
    p = 1
    cnt = 0
    k_ = k
    while (k_ != 0):
        if (k_ % 2 == 1):
            p *= li[cnt]    
        cnt += 1
        k_ = k_ // 2
    if (n % (p+1) == 0):
        print(p+1)
        print(n//(p+1))
```

得到：

```python
p = 7010173429825364096483198373148695080777600230634223905598006877008362970389922446515938798609891083009103950216075939132993276370895055486168201663192527
q = 12988193913131624476685175811562898160517888405838841061588955125010438953846498671738108261014900926212870350440269819634930731186959088388206550178956213
```

payload略

另一个做法：[RSA的dp泄露](https://blog.csdn.net/weixin_45859850/article/details/109559190)



第五关：

```bash
[DEBUG] Received 0x1a9 bytes:
    b'Good!\n'
    b'[$] challenge 5\n'
    b'[+] n = 0xb3eaacc65bf88213e2a641130ae0c382fb2682794e62385f9944f9ff7356bbe2b057226747f38e177cb758888297c7f843f95dda1f5831d2e8ce48256604d11b45fc9010cbd183ee646bf6c687792284bbf029b7abc9e53b87d66a9ef15dd982ac7fa73d99fdd6baaf512bd735b64e2fb2ca29d2bc2e250ae2f9322ece30424b\n'
    b"[+] 1. server's job: print hex(pow(m, k, n) * pow((m+k), k, n) % n) \\# k is your input (k>0)\n"
    b'[+] 2. your job: guess m\n'
    b'[-] your choice: \n'
```

我觉得我是比较愚钝的（哭），可以看出来相关消息攻击讲了之后印象也不深刻，忘完了.

> ##### TIP: 相关消息攻击
>
> 相关消息攻击：如果加密的多条消息具有线性相关性，产生的攻击称为相关消息攻击.
>
> 例子：假设$$\begin{cases}m^e \equiv c_1 (\operatorname{mod} n) \\ (m+t)^e \equiv c_2 (\operatorname{mod} n)\end{cases}$$，$t$已知，那么可以定义$(\operatorname{mod} N)$下的多项式$$f_1 = x^e-c_1,f_2=(x+t)^e-c_2$$.
>
> 容易知道$m$是$f_1,f_2$的根，所以$f_1,f_2$由公因式$(x-m)$，因此求公因式就可以得到$gcd(f_1,f_2)=x-m\Longrightarrow \boxed{m}$.
>
{: .block-tip }

这里试了一下赋值$k = 1,2$：

$$\begin{cases} m^2+m \equiv r_1 & (\operatorname{mod} n) \\ m^4 + 4m^3 + 4m^2 \equiv r_2 & (\operatorname{mod} n) \end{cases}$$

于是只需要将两个多项式求出(mod n)意义下的公因式即可，payload如下：

（这部分比较特殊，使用了子过程处理sagemath环境的运算，再传递回python代码中）

```python
print("\033[91m这是交互第5轮\033[0m")
data = conn.recvuntil(b'your choice: \n')
server_message = data.decode()
hex_numbers = re.findall(r'0x[0-9a-f]+', server_message)
print(server_message)
n = int(hex_numbers[0].replace('0x', ''), 16)
print(f"\033[91mGet n: {n}\033[0m")

conn.sendline(hex(1)[2:])
data = conn.recvuntil(b'your k(hex): \n')

# result = 0x---------- 
conn.sendline(hex(1)[2:])
data = conn.recvuntil(b'your choice: \n')
server_message = data.decode()
hex_numbers = re.findall(r'0x[0-9a-f]+', server_message)
print(server_message)
result1 = int(hex_numbers[0].replace('0x', ''), 16)
print(f"\033[91mGet result1: {result1}\033[0m")

conn.sendline(hex(1)[2:])
data = conn.recvuntil(b'your k(hex): \n')

conn.sendline(hex(2)[2:])
data = conn.recvuntil(b'your choice: \n')
server_message = data.decode()
hex_numbers = re.findall(r'0x[0-9a-f]+', server_message)
print(server_message)
result2 = int(hex_numbers[0].replace('0x', ''), 16)
print(f"\033[91mGet result2: {result2}\033[0m")

sage_code = f"""
import json
n = {n}
res1 = {result1}
res2 = {result2}
def related_message_attack(res1, res2, n):
    PRx.<x> = PolynomialRing(Zmod(n))
    g1 = x^2 + x - res1
    g2 = x^4 + 4*x^3 + 4*x^2 - res2

    def gcd(g1, g2):
        while g2:
            g1, g2 = g2, g1 % g2
        return g1.monic()

    return -gcd(g1, g2)[0]

ans = int(related_message_attack(res1, res2, n))
print("FINAL_RESULT:")
print(int(ans))
"""

sage_path = "/usr/bin/sage"
result = subprocess.run(
        [sage_path, '-c', sage_code],
        capture_output=True,
        text=True,
        timeout=30
    )
    
if result.returncode == 0:
        # 直接读取 SageMath 的输出（整数）
    lines = result.stdout.strip().split('\n')
    for line in lines:
        if line.startswith('FINAL_RESULT:'):
            continue
        try:
            m = int(line.strip())
            print(f"Found result: {m}")
            break
        except ValueError:
            continue
else:
    print(f"\033[91mFailed!!!!!!!!!!\033[0m")

```

最终：

```bash
Good!
Well done! Here is the flag: ACTF{e3ea2c418757d09a123753de5d865771}
```

<br/>

## DSA Review

> 摘自自己的crypto lab1 report


> ##### TIP: DSA签名算法的过程
>
> 密钥选取：
>
> 1. 首先指定素数$p,q$，其中$p$的长度是$L$，$q$的长度是$N<L$；
>
> 2. 现在我们用以下方法找到合适的$g$：
>
>    遍历$h = 2 \to p-2$的所有值，令$g = h^{\frac{p-1}{q}}\%p$且$g^k\equiv 1(\operatorname{mod} p)$的最小正整数解是$q$；
>
> 3. 再选一个私钥$0<x<q$，取满足以下条件的$0<y<p$：$y = g^x (\operatorname{mod}p)$；
>
>    这样就完成了公钥$p,q,g,y$和私钥$x$的选择。
>
> 签名过程：
>
> 1. 随机选择临时密钥$k(0<k<q)$（且不能重用，否则就会像这个题目一样被攻击）；
>
> 2. $$\begin{cases} r \equiv (g^k \% p) \% q & (\operatorname{mod}q) \\ s \equiv (H(m) + xr) k^{-1}\%q & (\operatorname{mod} q)\end{cases}$$
>
>    于是签名结果就是$(r,s)$
>
> 验证过程：
>
> 1. 计算辅助值，$w=s^{-1}(\operatorname{mod}q)$
>2. 计算辅助值，$u_1=H(m)w$ (mod $q$)
> 3. 计算辅助值，$u_2=rw$ (mod $q$)
> 4. 计算$v=(g^{u_{1}}y^{u_{2}}\operatorname{mod}p)$ (mod $q$)
> 5. 如果$v = r$，则校验成功。
> 
> {: .block-tip }

---

温习一下[DSA基础攻击题](https://zjusec.com/challenges/85)：

我的破解思路：

当$m_1 = m_2$时，有$H(m_1) = H(m_2)$，设为$H(m)$

两个签名变为：$$\begin{cases}s_1 \equiv k_1^{-1}(H(m) + xr_1) & (\operatorname{mod} q)\\
s_2 \equiv (k_1+1)^{-1}(H(m) + xr_2) & (\operatorname{mod} q)\end{cases}$$

化简得：$4(x(r_1 - r_2) + s_2)(s_1 - s_2)^{-1}s_1 \equiv H(m) + xr_1 (\operatorname{mod} q)$

解得 $x \equiv (H(m) - s_2s_1(s_1 - s_2)^{-1})[(r_1 - r_2)s_1(s_1 - s_2)^{-1} - r_1]^{-1} (\operatorname{mod} q)$

<br/>

[DSA Revenge](https://zjusec.com/challenges/118)：

类似上题DSA的$k$复用情况，我的破解思路：

当$m_1 = m_2$时，有$H(m_1) = H(m_2)$，设为$H(m)$

两个签名变为：$$\begin{cases}s_1 \equiv (k>>160)^{-1}(H(m) + xr_1) & (\operatorname{mod} q)\\
s_2 \equiv [(ak+b)\%c>>160]^{-1}(H(m) + xr_2) & (\operatorname{mod} q) \end{cases}$$

解得 $x \equiv ??? (\operatorname{mod} q)$

需要看论文



## Coppersmith方法(sagemath的使用)

> 摘自自己的crypto lab3 report

参考文档：[Dense univariate polynomials over \(\ZZ/n\ZZ\), implemented using NTL - Polynomials](https://doc.sagemath.org/html/en/reference/polynomial_rings/sage/rings/polynomial/polynomial_modn_dense_ntl.html#sage.rings.polynomial.polynomial_modn_dense_ntl.small_roots)

[Coppersmith算法解决RSA加密问题-先知社区](https://xz.aliyun.com/news/13209)

沉寂已久的Coppersmith出现了，我以为lab2就会用到的，然后想得过于复杂折磨死了自己，但现在还在做单变量Coppersmith的阅读理解.

> ##### TIP: Coppersmith方法的理论基础
>
> * Coppersmith引理：
>
>   对mod N下度数为$d$的首一多项式$f$，若$n$是$N$的因子，$n > N^{\beta}, 0 < \beta \leq 1$，则可以**在多项式时间内**求出mod N下$\vert x_0\vert < N^{\frac{\beta^2}{d}}$的根.
>
>   * $n = N: \vert x_0\vert < N^{\frac{1}{d}}$
>  * RSA中，$p \approx N^{0.5}$，所以可以求出$ \vert x_0\vert < N^{\frac{1}{4d}}$.
> 
> * 单变元的Coppersmith方法：
>
>   假设我们有定义在mod M下度数为$d$的整系数首一多项式$f(x) = x^d + \sum\limits_{i = 0}^{d-1} a_ix^i$，如果已知存在$x_0$是$F(x)$的根，即$F(x)\equiv 0 (\operatorname{mod} M)$且满足$\vert x_0\vert < M^{\frac{1}{d}}$，则求确切解$x_0$用到以下的Howgrave-Graham Lemma：
>
>   > 定义$X$是$\vert x_0\vert$取值的上界，将$F(x)$表示为行向量$b_F = (a_0,a_1x,\cdots, a_dx^d)$，只要找到$x$使得$\|b_F\|< \dfrac{M}{\sqrt{d+1}}$，则$x$就是所求的根（这一定理可以用Cauchy不等式+绝对值不等式证明）
>
> * Coppersmith Attack：
>
>   本质是通过LLL找到一个小系数的多项式来满足上述引理的条件：
>
>   考虑如下的$d-1$个多项式：$G_i(x) = Mx^i, 0\leq i < d$，由于每个$G_i$都满足$G_i(x_0) \equiv 0(\operatorname{mod} M)$，所以线性组合之后也能满足$F(x_0) \equiv 0 (\operatorname{mod} M)$，于是目标变成了找到使得$\|b_F\|\leq \dfrac{M}{\sqrt{d+1}}$的$F$.
>
>   构造格：$$L = \begin{bmatrix} M & 0 & \cdots & 0 & 0 \\ 0 & Mx & \cdots & 0 & 0 \\ \cdots & \cdots & \cdots & \cdots &\cdots \\ 0 & 0 & \cdots & Mx^{d-1} & 0 \\ a_0 & a_1x & \cdots & a_{d-1}x^{d-1} & a_dx^d \end{bmatrix}$$
>
>   使用LLL算法之后得到了结果$F'$满足$F'(x_0) \equiv 0 (\operatorname{mod} M)$且$b_{F}$较小. 但是这个范围只是初步的，与Coppersmith的界还有一定的距离.（后面的分析略，涉及到shift polynomial等操作）
>
> 应用上，**Sagemath的`small_root()`函数，是单变元方法的集成.**
{: .block-tip }

### 校巴137-Crush on Proust

Coppersmith下的RSA，但是题目描述很谜语人：

> Et en amour, il est plus facile de renoncer à un sentiment que de perdre une habitude.
> 在爱情中，放弃一种感情比改掉一个习惯更容易。

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



## PRNG问题（ Pseudo-Random Number Generator）

资源：https://en.wikipedia.org/wiki/Category:Pseudorandom_number_generators

### 校巴94-PRNG1







##  NSSCTF刷题

鹤城杯感觉看了一会全是工具题，没思路就直接翻题解然后get工具去了（：

### 453-[鹤城杯2021]easy_crypto

```
公正公正公正诚信文明公正民主公正法治法治诚信民主自由敬业公正友善公正平等平等法治民主平等平等和谐敬业自由诚信平等和谐平等公正法治法治平等平等爱国和谐公正平等敬业公正敬业自由敬业平等自由法治和谐平等文明自由诚信自由平等富强公正敬业平等民主公正诚信和谐公正文明公正爱国自由诚信自由平等文明公正诚信富强自由法治法治平等平等自由平等富强法治诚信和谐
```

附件是这么个东西，很莫名其妙，检索一下发现是“核心价值观编码”.

于是下载Utools和核心价值观插件，解码得到结果是`flag{IlUqU9O5guX6YiITsRNPiQmbhNRjGuTP}`

### 450-[鹤城杯2021]A-CRYPTO

题干就只有这一坨东西，提示标签是：base, ROT, 古典密码

```
4O595954494Q32515046324757595N534R52415653334357474R4N575955544R4O5N4Q46434S4O59474253464Q5N444R4Q51334557524O5N4S424944473542554O595N44534O324R49565746515532464O49345649564O464R4R494543504N35
```

查了一下发现了一个叫做ciphey的工具，于是在WSL上安装：

```bash
$ sudo apt update
$ sudo apt install python3 python3-pip
$ pip3 install ciphey
```

然后只需要：

```bash
$ ciphey "4O595954494Q32515046324757595N534R52415653334357474R4N575955544R4O5N4Q46434S4O59474253464Q5N444R4Q51334557524O5N4S424944473542554O595N44534O324R49565746515532464O49345649564O464R4R494543504N35"
```

即可获得：

<center><img src="../photos/csactf_prep/ciphey_0.png" alt="rr" style="zoom: 75%;" /></center>



### 420-[SWPUCTF 2021 新生赛]crypto8

我又学会了新的解码工具-随波逐流解码工具！虽然没有下载成功，但是找到了能实现类似功能的一个网站.

这道题是uuencode，直接丢进[CTF在线工具-在线UUencode编码\\UU编码\\UUencode解码\\UUencode编码原理\\UUencode编码算法](http://www.hiencode.com/uu.html)

得到：

```
NSSCTF{cheese_is_power}
```

### 608-[柏鹭杯 2021]试试大数据分解?

是一道RSA题





### 691-[BJDCTF 2020]base??

Base64加密的变种，只是替换表而已.

```python
'''
https://www.nssctf.cn/problem/691
dict:{0: 'J', 1: 'K', 2: 'L', 3: 'M', 4: 'N', 5: 'O', 6: 'x', 7: 'y', 8: 'U', 9: 'V', 10: 'z', 11: 'A', 12: 'B', 13: 'C', 14: 'D', 15: 'E', 16: 'F', 17: 'G', 18: 'H', 19: '7', 20: '8', 21: '9', 22: 'P', 23: 'Q', 24: 'I', 25: 'a', 26: 'b', 27: 'c', 28: 'd', 29: 'e', 30: 'f', 31: 'g', 32: 'h', 33: 'i', 34: 'j', 35: 'k', 36: 'l', 37: 'm', 38: 'W', 39: 'X', 40: 'Y', 41: 'Z', 42: '0', 43: '1', 44: '2', 45: '3', 46: '4', 47: '5', 48: '6', 49: 'R', 50: 'S', 51: 'T', 52: 'n', 53: 'o', 54: 'p', 55: 'q', 56: 'r', 57: 's', 58: 't', 59: 'u', 60: 'v', 61: 'w', 62: '+', 63: '/', 64: '='}
chipertext:
FlZNfnF6Qol6e9w17WwQQoGYBQCgIkGTa9w3IQKw
'''
import base64
import string

str = "FlZNfnF6Qol6e9w17WwQQoGYBQCgIkGTa9w3IQKw"
string1 = "JKLMNOxyUVzABCDEFGH789PQIabcdefghijklmWXYZ0123456RSTnopqrstuvw+/="
string2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="

print(base64.b64decode(str.translate(str.maketrans(string1, string2))).decode())
```

flag: `BJD{D0_Y0u_kNoW_Th1s_b4se_map}`



### 723-[安洵杯 2019]JustBase

```bash
VGhlIGdlb@xvZ#kgb@YgdGhlIEVhcnRoJ#Mgc#VyZmFjZSBpcyBkb@!pbmF)ZWQgYnkgdGhlIHBhcnRpY#VsYXIgcHJvcGVydGllcyBvZiB#YXRlci$gUHJlc@VudCBvbiBFYXJ)aCBpbiBzb@xpZCwgbGlxdWlkLCBhbmQgZ@FzZW(!cyBzdGF)ZXMsIHdhdGVyIGlzIGV$Y@VwdGlvbmFsbHkgcmVhY#RpdmUuIEl)IGRpc#NvbHZlcywgdHJhbnNwb#J)cywgYW%kIHByZWNpcGl)YXRlcyBtYW%%IGNoZW!pY@FsIGNvbXBvdW%kcyBhbmQgaXMgY@(uc#RhbnRseSBtb@RpZnlpbmcgdGhlIGZhY@Ugb@YgdGhlIEVhcnRoLiBFdmFwb#JhdGVkIGZyb@)gdGhlIG(jZWFucywgd@F)ZXIgdmFwb#IgZm(ybXMgY@xvdWRzLCBzb@!lIG(mIHdoaWNoIGFyZSB)cmFuc#BvcnRlZCBieSB#aW%kIG(@ZXIgdGhlIGNvbnRpbmVudHMuIENvbmRlbnNhdGlvbiBmcm(tIHRoZSBjbG(!ZHMgcHJvdmlkZXMgdGhlIGVzc@VudGlhbCBhZ@VudCBvZiBjb@%)aW%lbnRhbCBlcm(zaW(uOiByYWluLlRoZSByYXRlIGF)IHdoaWNoIGEgbW(sZWN!bGUgb@Ygd@F)ZXIgcGFzc@VzIHRob#VnaCB)aGUgY#ljbGUgaXMgbm()IHJhbmRvbQpBbmQgdGhlIGZsYWcgaXM^IENURnsyMi!RV)VSVFlVSU*tUExLSkhHRkRTLUFaWENWQk%NfQ==
```

脑洞小开的一道题（苦笑

观察键盘，把里面奇怪的符号换成键盘上对应的数字，然后再base64解码：

```
The geology of the Earth's surface is dominated by the particular properties of water. Present on Earth in solid, liquid, and gaseous states, water is exceptionally reactive. It dissolves, transports, and precipitates many chemical compounds and is constantly modifying the face of the Earth. Evaporated from the oceans, water vapor forms clouds, some of which are transported by wind over the continents. Condensation from the clouds provides the essential agent of continental erosion: rain.The rate at which a molecule of water passes though the cycle is not random
And the flag is: CTF{22-QWERTYUIO-PLKJHGFDS-AZXCVBNM}
```

### 3674-[GDOUCTF 2023]Magic of Encoding

人眼搜索删掉了重复信息，得到了:

```plaintext
UEsDBBQACAAIAAZUilYAAAAAAAAAACUAAAAVACAATWFnaWMgb2YgRW5jb2RpbmcudHh0VVQNAAdNkTNkTpEzZE2RM2R1eAsAAQT1AQAABBQAAABLy0lMr84wKDCOrzQojc/JzDZOiS/JSI33NUnPTI43L8pMzq7lAgBQSwcIjmX6WicAAAAlAAAAUEsBAhQDFAAIAAgABlSKVo5l+lonAAAAJQAAABUAIAAAAAAAAAAAAKSBAAAAAE1hZ2ljIG9mIEVuY29kaW5nLnR4dFVUDQAHTZEzZE6RM2RNkTNkdXgLAAEE9QEAAAQUAAAAUEsFBgAAAAABAAEAYwAAAIoAAAAAAA==
```

丢到cyberchef里面是这样的：

<center><img src="../photos/csactf_prep/magic_of_encoding.png" alt="rr" style="zoom: 50%;" /></center>



### 3971-

暴力破解的方法：

```bash
$ hashcat -a 3 -m 0 496603d6953a15846cd7cc476f146771 LitCTF{md5can?a?a3de?arypt213thoughcr?ash}
```



### 5197-[鹤城杯 2021]Crazy_Rsa_Tech

典型RSA和中国剩余定理的题.

重温一下这个点：

> ##### TIP: 中国剩余定理
>
> 考虑同余方程
> 
>$$\begin{cases} x \equiv c_1 & (\operatorname{mod} n_1) \\  x \equiv c_2 & (\operatorname{mod} n_2) \\ & \vdots \\ x \equiv c_k & (\operatorname{mod} n_k)\end{cases}$$
> 
>我们首先计算出$N = n_1 * n_2 *\cdots * n_k$，并得到列表
> 
>$$ N_i = N // n_i$$
> 
>再算出$N_i$模$n_i$的逆$inv_i$:
> 
>$$inv_i = N_i^{-1} (\operatorname{mod}n_i)$$
> 
>最后获得余数并对$N$取模，得到最终结果：
> 
>$$x = \sum\limits_{i=1}^r c_i* N_i*inv_i (\operatorname{mod} N)$$
> 
{: .block-tip }

payload:

```python
N_list = []
inv_list = []
N = 1

for n in n_list:
    N *= n

for n in n_list:
    N_list.append(N//n)

for i in range(9):
    inv_list.append(gmpy2.invert(N_list[i],n_list[i]))

res = 0
for i in range(9):
    res += (inv_list[i] * N_list[i] * c_list[i])

res = res%N
flag = gmpy2.iroot(res,9)[0]

print(long_to_bytes(flag))
```



### 6717-[BCACTF 2021]FNES_1

感觉挺有意思可惜没时间做了.下面是题干，还没来得及看.

```python
import random
import math
import time
import binascii
from Crypto.Cipher import ARC4
from Crypto.Hash import SHA


with open("flag.txt", "r") as f:
    flag = f.read().strip().encode("ascii")

with open("key.txt", "r") as f:
    key = int(f.read().strip())

target_query = "Open sesame... Flag please!"

print("""
Welcome to your Friendly Neighborhood Encryption Service (FNES)!
If you and a friend both run this service at the same time,
you should be able to send messages to each other!
Here are the steps:
1. Friends A and B connect to the server at the same time (you have about a five second margin)
2. Friend A encodes a message and sends it to Friend B
3. Friend B decodes the message, encodes their reply, and sends it to Friend A
4. Friend A decodes the reply, rinse and repeat
Make sure to not make any mistakes, though, or your keystreams might come out of sync...
PS: For security reasons, there are four characters you aren't allowed to encrypt. Sorry!
""", flush=True)

tempkey = SHA.new(int(key + int(time.time() / 10)).to_bytes(64, 'big')).digest()[0:16]
cipher = ARC4.new(tempkey)

while True:
    print("Would you like to encrypt (E), decrypt (D), or quit (Q)?", flush=True)
    l = input(">>> ").strip().upper()
    if (len(l) > 1):
        print("You inputted more than one character...", flush=True)
    elif (l == "Q"):
        print("We hope you enjoyed!", flush=True)
        exit()
    elif (l == "E"):
        print("What would you like to encrypt?", flush=True)
        I = input(">>> ").strip()
        if (set(I.lower()) & set("flg!")): # You're not allowed to encrypt any of the characters in "flg!"
            print("You're never getting my flag!", flush=True)
            exit()
        else:
            print("Here's your message:", flush=True)
            c = str(binascii.hexlify(cipher.encrypt(str.encode(I))))[2:-1]
            print(c, flush=True)
    elif (l == "D"):
        print("What was the message?", flush=True)
        I = input(">>> ").strip()
        m = str(cipher.decrypt(binascii.unhexlify(I)))[2:-1]
        if (m == target_query):
            print("Passphrase accepted. Here's your flag:", flush=True)
            print(str(flag)[2:-1], flush=True)
            exit()
        else:
            print("Here's the decoded message:", flush=True)
            print(m, flush=True)
```





### 6314-[强网杯 2024 final]shopping_game

```python
from secret import flag
from Crypto.Util.number import *
from gmpy2 import *
def next_prime(x):
    while not isPrime(x):
        x += 1
    return x

success = 0

for i in range(20):
    coins = 27
    space = 0
    p = getPrime(64)
    delta = getRandomNBitInteger(30)
    q = next_prime(p + delta)
    N = p*q
    print("Welcome to my supermarket\n")
    while coins > 0:
        choice = input('give me your choice\n')
        if choice == '1':
            space = int(input("What size of house would you like to purchase?\n"))
            assert 1 <= space <= 10
            ls = [0] * space
            coins -= space * 5
            print(f'{coins} coins left\n')
        elif choice == '2':
            op = input()
            assert op in ['+', '-', '*', '//', '%', 'root']
            a, b, c= input().split('.')
            try:
                if op == 'root':
                    exec(f'{a}=iroot({b},{c})[0]')
                else:
                    exec(f'{a}={b}{op}{c}')
            except:exit
            if op in '+-':
                coins -= 1
            elif op in '*//%':
                coins -= 3
            else:
                coins -= 5
            print(f'{coins} coins left\n')

        elif choice == '3':
            state = 0
            print("One coin to check\n")
            coins -= 1
            print("You must have decorated a beautiful house.\n")
            assert coins >= 0
            for i in ls:
                if i > 1 and i < N and N%i == 0:
                    success += 1
                    state = 1
                    print(f'wonderful!, still {coins} coins left\n')
                    break
            if state:
                break

if success == 20:
    print(f'Congratulations! Here is your flag:{flag}\n')
```

choice = 1时:  我需要开辟一个ls，空间大小space，从N的分解来看只能是space = 2.

为了让success能积累到20，首先需要让ls里面的所有值都是N的因子

……

[题解](https://www.nssctf.cn/note/set/9719)里面还有一个最为简单的方法（疑似是pwn题）：

```python
context.log_level = "debug"
conn = remote("node1.anna.nssctf.cn", 28499)
conn.recvuntil(b"Welcome to my supermarket\n")
conn.recvuntil(b'give me your choice\n')

conn.sendline(b"2")
conn.sendline(b"+")

conn.sendline(b"a.print(flag).1")
print(conn.recvline().strip().decode())
```



## 校巴杂题

摆了，试过了都不太会做（：

### 25-3DES

### 30-base64-encrypt

## Cryptohack

### Introduction

只有这个传递json有点记录的意义：

> Several of the challenges are dynamic and require you to talk to our challenge servers over the network. This allows you to perform man-in-the-middle attacks on people trying to communicate, or directly attack a vulnerable service. To keep things consistent, our interactive servers always send and receive JSON objects.
>
> Such network communication can be made easy in Python with the `pwntools` module. This is not part of the Python standard library, so needs to be installed with pip using the command line `pip install pwntools`.
>
> For this challenge, connect to `socket.cryptohack.org` on port `11112`. Send a JSON object with the key `buy` and value `flag`.
>
> The example script below contains the beginnings of a solution for you to modify, and you can reuse it for later challenges.
>
> `pwntools.py`:
>
> ```python
> #!/usr/bin/env python3
> from pwn import * # pip install pwntools
> import json
> 
> HOST = "socket.cryptohack.org"
> PORT = 11112
> 
> r = remote(HOST, PORT)
> 
> def json_recv():
>     line = r.readline()
>     return json.loads(line.decode())
> 
> def json_send(hsh):
>     request = json.dumps(hsh).encode()
>     r.sendline(request)
> 
> print(r.readline())
> print(r.readline())
> print(r.readline())
> print(r.readline())
> 
> request = {
>     "buy": "clothes"
> }
> json_send(request)
> 
> response = json_recv()
> 
> print(response)
> ```

只需要交互的时候写个`{"buy": "flag"}`就能得到flag.

<br/>

### General

#### You either know, XOR you don't

```
I've encrypted the flag with my secret key, you'll never be able to guess it.
Remember the flag format and how it might help you in this challenge!
0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104
```

丢到cyberchef里面，

<center><img src="../photos/csactf_prep/xor_cc0.png" alt="rr" style="zoom: 50%;" /></center>

可以看到myXORkey了，然后把这个放到左边的框里面就行了：

<center><img src="../photos/csactf_prep/xor_cc1.png" alt="rr" style="zoom: 50%;" /></center>

flag: `crypto{1f_y0u_Kn0w_En0uGH_y0u_Kn0w_1t_4ll}`



### modulo

* Quadratic Residues:

  We say that an integer *x* is a *Quadratic Residue* if there exists an a*a* such that $a^2\equiv x (\operatorname{mod}p)$. If there is no such solution, then the integer is a *Quadratic Non-Residue*.

  一般来说*Quadratic Residue*是成对出现的.

  运算法则：

  ```
  Quadratic Residue * Quadratic Residue = Quadratic Residue
  Quadratic Residue * Quadratic Non-residue = Quadratic Non-residue
  Quadratic Non-residue * Quadratic Non-residue = Quadratic Residue
  ```

  网站上给出了比较好的记忆方法：Replace "Quadratic Residue" with +1 and "Quadratic Non-residue" with −1, all three results are the same!

  <br/>

* Legendre Symbol:

  记$(a/p) \equiv a^{\frac{p-1}{2}} (\operatorname{mod} p)$，则可以根据以下分支情况判别$a$是否为quadratic residue.

  $$ (a/p) = \begin{cases} 1 & \text{如果}a\text{是mod p下的quadratic residue且}a\neq 0(\operatorname{mod} p) \\ -1 & \text{如果}a\text{是mod p下的quadratic non-residue}\\ 0 & a\equiv 0(\operatorname{mod} p) \end{cases}$$

  (1)如果$p = 4k+3$，那么在找到合适的$a$之后，可以这样计算出root：

  $root = \pm a^{\frac{p+1}{4}} (\operatorname{mod}p)$（由Fermat小定理易证）

  (2)如果$p = 4k+1$，那么直接使用Sagemath，不要犹豫！！！
  
* eg. [CryptoHack – Modular Arithmetic - Adrien's Signs](https://cryptohack.org/courses/modular/adrien/)

  ```python
  lis = # too long to display
  a = 288260533169915
  p = 1007621497415251
  plaintext = ''
  a_p = pow(a,(p-1)//2, p)
  print(a_p)   # 结果是1
  
  for m in lis:
      L = pow(m, (p-1)//2, p)
      if L == 1:
          plaintext += '1'
      else:
          assert L == p-1
          plaintext += '0'
  print(plaintext)
  flag = '' 
  for i in range(0, len(plaintext),8):
      flag += chr(int(plaintext[i:i+8],2))
  print(flag)
  ```

  这个题是Legendre的应用.

  

* [CryptoHack – Modular Arithmetic - Modular Binomials](https://cryptohack.org/courses/modular/bionomials/)

  化简：

  $$\begin{cases} c_1 \equiv (2p+3q)^{e_1} & (\operatorname{mod}N) \\ c_2 \equiv (5p+7q)^{e_2} & (\operatorname{mod}N) \end{cases} \Longrightarrow \begin{cases} c_1 \equiv (2p)^{e_1}+(3q)^{e_1} & (\operatorname{mod}N) \\ c_2 \equiv (5p)^{e_2}+(7q)^{e_2} & (\operatorname{mod}N) \end{cases} $$$$\Longrightarrow \begin{cases} c_1^{e_2}5^{e_1e_2} \equiv (10p)^{e_1e_2}+(15q)^{e_1e_2} & (\operatorname{mod}N) \\ c_2^{e_1}2^{e_1e_2} \equiv (10p)^{e_1e_2}+(14q)^{e_1e_2} & (\operatorname{mod}N) \end{cases}$$

  $$ \Longrightarrow d = (15^{e_1e_2}-14^{e_1e_2})q^{e_1e_2} \equiv 5^{e_1e_2}c_1^{e_2}-2^{e_1e_2}c_2 ^{e_1} (\operatorname{mod}N)$$

  所以只需要计算$gcd(d,N)$即可得到$q$.

  payload:
  {% raw %}
  
  ```python
  from math import gcd
  # 参数略
  d = pow(5,e1*e2,N)*pow(c1,e2,N)-pow(2,e1*e2,N)*pow(c2,e1,N)
  
  q = gcd(d,N)
  p = N//q
  print(f"crypto{{{p},{q}}}")
  ```
  {% endraw %}
  <br/>

### Public Key

* [CryptoHack – Public-Key Cryptography - Factoring](https://cryptohack.org/courses/public-key/rsa_factoring/) 

  直接factordb

* [CryptoHack – Public-Key Cryptography - Monoprime](https://cryptohack.org/courses/public-key/monoprime/)

  指出了一个问题：为什么RSA中$N$一定要是$p\times q$?如果$N$是一个大素数呢？

  这样的话，$\phi(N)$是非常好计算的，进而$d$也可以破解了.

### Symmetirc cryptography

- The mathematical term for a one-to-one correspondence:   $\textcolor{red}{Bijection}$.

* The best single-key attack against AES:   $\textcolor{red}{biclique}$



### RSA







## 重温lab1,2剩余章节

> [crypto lab 1: 消息加密和数字签名 - CTF101-Labs-2025](https://courses.zjusec.com/intro/crypto-lab1/#task-40)
>
> 这个lab之前我只完成了DSA部分（而且DSA_Revenge也做不出来)，学习一下剩余的知识点.

### 古典密码的拓展 (60%)

> 希尔密码是古典密码学与线性代数的结合，通过希尔密码的破解，也可以初步感受现代密码学的特点：以数学为基础的算法构建和破解。
>
> 本 Challenge 需要完成 ZJU School-Bus 上的[ HSC ](https://zjusec.com/challenges/168)一题，在实验报告中简单描述这道题的做法。
>
> 这里首先先让同学们学习一下 sagemath 的使用方法，对完成本题或者之后专题的学习有较大的帮助。
>
> - 对题目中的 MT 矩阵进行随机赋值，使其可逆，使用 sage 求出它的逆矩阵，分值 10 分
> - 随机设置 flag 生成 FT，计算 RT，再通过 RT 和 MT 求出 FT 的值，与原 FT 进行比对，分值 10 分
>
> 如果后续没有选择密码学专题的打算，上述复现可以使用[在线环境](https://sagecell.sagemath.org/)。
>
> HSC 题目分值 40 分，加上 sage 复现部分本 Challenge 共 60 分，同样，如果没法完整做出，也可以叙述自己的思路和解题过程，会根据完成情况给分。

资料：[Linear Algebra - Tutorial](https://doc.sagemath.org/html/en/tutorial/tour_linalg.html)

参考Writeup: [CTF/2023-2024暑短学期/Lab1-Crypto Report.md · BruceJqs](https://github.com/BruceJqs/MyNotebook/blob/main/docs/blog/CTF/2023-2024暑短学期/Lab1-Crypto Report.md)

题干：

```python
MT = matrix(Zmod(256), [[?, ?, ?], [?, ?, ?], [?, ?, ?]]) # ? means unknown number
assert MT.is_invertible()
flag = "AAA{?????????????????????????}" # ? means unknown printable char
FT = matrix(Zmod(256), 3, 10)
for i in range(3):
	for j in range(10):
		FT[i, j] = ord(flag[i + j * 3])
RT = MT * FT
result = b''
for i in range(10):
	for j in range(3):
		result += bytes([RT[j, i]])
print(result)
# b'\xfc\xf2\x1dE\xf7\xd8\xf7\x1e\xed\xccQ\x8b9:z\xb5\xc7\xca\xea\xcd\xb4b\xdd\xcb\xf2\x939\x0b\xec\xf2'
```

暴力破解跑不动睡不着觉啊睡不着觉，深夜起来问队友有没有当时基础周做这个的，结果得到了上面那个writeup.

于是看了一下代码，还真是只能暴力破，估计自己搓的代码问题很大于是学习一下：

```python
def check(matrix):
    for i in range(3):
        for j in range(10):
            if matrix[i,j] < 32 or matrix[i,j] > 126:
                return False
    return True
# 检查3×10矩阵中的所有元素是否都在ASCII可打印字符范围内(32-126)，这样解密后的结果可读

encoded = b'\xfc\xf2\x1dE\xf7\xd8\xf7\x1e\xed\xccQ\x8b9:z\xb5\xc7\xca\xea\xcd\xb4b\xdd\xcb\xf2\x939\x0b\xec\xf2'
encoded_iter = iter(encoded)

RT = matrix(Zmod(256), [[0 for i in range(10)] for j in range(3)])
i = 0

for element in encoded_iter:
    RT[i % 3, i // 3] = element
    i += 1
# 填充RT矩阵 ###############################################################
    
line1 = []
line2 = []
line3 = []

a1 = RT[0,0]
a2 = RT[1,0]
a3 = RT[2,0]
b1 = RT[0,1]
b2 = RT[1,1]
b3 = RT[2,1]
c1 = RT[0,9]
c2 = RT[1,9]
c3 = RT[2,9]

for i in range(256):
    for j in range(256):
        for k in range(256):
            if (a1 * i + a2 * j + a3 * k) % 256 == 65:
                if (32 <= (247 * i + 30 * j + 237 * k) % 256 <= 126 and 32 <= (204 * i+81 * j+139 * k) % 256 <= 126 and 32 <= (57 * i + 58 * j + 122 * k) % 256 <= 126):
                    if (b1 * i + b2 * j + b3 * k) % 256 == 123:
                        line1.append([i, j, k])
                    elif (c1 * i + c2 * j + c3 * k) % 256 == 125:
                        line3.append([i, j, k])
                    else:
                        line2.append([i, j, k])
print(line1)

########################## 极为暴力的纯破解方法 #########################

total = 0
MTN = matrix(Zmod(256), [[0,0,0],[0,0,0],[0,0,0]])
for i in line1:
    for j in line2:
        for k in line3:
            for l in range(3):
                MTN[0,l] = i[l]
                MTN[1,l] = j[l]
                MTN[2,l] = k[l]
            if MTN.is_invertible():
                FT_cal = MTN * RT
                if check(FT_cal):
                    total += 1
                    print("Case "+str(total)+":")
                    print(FT_cal)
                    print("\n")
```



### RSA 的密钥格式解析

> RSA 密钥的格式有很多种，常见的有 PEM、DER 等格式。PEM 格式的密钥是 Base64 编码的 DER 格式密钥，DER 格式的密钥是 ASN.1 编码的二进制格式。
>
> 你可能需要参考包括但不限于 [此博客](http://www.shangyang.me/2017/05/24/encrypt-rsa-keyformat/) 来了解 RSA 密钥的具体格式和结构。
>
> 本 Challenge 需要完成比赛平台上的 Leaked RSA Key 一题，在实验报告中描述这道题的做法。
>
> - 解析 DER 格式的 RSA 密钥，解释各个字段的含义，分值 30 分
> - 使用[ factordb ](https://factordb.com/)或者 yafu 等其他工具分解 RSA 模数解出明文，分值 10 分
> - ( 慎选 ) 解析不出意外的话，你会发现私钥只有前半部分。你可以尝试使用 RSA 已知私钥高位攻击来恢复后半部分，仅使用网络上的脚本只能获得 15 分，如果能够在报告中详细解释攻击过程和原理，可以获得 35 分。
>
> 如果没法完整做出，也可以叙述自己的思路和解题过程，会根据完成情况给分。


记录一下这个博客的知识点：

> ##### TIP: RSA的常用密钥格式
>
> 工具：
>
> * 解析ASN.1格式下的密钥构成：[ASN.1 Parser \| phpseclib](https://phpseclib.sourceforge.net/x509/asn1parse.php) 以及 [ASN.1结构解析器](https://www.ufreetools.com/zh/tool/asn1-structure-parser)
>
> 知识点：
>
> * DER (Distinguished Encoding Rules)格式
>
>   是密钥在ASN.1 format下二进制表述格式.
>
> * PEM (Privacy-Enhanced Mail)格式：是对DER的base64编码
>
>   Each object is delimited by lines similar to "`-----BEGIN ...-----`" and "`-----END ...-----`". Data that is *not* between such lines is ignored, and is sometimes used for comments, or for a human-readable dump of the encoded data.
>
> * PKCS #1
>
>   长这个样子：
>
>   ```ASN.1
>   -----BEGIN RSA PUBLIC KEY-----
>   BASE64 ENCODED DATA
>   -----END RSA PUBLIC KEY-----
>   ```
>
>   
>
{: .block-tip }

再看一下Leaked RSA Key这道题：

> 雨夜，卢浮宫地下的羊皮纸霉味与血腥气在档案库里缠绵，首席修复师艾琳·德·维特倒在文艺复兴的尘埃中，她的指尖凝固在键盘"RSA-PKCS#1"的凹痕上，烧焦的屏幕幽幽浮出半截密钥——
>
> ```
> -----BEGIN RSA PRIVATE KEY-----
> MIGrAgEAAiEAwmNq5cPY5D/7l6sJAo8arGwL9s09cOvKKBv/6X++MN0CAwEAAQIgGAZ5m9RM5kkSK3i0MGDHhvi3f7FZPghC2gY...
> ```
>
> 如同被撕碎的魔法契约，那些省略号里沉睡着达芬奇《机械天使的密语》手稿的终极秘密。她染血的掌心紧攥的便签上，十六进制密文`1c194cd4f48d77b2e14cace43869bea17615ab23da0ef63b7bf56116ad3ac93b`像一串冰冷的诅咒，这是凶手盗取末日兵器蓝图时被监控拍下的罪证视频，却被封存在RSA的数学牢笼中。
>
> 我在现场拾起她未写完的笔记："他们以为密钥只是数字...却不知PKCS#1的ASN.1结构是唤醒机械天使的祷文..."，血渍晕染了后半句。此刻，残缺的PEM文件在证物台上泛着冷光，头部清晰的模数n与指数e是达芬奇留下的密码锁齿，而消逝在省略号中的素数p和q，正是凶手刻意抹去的钥匙齿痕。十六进制密文在投影仪上投出诡谲的波纹，仿佛五百年前的机械齿轮在黑暗中重新啮合——只有让破碎的DER编码重生，让PKCS#1的骨架从PEM残片中完整站起，才能听见素数的低语破译密文，让视频里的凶手在蓝光中显形，让吞噬光的机械在《启示录》坐标前停止心跳...
>
> 雨点敲打彩绘玻璃，像倒计时的秒针。卢浮宫穹顶的鸽群突然惊飞，散落的羽毛在密钥片段旁排成一行隐形的警告：当模数在标准格式中复活时，真相将刺穿所有阴影。

题干提到了PKCS#1的ASN.1结构，需要还原“破碎的DER编码”.

对于RSA私钥，其ASN.1结构如下：

```
RSAPrivateKey ::= SEQUENCE {
    version           Version,
    modulus           INTEGER,  -- n
    publicExponent    INTEGER,  -- e
    privateExponent   INTEGER,  -- d
    prime1            INTEGER,  -- p
    prime2            INTEGER,  -- q
    exponent1         INTEGER,  -- d mod (p-1)
    exponent2         INTEGER,  -- d mod (q-1)
    coefficient       INTEGER,  -- (inverse of q) mod p
}
```

（现在知道之前赶出来的报告里面对这部分的理解有多荒谬了）

使用ufreetools解出来$e= 65537$，$n$的值通过拼接ufreetools给出的hex然后转成10进制得出，为87924348264132406875276140514499937145050893665602592992418171647042491658461

使用yafu分解之后得到：

```
p = 275127860351348928173285174381581152299
q = 319576316814478949870590164193048041239
```

于是很自然地得到了flag：`AAA{N3veR_Le4k_PR1va7eK3y_Ag41N}`



### 随机数的预测 (50%+15%)

> 随机数在密码学中起着重要的作用，尤其是在密钥生成和加密算法中。
>
> 在课上我们主要介绍了随机数的生成和预测方法，以及相关的攻击方式，你可以尝试实现一些简单的随机数预测攻击。
>
> 本 Challenge 需要完成 ZJU School-Bus 上的[ PRNG Study1 ](https://zjusec.com/challenges/94)一题，在实验报告中简单描述这道题的做法。完成本题可以获得 50 分。
>
> - 如果想要获得额外的 15 分奖励，你可以再选择任意一种语言的随机数生成器进行分析并阐述攻击的思路。
>
> 如果没法完整做出，也可以叙述自己的思路和解题过程，会根据完成情况给分。





### （慎选）哈希函数的扩展攻击 (60%)

> 哈希函数是现代密码学中重要的组成部分，广泛应用于数字签名、消息认证等场景。在课上我们介绍了哈希函数的基本原理和常见的攻击方式。
>
> 本 Challenge 需要完成 ZJU School-Bus 上的[ treasurebank ](https://zjusec.com/challenges/32)一题，在实验报告中简单描述这道题的做法。
>
> - 你可能需要注意 mdx 并非 md5，以及本题目需要 python2 环境。
>
> 如果没法完整做出，也可以叙述自己的思路和解题过程，会根据完成情况给分。



### EZDLP

> ##### TIP: DLP(离散对数问题)
>
> DLP（离散对数问题）：给定 $g^x \equiv y (\operatorname{mod} p)$ 中的 $g,y,p$，其中 $p$为大素数，求解 $x$.
>
> * 这是一个困难问题，目前无法多项式复杂度时间内解决（NP）.
>
> Diffie-Hellman密钥交换协议：
>
> * 首先由参与方A,B公开参数$g,p$，并分别随机生成$x_A,x_B$，
>
> * 接着分别计算各自的公钥：$y_A = g^{x_A} (\operatorname{mod} p), y_B = g^{x_B} (\operatorname{mod} q)$
>
> * 最后是确认：协商密钥为$y_B^{x_A} \equiv  y_A^{x_B} \equiv g^{x_Ax_B} (\operatorname{mod} p)$
>
> <br/>
>
> 攻击方法：
>
> * cado-nfs工具求解
> * 大步小步算法（BSGS算法）
> * Pohlig-Hellman算法
>
> BSGS算法：
>
> - 对于  $g^x \equiv y (\operatorname{mod} p), 0<x\leq m$ 的DLP 问题，可在$O(\sqrt{m})$的时间复杂度和$O(\sqrt{m})$的空间复杂度内求解
>
> * 流程：
>
>   1. 设$$x = \sqrt{m}x_0+x_1(0\leq x_0,x_1\leq \sqrt{m}) \Longrightarrow g^{\sqrt{m}x_0+x_1} \equiv y (\operatorname{mod} p)$$
>
>      $$\Longrightarrow g^{\sqrt{m}x_0} \equiv yg^{-x_1} (\operatorname{mod} p)$$
>
>   2. 两边分别去计算并存储所有$x_0,x_1$代入后的值并进行比较，如果有一项对应相等就破解出了$x_0,x_1$，从而得出$x$.
>
> Pohlig-Hellman算法流程：（适用于$p-1$是光滑的情况，即$p-1 = \Pi^{k}_{i=1} p_i^{\alpha_i}$，其中的$p_i$都很小）
>
> 1. $$ p-1 = \Pi^{k}_{i=1} p_i^{\alpha_i} $$，并且对每个$p_i$，求出$x_i = x (\operatorname{mod} p_i^{\alpha_i})$；
>
> 2. 逐位恢复$x_i$，即计算$$x_i = \sum\limits_{k = 0}^{\alpha_i-1}x_{ik}p_i^{k}$$式子中的每项$x_{ik}$：
>
> 3. $g^{x_i} \equiv b (\operatorname{mod} p )\Longrightarrow g^{\frac{p-1}{p_i^t}\cdot x_i} \equiv b^{\frac{p-1}{p_i^t}}(\operatorname{mod} p )$，其中$0<t<\alpha_i$. 
>
>    记$A = g^{\frac{p-1}{p_i^t}}, B =  b^{\frac{p-1}{p_i^t}}$，则$A^{x_i}\equiv B(\operatorname{mod} p )$；
>
> 4. 由于对每个$t$，都有$A^{p_i^t}\equiv 1(\operatorname{mod} p ) \Longrightarrow A^{\sum\limits_{j=0}^{t-1}x_{ij}*p_i^j}\equiv B(\operatorname{mod} p )$，所以考虑从$t=1$开始到$\alpha_i$，通过先前计算出的每一个$x_{ij}$，带入得出$x_i (\operatorname{mod} p_i^{\alpha_i})$的值，用这些值构造CRT求解即可得到$x(\operatorname{mod} p-1)$的值.
>
{: .block-tip }


先看题目源码：

```python
from Crypto.Util.number import *
from Crypto.Cipher import AES
from hashlib import md5
from secret import flag

def pad(x, length):
    return x + (length - len(x) % length) * b'\x00'

p = 960494008017250155494739990397196249930200062145145133132556398221074529657304218221253517153928380265486339083177542201148993799925721673833333778621388110957986908045712612233794551809
x = getPrime(500)
g = 3
c = pow(g, x, p)

aes = AES.new(key = md5(str(x).encode()).digest(), mode = AES.MODE_ECB)
ct = aes.encrypt(pad(flag, 16))
print(f"c = {c}")
print(f"ct = {ct}")

'''
c = 505527904713564983625416248872210831215228354175257237841602581321675204643681129570897695080321118656513647239718859773976453054734892142640867733520305568808093022238369199760987416665
ct = b'qBS\x84\xfc"\xee$\xb2d\xba\xeb\x00\xf7\xf4\xa4\x91\x90<N\x1a\xb0\xa5>\xdc^\xe3I\xc3\xecc\x1e'
'''
```

因为`x = getPrime(500)`，所以不方便使用BSGS，时间复杂度过于高了.

$p-1 = 2^{518}*1119326809698249181662206673457$

用了yafu发现是个大素数，有点难办. 所以试一下Pohlig-Hellman攻击.

接下来手搓一下这个代码：

```python
p = # 略
n = p - 1
g = 3
h = #略
ct = b'qBS\x84\xfc"\xee$\xb2d\xba\xeb\x00\xf7\xf4\xa4\x91\x90<N\x1a\xb0\xa5>\xdc^\xe3I\xc3\xecc\x1e'

# 计算 x mod 2^518
x = 0  # 累计值
gamma = pow(g, n // 2, p)  # γ = g^(n/2) mod p，阶为2

for k in range(518):
    exponent = n // (2 ** (k + 1))  # 整数除法
    h_k = (h * pow(g, -x, p)) % p  # 调整 h
    temp = pow(h_k, exponent, p)
    if temp == 1:
        x_k = 0
    elif temp == gamma:
        x_k = 1
    else:
        print(f"Error at k={k}")
        x_k = 0
    x += x_k * (2 ** k)

print(f"x = {x}")
assert (pow(g,x,p) == h)

key = hashlib.md5(str(x).encode()).digest()
cipher = AES.new(key, AES.MODE_ECB)
decrypted = cipher.decrypt(ct) # 解密
flag = decrypted.rstrip(b'\x00')  # 去除填充的空字节

print(f"Flag: {flag.decode()}")
```

Flag: `AAA{W31c0m3_T0_CT4_lo1_c0urs3!}`

