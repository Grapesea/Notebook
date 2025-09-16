!!! tips

    资源：[buuctf中的RSA刷题 - 骁隆's Blog](https://www.onctf.com/posts/d38358f9.html)

    [『CTF』史上最全 RSA 题目总结 - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/web/287854.html)

    Dan Boneh. Twenty years of attacks on the RSA cryptosystem. *Notices of the American Mathematical Society (AMS)*, 46(2):203–213, 1999.

    工具：RsaCtfTools

以下摘自自己的crypto lab2 report：

根据[cryptohack](https://cryptohack.org/challenges/rsa/)的指导，按部就班学习一下RSA加密算法的过程：

!!! tips

    * RSA概念与定义：

        **约定记号：$x=y (\operatorname{mod} N)$表明$x$的满足情况之下最小且唯一性；$x\equiv y (\operatorname{mod} N)$表明$x$只要是使得等式成立的任意值即可.**

        首先引入模幂（Modular Exponentiation）的概念：

        这是一次取幂再取模操作之后的余数，Python中记作`pow(base, exponent, modulus)`，即$remainder = base^{exponent} (\operatorname{mod}modulus)$

        这个操作的正逆向难度不同，即从base, exponent, modulus推出remainder易，但知道了remainder在内的任意三个信息则较难推出剩余信息。

        模幂（Modular Exponentiation）和大素数分解（prime factorisation）叠加在一起就能制造出**陷门**（Trap Door, a function that is easy to compute in one direction, but hard to do in reverse unless you have the right information）

    <br/>

    * 公钥$(e,N)$的生成：
    
        我们考虑$N = p \times q$作为modulus，其中$p,q$都是素数；$e$是幂，所以公钥对就是$(N,e)$.
    
        常见的$e$值是65537，也就是`0x10001`.
    
        现在我们输入一条待加密信息$m$，用公钥经过模幂计算就可以得到加密文本.
    
        ```python
            p = 17
            q = 23
            e = 65537
            m = 12
            cipher = pow(m, e, p*q)
            print(cipher)
        ```
    
        私钥$(d,N)$（Private Key）:在数值上是满足$d \equiv e^{-1} (\operatorname{mod}\phi(N))$这一方程的**任一正整数解**.
    
        <br/>
    
    * 还原message：
    
        拥有了加密后的信息$c$，所有公钥和私钥信息，想要还原$message$，应该怎么做呢？
    
        首先注意到$e \times d \equiv 1 (\operatorname{mod} \phi (N))$，于是$\exists k \in Z, e \times d = 1 + k\phi(N)$
    
        由于$c = m^e (\operatorname{mod} \phi(N))$，所以$c^d \equiv (m^e)^d \equiv m^{ed} \equiv m^{1+k\phi(N)} \equiv m (\operatorname{mod} N)$，
    
        其中后半部分是由欧拉定理得到的：$(m,N) = 1 \Longrightarrow m^{\phi(N)} \equiv 1(\operatorname{mod}N) \Longrightarrow m^{k\phi(N)} \equiv 1(\operatorname{mod}N)$ 
    
        于是$m = c^d(\operatorname{mod} N)$，这就是我们希望的答案.
    
        <br/>
    
    * hash函数的引入：
    
        现在我们想要给别人传送信息$m$，又不希望被非目标人员解开.
    
        我们引入Hash函数$H(m)$（常用的有SHA256, MD5 etc.）
    
        首先用朋友的公钥$(N_0,e_0)$加密出$c$：$c = m^{e_0} (\operatorname{mod} N_0)$
    
        然后“签名”：对$H(m)$使用自己的私钥$(N_1,d_1)$加密出新信息$S$：$S = H(m)^{d_1} (\operatorname{mod} N_1)$
    
        此时对方如果想要解密，可以：$m = c^{d_0} (\operatorname{mod} N_0)$
    
    * 验证：
    
        使用自己的公钥$(N_1,e_1)$解密：如果$H'(m) = S^{e_1} (\operatorname{mod} N_1)$与$H(m)$相等，则验证通过.

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

### RSA Adventure(校巴-98)

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

 [RSA常见题型二（e与φ(n)不互素） - xiehou~ - 博客园](https://www.cnblogs.com/llh-just/p/19000659)

试了两次，$e,p,q$不变，只有$c$每次都变.

这个题就比较有意思了，一开始想水一水结果猛地发现$e$是6，所以上网查一下不互素的方法：

这里$gcd(e,p-1) \neq 1, gcd(e,q-1) \neq 1$，所以考虑有限域开方解密：

!!! tips

    有限域开方解密  

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

!!! tips

    相关消息攻击：如果加密的多条消息具有线性相关性，产生的攻击称为相关消息攻击.

    例子：假设$\begin{cases}m^e \equiv c_1 (\operatorname{mod} n) \\ (m+t)^e \equiv c_2 (\operatorname{mod} n)\end{cases}$，$t$已知，那么可以定义$(\operatorname{mod} N)$下的多项式$f_1 = x^e-c_1,f_2=(x+t)^e-c_2$.

    容易知道$m$是$f_1,f_2$的根，所以$f_1,f_2$由公因式$(x-m)$，因此求公因式就可以得到$gcd(f_1,f_2)=x-m\Longrightarrow \boxed{m}$.

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
    PRx.<x= PolynomialRing(Zmod(n))
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
