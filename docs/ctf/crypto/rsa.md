???+ tips "资源与工具"

    [CTF101_2025-公钥密码学](https://courses.zjusec.com/slides/crypto-lec2)

    资源：[buuctf中的RSA刷题 - 骁隆's Blog](https://www.onctf.com/posts/d38358f9.html)

    [『CTF』史上最全 RSA 题目总结 - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/web/287854.html)

    Dan Boneh. Twenty years of attacks on the RSA cryptosystem. *Notices of the American Mathematical Society (AMS)*, 46(2):203–213, 1999. $\quad$[解读1](https://mzhang.io/posts/2018-10-26-twenty-years-of-rsa-attacks/) 
    $\quad$
    [解读2](https://harper-yuan.github.io/2022/10/29/RSA%E5%8A%A0%E5%AF%86%E7%B3%BB%E7%BB%9F%E7%9A%8420%E5%B9%B4/)

    工具：RsaCtfTools

## 数学基础

### [有限域的生成元](https://cryptohack.org/courses/public-key/dh-starter-2/)

**子群 $H = \langle g \rangle$**：

在有限域 $\mathbb{F}_p$（即模 $p$ 的整数集合）中，只考虑乘法，如果选一个数字 $g$，不断让它自乘：$g^1 \pmod p$$g^2 \pmod p$$g^3 \pmod p$...这些结果会形成一个循环，其结果构成的数字集合就叫做由 $g$ 生成的子群 $H$.

关于模数$p$求其本原元素$g$的代码：

```python
from sympy import primitive_root
p = 28151
g = primitive_root(p)
print(g)
```

### DLP问题

离散对数问题与Diffie-Hellman数据交换协议.

## RSA基础

以下摘自自己的crypto lab2 report：

根据[cryptohack](https://cryptohack.org/challenges/rsa/)的指导，按部就班学习一下RSA加密算法的过程：

???+ tips "RSA基础知识"

    * RSA概念与定义：

        **约定记号：$x=y \pmod  N$表明$x$的满足情况之下最小且唯一性；$x\equiv y \pmod  N$表明$x$只要是使得等式成立的任意值即可.**

        首先引入模幂（Modular Exponentiation）的概念：

        这是一次取幂再取模操作之后的余数，Python中记作`pow(base, exponent, modulus)`，即$remainder = base^{exponent} \pmod modulus$

        这个操作的正逆向难度不同，即从base, exponent, modulus推出remainder易，但知道了remainder在内的任意三个信息则较难推出剩余信息。

        模幂（Modular Exponentiation）和大素数分解（prime factorisation）叠加在一起就能制造出**陷门**（Trap Door, a function that is easy to compute in one direction, but hard to do in reverse unless you have the right information）

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
    
        私钥$(d,N)$（Private Key）:在数值上是满足$d \equiv e^{-1} \pmod \phi(N)$这一方程的**任一正整数解**.
    
    * 还原message：
    
        拥有了加密后的信息$c$，所有公钥和私钥信息，想要还原$message$，应该怎么做呢？
    
        首先注意到$e \times d \equiv 1 \pmod  \phi (N)$，于是$\exists k \in Z, e \times d = 1 + k\phi(N)$
    
        由于$c = m^e \pmod  \phi(N)$，所以$c^d \equiv (m^e)^d \equiv m^{ed} \equiv m^{1+k\phi(N)} \equiv m \pmod  N$，
    
        其中后半部分是由欧拉定理得到的：$(m,N) = 1 \Longrightarrow m^{\phi(N)} \equiv 1\pmod N \Longrightarrow m^{k\phi(N)} \equiv 1\pmod N$ 
    
        于是$m = c^d\pmod N$，这就是我们希望的答案.
    
    * hash函数的引入：
    
        现在我们想要给别人传送信息$m$，又不希望被非目标人员解开.
    
        我们引入Hash函数$H(m)$（常用的有SHA256, MD5 etc.）
    
        首先用朋友的公钥$(N_0,e_0)$加密出$c$：$c = m^{e_0} \pmod  N_0)$
    
        然后“签名”：对$H(m)$使用自己的私钥$(N_1,d_1)$加密出新信息$S$：$S = H(m)^{d_1} \pmod  N_1)$
    
        此时对方如果想要解密，可以：$m = c^{d_0} \pmod  N_0)$
    
    * 验证：
    
        使用自己的公钥$(N_1,e_1)$解密：如果$H'(m) = S^{e_1} \pmod  N_1)$与$H(m)$相等，则验证通过.

??? tips "PoW板子"

    ```python
    ''' 第一次交互的内容：
    sha256(XXXX + 'ikKO3b').hexdigest() = 75e803bd1d4b6fe22bc345d5625edcf98a717bb496988b8f5f964764c1be98f
    Give me XXXX (4 bytes, only contain letters or digits): 
    '''
    context.log_level = "debug"
    conn = remote("10.214.160.13", 12501)
    data = conn.recvuntil(b'Give me XXXX (4 bytes, only contain letters or digits):')
    server_message = data.decode()
    print(server_message)

    def string1(server_message):
        pattern = r"sha256\(XXXX\s*\+\s*'([0-9a-zA-Z]+)'\)\.hexdigest\(\)\s*==\s*([0-9a-f]+)"
        match = re.search(pattern, server_message, re.IGNORECASE)

        if match:
            r = match.group(1)
            s = match.group(2)
            return r, s
        return None, None

    r,s = string1(server_message)
    print("\033[91m这是交互第一轮\033[0m")
    print(f'Extracted: r:{r}, s:{s}')

    def getxxxx(r,s):
        charset = string.ascii_letters + string.digits
        cnt = 0
        for i in range(1,7):
            for cmb in itertools.product(charset, repeat=i):
                key = ''.join(cmb)
                cnt += 1
                if (cnt % 10000000 == 0):
                    print(cnt)
                if hashlib.sha256((key + r).encode()).hexdigest() == s:
                    print(f"Key found: {key} after {cnt} attempts")
                    return key
        return None

    result = getxxxx(r,s)
    print(f"找到的XXXX: {result}")
    conn.sendline(result)
    ```

## RSA分解攻击

### 直接分解


## RSA低公钥私钥指数攻击

### [校巴-5](https://zjusec.com/challenges/5)

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

??? tips "Writeup"

    ```python
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

### [modulus_inutilis](https://cryptohack.org/courses/public-key/modulus_inutilis/)

??? tips "Writeup"

    ```python
    from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
    import gmpy2

    n = 17258212916191948536348548470938004244269544560039009244721959293554822498047075403658429865201816363311805874117705688359853941515579440852166618074161313773416434156467811969628473425365608002907061241714688204565170146117869742910273064909154666642642308154422770994836108669814632309362483307560217924183202838588431342622551598499747369771295105890359290073146330677383341121242366368309126850094371525078749496850520075015636716490087482193603562501577348571256210991732071282478547626856068209192987351212490642903450263288650415552403935705444809043563866466823492258216747445926536608548665086042098252335883
    e = 3
    ct = 243251053617903760309941844835411292373350655973075480264001352919865180151222189820473358411037759381328642957324889519192337152355302808400638052620580409813222660643570085177957

    for i in range(10000):
        test = i * n + ct
        m , _ = gmpy2.iroot(test,3)
        if _:
            print(m)
            print(long_to_bytes(m))
    ```

## RSA相关攻击

### 扩展欧几里得算法

#### [Endless RSA-第二关](https://zjusec.com/challenges/82)

```bash
====== Level  2 ======
### n = 0x75c14feb68d40564271f8da54a1973dad15d47fe0a7101d5056e84d2fcaf3c17ec62cdd4b1662ab6319b410122fd2e2dd128b535bb61eadc6891ee02f982a8356894033ba24c1b5ea42e5a6166f427970d415c9b1ff635213dea6fb116b386d3d6362f2f00579f6e273320a9ad3b0a9895cdacfadd7c5eacd5e3121ac420f93b
### e1 = 0xa8eb28b3
### e2 = 0xe54d3167
### c1 = 0x10e64617de6b664c88af52bb51a7a57c64ac3427a80b19d02a7fbed022631ba7baaeb10026193525b36ce378781b8f382bb88e08b7e16cca1e6314f4eb94019cf76c9f5f64cf2fd981e42cc459e526bf5263a79f744e26114ff04d3206d570fa7d143ec5d205a16684bac4f0dd16f91c622e6ece8628a45ea56575a303c8f42b
### c2 = 0x6353d6ba409275651e13e2fad14d5f4dce7d57de645197541f79fa3c222ccf6c173186e4df1a9edf33e941f22246842e99676f57ace226b3280621281200de1e893d7cd15b8f33a6239a04133f60a9ca9f3d0a79361ff3a70f91a1802cb26898e6f5b4b4003963a4e9bda36c48e8beef3076a8db50ff3c35ce2fbd043a59e55f
!!! assert c1 == pow(m, e1, n)
!!! assert c2 == pow(m, e2, n)
@@@ m = 
```

??? tips "扩展欧几里得算法"

    extend_gcd是利用递归回溯，在计算gcd的过程中找到符合Bezout等式的$x,y$的过程.

    在辗转相除的过程中，其中一环是$gcd(a,b) = gcd(b,a\pmod b)) (*)$

    现在设已经计算出下一层的解：$bx'+a\pmod b)y' = gcd(b,a\pmod b)) (**)$

    则把(*)带入到(**)中，有：

所以书写：

??? tips "Writeup"

    ```python
    def egcd(a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = egcd(b % a, a)
            return (g, x - (b // a) * y, y)

    def solve():
        g, x, y = egcd(e1, e2)
        if x < 0:
            x = -x
            c1_inv = gmpy2.invert(c1, n)
            result = pow(c1_inv, x, n)
        else:
            result = pow(c1, x, n)
        if y < 0:
            y = -y
            c2_inv = gmpy2.invert(c2, n)
            result = (result * pow(c2_inv, y, n)) % n
        else:
            result = (result * pow(c2, y, n)) % n
        return result

    m = solve()
    ```

### 连分数展开

??? tips "Wiener Theorem"

    如果$N = p*q (q < p < 2p), d < \dfrac{1}{3}N^{\frac{1}{4}}$，则在已知$(N,e)$的情况下，$d$是可以恢复的.

#### Endless RSA-第三关

```bash
Received 0x35d bytes:
    b'====== Level  3 ======\n'
    b'### n = 0xce202f8fd1b78c23dfa53314617510cd422e3f4c5aa412400ed44abaf3d4bbdf4230c8f9f73736c32cbcbec0c7780b6b56f7d4bea1678640581cd4aaf2df9ff4175846fc44ddf94e924a188d0b0989ecc462da8c5e88c295e26beeafab201ab6ab299dc0f0106dd1a3cc21d17c757130be6f3f0b5b250932396f34ac3295d057\n'
    b'### e = 0x684b3ab9779f91c23597668e5eb8dd73a3333f9fb7a456583204d255576bef204a1201d276a00cb88d531c3aa993e7304162bf673baebffc39210a1c3faa64712a4e12c1da67eb98817d981bc8bbe9d4cf605903fc039b507e8b77248a88c995741b152c41609d3d86518cba8d9da419dd36e8f8bc07881be87990ea26873b6b\n'
    b'### c = 0x9d749f88d638b0a560d7cd7896f9fb07b10dd0cd5c3771742d3a4388750e1d26353daea617de31f6a98e9a1c06de4df3baa54de3adaf3c238c7405c8d81d5a0efacfff8284584489d1bd5611e0dd5faf850982dfed6adb15f173b279244e8b75e97cb08b3772c78e36a711f98c69558d628e51353ae241f581dd31689a11773b\n'
    b'!!! assert c == pow(m, e, n)\n'
    b'@@@ m = '
```

还是跑了两遍，得到的第二遍：

```bash
[DEBUG] Received 0x35d bytes:
    b'====== Level  3 ======\n'
    b'### n = 0xce202f8fd1b78c23dfa53314617510cd422e3f4c5aa412400ed44abaf3d4bbdf4230c8f9f73736c32cbcbec0c7780b6b56f7d4bea1678640581cd4aaf2df9ff4175846fc44ddf94e924a188d0b0989ecc462da8c5e88c295e26beeafab201ab6ab299dc0f0106dd1a3cc21d17c757130be6f3f0b5b250932396f34ac3295d057\n'
    b'### e = 0x684b3ab9779f91c23597668e5eb8dd73a3333f9fb7a456583204d255576bef204a1201d276a00cb88d531c3aa993e7304162bf673baebffc39210a1c3faa64712a4e12c1da67eb98817d981bc8bbe9d4cf605903fc039b507e8b77248a88c995741b152c41609d3d86518cba8d9da419dd36e8f8bc07881be87990ea26873b6b\n'
    b'### c = 0x5b7948b8177ea6c826a360ce98ec01e4a0de030e6e29537862f5312bb55a9117c2a01dae28040bad3677e3871ba00abaa67d30a64e38102ab33c47c16fea6f420c7b565ce48fa57e09eb7f62fc95adaad036f33acaaf010dd83592dfc93d3eae1ba6b8ae9c1723ded27132da37a5681170e0286a7a9c3418c6dcc49130926145\n'
    b'!!! assert c == pow(m, e, n)\n'
    b'@@@ m = '
```

也就是说，难度相较于Level 1又升级了，虽然$n,e$仍然是已知的固定数，但数量级大了很多以至于难以分解（都是1024bits）这道题的方法跟下面的1.2.3一致，均使用了连分数展开，所以不赘述.

??? tips "Writeup"

    ```python
    def continued_fractions(n, d): #计算n/d的连分数展开
        fractions = []
        while d:
            q = n // d
            fractions.append(q)
            n, d = d, n - q * d
        return fractions

    def convergents(cf):     # 从连分数计算收敛分数
        convergents_list = []
        h_prev, h_curr = 0, 1
        k_prev, k_curr = 1, 0
        
        for a in cf:
            h_next = a * h_curr + h_prev
            k_next = a * k_curr + k_prev
            convergents_list.append((h_next, k_next))
            h_prev, h_curr = h_curr, h_next
            k_prev, k_curr = k_curr, k_next
        
        return convergents_list

    def wiener_attack(e, N):
        cf = continued_fractions(e, N)
        convergents_list = convergents(cf)
        
        for k, d in convergents_list:
            if k == 0 or d == 0:
                continue
            if (e * d - 1) % k == 0:
                phi_candidate = (e * d - 1) // k
                
                # 尝试分解N
                # N = p*q, φ(N) = (p-1)*(q-1) = N - p - q + 1
                # 所以 p + q = N - φ(N) + 1
                s = N - phi_candidate + 1
                discriminant = s * s - 4 * N
                
                if discriminant >= 0:
                    sqrt_discriminant = isqrt(discriminant)
                    if sqrt_discriminant * sqrt_discriminant == discriminant:
                        p = (s + sqrt_discriminant) // 2
                        q = (s - sqrt_discriminant) // 2
                        
                        if p * q == N and p > 1 and q > 1:
                            return d, p, q
        
        return None, None, None

    def small_d_attack(N, e, c):    # main
        print("Wiener攻击开始")
        d, p, q = wiener_attack(e, N)
        if d is not None:
            print(f"d = {hex(d)}")
            print(f"p = {hex(p)}")
            print(f"q = {hex(q)}")
            phi = (p - 1) * (q - 1)
            if (e * d) % phi == 1:
                m = pow(c, d, N)
                return m
        return None

    N = # 略
    e = # 略
    c = # 略
    m = small_d_attack(N, e, c)
    ```

### Blinding

> 参考文献：Dan Boneh. Twenty years of attacks on the RSA cryptosystem. *Notices of the American Mathematical Society (AMS)*, 46(2):203–213, 1999.

假设我的私钥：$(N,d)$，公钥：$(N,e)$，攻击者希望被我签名的信息是$m$.

现在攻击者挑选了一个随机的$r$，并经过了以下处理把$m' = r^em\pmod N)$传给我.

于是我提供了对$m'$的签名$s'$，但这样一来就会被攻击从而获取正常签名的$s$，这是因为：

$$m' = mr^e\pmod N) \Longrightarrow s' = (m')^d = (mr^e)^d=m^dr^{de}\equiv m^dr\pmod N)$$

（欧拉定理，$$de \equiv 1\pmod  \phi(N) \Longrightarrow r^{ed-1}\equiv 1 \pmod  N)$）

所以想要知道$s=m^d\pmod  N)$，只需要计算$s'/r\pmod  N)$ 即可.

??? tips "攻击者角度的payload"

    ```python
    N = #
    e = #
    m_pro = #
    r = #
    s_pro = #

    ```



#### [RSA Adventure第一关](https://zjusec.com/challenges/98)

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

### 密钥交互破解

#### [Another RSA](https://zjusec.com/challenges/12)

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

??? tips "Writeup"

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

### AMM破解（有限域开方解密）

> [有限域上的高次开根AMM算法在RSA上的应用-奇安信](https://forum.butian.net/share/1689)

#### [RSA Adventure-第二关](https://zjusec.com/challenges/98)

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

???+ tips "有限域开方解密"



payload:

??? tips "Writeup"

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


#### [RSA Adventure-第三关](https://zjusec.com/challenges/98)

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

??? tips "Writeup"

    ```python
    n = 0x4a471ffda8b4d8d223f6b64884b798a8a8356e6d024f92c46a9171c8841b
    e = 3
    p = 800336709776908303691579 # pow = 1
    q = 800336709776908303690799 # pow = 2
    phi = (p-1)*(q-1)*q
    d = gmpy2.invert(e,phi)
    m = pow(c,d,n)
    ```

### dp相关攻击

#### [RSA Adventure-第四关](https://zjusec.com/challenges/98)

```bash
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

$$\begin{cases} de = 1 + k(p-1)(q-1) \\ d = d_p + k_1(p-1) \end{cases} \Longrightarrow de = 1 + k(p-1)(q-1) = ed_p+ek_1(p-1)$$

$$\Longrightarrow ed_p\equiv 1 \pmod p-1)$$

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

### 相关消息攻击

#### [RSA Adventure-第五关](https://zjusec.com/challenges/98)

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

???+ tips "相关消息攻击"

    如果加密的多条消息具有线性相关性，产生的攻击称为相关消息攻击.

    例子：假设$\begin{cases}m^e \equiv c_1 \pmod  n) \\ (m+t)^e \equiv c_2 \pmod  n)\end{cases}$，$t$已知，那么可以定义$\pmod  N)$下的多项式$f_1 = x^e-c_1,f_2=(x+t)^e-c_2$.

    容易知道$m$是$f_1,f_2$的根，所以$f_1,f_2$由公因式$(x-m)$，因此求公因式就可以得到$gcd(f_1,f_2)=x-m\Longrightarrow \boxed{m}$.

这里试了一下赋值$k = 1,2$：

$$\begin{cases} m^2+m \equiv r_1 & \pmod  n) \\ m^4 + 4m^3 + 4m^2 \equiv r_2 & \pmod  n) \end{cases}$$

于是只需要将两个多项式求出(mod n)意义下的公因式即可，payload如下：

（这部分比较特殊，使用了子过程处理sagemath环境的运算，再传递回python代码中）

??? tips "Writeup"

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

## 赛题Archive

### 2024长城杯-rasnd

??? info "Problem"

    ```python
    from Crypto.Util.number import getPrime, bytes_to_long
    from random import randint
    import os

    FLAG = os.getenv("FLAG").encode()
    flag1 = FLAG[:15]
    flag2 = FLAG[15:]

    def crypto1():
        p = getPrime(1024)
        q = getPrime(1024)
        n = p * q
        e = 0x10001
        x1=randint(0,2**11)
        y1=randint(0,2**114)
        x2=randint(0,2**11)
        y2=randint(0,2**514)
        hint1=x1*p+y1*q-0x114
        hint2=x2*p+y2*q-0x514
        c = pow(bytes_to_long(flag1), e, n)
        print(n)
        print(c)
        print(hint1)
        print(hint2)


    def crypto2():
        p = getPrime(1024)
        q = getPrime(1024)
        n = p * q
        e = 0x10001
        hint = pow(514*p - 114*q, n - p - q, n)
        c = pow(bytes_to_long(flag2),e,n)
        print(n)
        print(c)
        print(hint)
    print("==================================================================")
    crypto1()
    print("==================================================================")
    crypto2()
    print("==================================================================")
    ```

先看第一部分：$p,q(1024 \text{bits}), x_1,x_2(\text{rand, 11bits}),y_1,y_2(\text{rand, >100bits})$

$$\begin{cases}
hint_1 + \text{0x}114 = x_1 p + y_1 q \\
hint_2 + \text{0x}514 = x_2 p + y_2 q
\end{cases}$$

破解关键点在于$x_1,x_2$太小，于是可以通过双重迭代设置两个小参数$a,b(\text{11bits})$，使得：

$$\begin{cases}
a(hint_1 + 0x114) = ax_1 p + ay_1 q \\
b(hint_2 + 0x514) = bx_2 p + by_2 q
\end{cases} \overset{ax_1=bx_2}\Longrightarrow 
res = a(hint_1 + \text{0x}114) - b(hint_2 + \text{0x}514) = (ay_1 - by_2) q \equiv 0\pmod  q)$$

于是求出$q = \operatorname{gcd}(res,n)$. 这题就基本完成了.

第二部分：费马小定理的应用.

注意到$n-p-q = \phi(n) - 1$，而且很明显$\operatorname{gcd}(514p - 114q, n) = 1$，所以直接使用费马小定理得到：

$$ hint = (514p - 114q)^{n - p - q} \equiv (514p - 114q)^{-1} \pmod  n)\Longrightarrow (514p - 114q)hint \equiv 1 \pmod  n) 
\Longrightarrow 514p^2 - hint^{-1} p - 114 n \equiv 0 \pmod  n)$$

直接sagemath调用`roots()`就能解决了.

??? tips "[NSSCTF-Writeup](https://www.nssctf.cn/note/set/9943)"

    ```python
    from pwn import *
    from itertools import product

    # context.log_level = 'debug'
    io = remote('node1.anna.nssctf.cn', 28785)

    def attack1(n,c,hint1,hint2):
        for a, b in product(range(int(2**11)), repeat=2):
            q = gcd(a * (hint1 + 0x114) - b * (hint2 + 0x514), n)
            if q != 1 and q < n:
                print(q, n)
                break
        p = n // q

        d = pow(0x10001,-1,(p-1)*(q-1))
        m = pow(c,d,n)
        # print(bytes.fromhex(hex(m)[2:]))
        return bytes.fromhex(hex(m)[2:])


    def attack2(n,c,hint):
        P.<x> = PolynomialRing(ZZ)
        f = 514*x^2 - pow(hint,-1,n)*x - 114*n
        p = int(f.roots()[0][0])
        q = n // p

        d = pow(0x10001,-1,(p-1)*(q-1))
        m = pow(c,d,n)
        # print(bytes.fromhex(hex(m)[2:]))
        return bytes.fromhex(hex(m)[2:])

    io.recvline()
    n = int(io.recvline().decode().strip())
    c = int(io.recvline().decode().strip())
    hint1 = int(io.recvline().decode().strip())
    hint2 = int(io.recvline().decode().strip())
    print(attack1(n,c,hint1,hint2))

    io.recvline()
    n = int(io.recvline().decode().strip())
    c = int(io.recvline().decode().strip())
    hint = int(io.recvline().decode().strip())
    print(attack2(n,c,hint))
    ```

    还有[一个解](https://www.nssctf.cn/note/set/12514)感觉也不错.

### 2025ZJUCSACTF-babyRSA

[Ref](https://blog.5dbwat4.top/arch/CSACTF2025-Writeup#babyRsa)

??? info "Problem"

    ```python
    from Crypto.Util.number import *
    from secret import flag
    import gmpy2

    m = bytes_to_long(flag[:19])

    p = getPrime(1024)
    q = getPrime(1024)
    N = p * q
    phin = (p - 1) * (q - 1)
    e = 0x10001
    d = gmpy2.invert(e, phin)
    print(d - p)
    print(pow(m, e, N))
    print(N)
    # 2551756296230556455153461142256558662892670316950235756205055813974596327809845104526723991103791519643650309481773430116596445056621314003219883178059757998882818276435859354707327583130042659575327825768326628051521469996692935342698707595506169488367250369701727437051651180572487178040011110411554700942787226887828691419928759312983854249497569715361729302927781514981880654479059321530075054979991662440146179410101287675885973372091690923001774040638576268604000902523671010492732048209337569176535938725020523648350397601225455506699505240572770233601345289329527790660324779363188244080506367846538941254260
    # 15971309396256835362531485951128166983206687537714027537858621542505837518266962953113283078076889299992766766084018288988406699208913051384679790264007098624219450206475206014672536932788204025908959226423862863105445190794751238955057213166812828836859124836604576681535267728522357997298297456365207788184878644031601919916837973507434190104725947258940723229288878807644645051813848097692257981034447284379832096671294140741904947037566307085602107241375721489415120904300455359620297677533606229298114263489015021336257788565359759312693790170999715775553831478938083873456866209473156243356364882697055947038033
    # 17154010912510203959523272425896818657297869993021602292995255193399642992683743831712781844801434487935779088368754260903824107054650841709818595121602457685176250013619541956042068706082019261523054643284318619613556526738461883634674858927755444636283155962574839577603247863491547049667474422304037381854670052998349971200044078692166792550323925980836302324144231971216224668698971348394532478457497878076908606080048700669391473735992839985369965723367504239067817263161028103823044373957891549372409108859137498344836594151291454836621683376821160950429180536440623985341901524194163420366533633759132239742143


    m = bytes_to_long(flag[19:])

    p = getStrongPrime(1024)
    q = gmpy2.next_prime(p ^ ((1 << 900) - 1))
    n = p * q
    e = 0x10001

    c = pow(m, e, n)
    print(hex(n))
    print(hex(c))
    # 0x979b0d5014e3e0b01091d5cd145c5c62f027da4592f71dbbcf114e9e94d56632832fb57a0e27d581bd86be6ef5a019781edef8e35dab664eb46efa67bdcf1b3abf5de2f21d125d6559493d7b7460f33387fc1c38329fd60c9e69803f74bb645cf11d674585b86ad9c966d0ca6fafdcf8c0c7eaddca396ab5b3a21a8ae261fa7e1915f618593352f2d7efd8eba8d1fd80074fbd66999e86bc8417761daecf2a9c446a9db93e691f277cffe870d2b781c305a9ceb71bd4191cb733f6377b7d123aa7e86e0519b484e347fb0307fc468c8006a66452a5ae90046a43ecb17fe4480aa39ca7674cbd88d837c0902c32a109b67a3d91e5ffa4cd3fbeaf305335fae207
    # 0x82f76dce83c5156bfb205e173372c9bc074155f0548975b0bd1ea4b258e2262e8612a29331602f952e598439c6651b27d7d75822040101994fcae8120f3fe5cc2df49f221843dd02c1b14c91ea24ad51cdf7cbcd8e4961c2e03045642257365dfabeb873de2a7ea4c1e1c69e975d644fa015f0dbb149bbe99b7c592465ae5effd3cc0405ebe7dde2ec401d19d73d4c41259fc7823c060af95c20e3f553b075b7a29af786957917a45bcf5ac9196ddb87e3e78bf63f9b9d705676759effe111301b8b23d8f4aeafd8f5a337a7cc982ed306f0fb2132078a8da3de543ad14a15d74c9cc19a4a57818f9611681e023919da1832dc883d1bac97130c4dbb7b60dda
    ```

第一部分：

假设 $X = d-p$，则 $e(X+p) = k(p-1)(\dfrac Np - 1) + 1$

整理得: $(e+k)p^2 + (eX - kN - k - 1)p + kN = 0$

由于 $ed = k\phi(N) + 1$ 中的 $k$ 不会很大，所以可以枚举 $1 < k < e$ 找到有解的情况：

??? tips "Writeup-1"

    ```python
    from Crypto.Util.number import long_to_bytes

    X = #
    C1 = #
    N1 = #
    e = 0x10001

    print("[*] 正在破解第一部分...")
    R.<p> = PolynomialRing(ZZ)
    for k in range(1, e):
        f = (e + k)*p^2 + (e*X - k*N1 - k - 1)*p + k*N1
        roots = f.roots()
        if roots:
            p_val = int(roots[0][0])
            print(p_val)
            if N1 % p_val == 0:
                d1 = int(inverse_mod(e, (p_val-1)*(N1//p_val-1)))
                m1 = pow(C1, d1, N1)
                part1 = long_to_bytes(int(m1))
                print(f"Part 1: {part1.decode()}")
                break
    ```

??? tips "Writeup-2"

    ```python
    import math
    from Crypto.Util.number import long_to_bytes

    def main(n, c):
        e = 0x10001
        base = 2**900
        N_low = n % base

        found = False
        p_val = None
        q_val = None

        for k in range(1, 10000, 2):
            solutions = [1]
            for m in range(2, 901):
                new_solutions = []
                for b0 in solutions:
                    f_val = b0*b0 + b0*(1 - k) + N_low
                    if f_val % (2**(m-1)) != 0:
                        continue
                    c_val = f_val // (2**(m-1))
                    if c_val % 2 == 0:
                        new_solutions.append(b0)
                        new_solutions.append(b0 + 2**(m-1))
                solutions = new_solutions
                if not solutions:
                    break

            if not solutions:
                continue

            for b in solutions:
                d = base - 1 - b + k
                C = b * d - n
                D = (base - 1 + k)**2 - 4 * C
                root = math.isqrt(D)
                if root * root != D:
                    continue
                A = (- (base - 1 + k) + root) // 2
                if A % base != 0:
                    continue
                p = A + b
                if n % p == 0:
                    p_val = p
                    q_val = n // p
                    found = True
                    break
            if found:
                break

        if not found:
            print("Failed to factor n")
            return

        phi = (p_val - 1) * (q_val - 1)
        d = pow(e, -1, phi)
        m = pow(c, d, n)
        flag = long_to_bytes(m)
        print(flag.decode())

    if __name__ == '__main__':
        main(N2, C2)
    ```