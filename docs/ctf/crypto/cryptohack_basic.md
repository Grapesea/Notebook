## Introduction

??? tips "传递json"

    Several of the challenges are dynamic and require you to talk to our challenge servers over the network. This allows you to perform man-in-the-middle attacks on people trying to communicate, or directly attack a vulnerable service. To keep things consistent, our interactive servers always send and receive JSON objects.

    Such network communication can be made easy in Python with the `pwntools` module. This is not part of the Python standard library, so needs to be installed with pip using the command line `pip install pwntools`.

    For this challenge, connect to `socket.cryptohack.org` on port `11112`. Send a JSON object with the key `buy` and value `flag`.

    The example script below contains the beginnings of a solution for you to modify, and you can reuse it for later challenges.

    `pwntools.py`:

    ```python
    #!/usr/bin/env python3
    from pwn import * # pip install pwntools
    import json

    HOST = "socket.cryptohack.org"
    PORT = 11112

    r = remote(HOST, PORT)

    def json_recv():
        line = r.readline()
        return json.loads(line.decode())

    def json_send(hsh):
        request = json.dumps(hsh).encode()
        r.sendline(request)

    print(r.readline())
    print(r.readline())
    print(r.readline())
    print(r.readline())

    request = {
        "buy": "clothes"
    }
    json_send(request)

    response = json_recv()

    print(response)
    ```

    只需要交互的时候写个`{"buy": "flag"}`就能得到flag.

## Encoding

主要是需要温习一下各种加解码的代码书写.

??? tips "Writeup"

    ```python
    from pwn import * # pip install pwntools
    import json
    import base64
    import codecs
    from Crypto.Util.number import long_to_bytes
    import requests

    r = remote('socket.cryptohack.org', 13377, level = 'debug')

    def json_recv():
        line = r.recvline()
        return json.loads(line.decode())

    def json_send(hsh):
        request = json.dumps(hsh).encode()
        r.sendline(request)

    for i in range(101):
        received = json_recv()
        print("Received type: ")
        print(received["type"])
        print("Received encoded value: ")
        print(received["encoded"])

        type = received["type"]
        challenge_words = received["encoded"]
        
        if type == "base64":
            res = base64.b64decode(challenge_words).decode()
        elif type == "hex":
            res = bytes.fromhex(challenge_words).decode()
        elif type == "rot13":
            res = codecs.decode(challenge_words, 'rot_13')
        elif type == "bigint":
            res = long_to_bytes(int(challenge_words,16)).decode()
        elif type == "utf-8":
            res = "".join([chr(b) for b in challenge_words])

        to_send = {
            "decoded": res
        }
        cnt = i+1
        print(f"\033[91m这是交互第{cnt}轮\033[0m")
        json_send(to_send)
    ```

## XOR

### [You either know, XOR you don't](https://cryptohack.org/challenges/general/)

??? tips "Writeup"
    
    ```plaintext
    I've encrypted the flag with my secret key, you'll never be able to guess it.
    Remember the flag format and how it might help you in this challenge!
    0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104
    ```

    丢到cyberchef里面，

    <center><img src="../photos/cryptohack/xor_cc0.png" alt="rr" style="zoom: 50%;" /></center>

    可以看到myXORkey了，然后把这个放到左边的框里面就行了：

    <center><img src="../photos/cryptohack/xor_cc1.png" alt="rr" style="zoom: 50%;" /></center>

    flag: `crypto{1f_y0u_Kn0w_En0uGH_y0u_Kn0w_1t_4ll}`

### [Lemur XOR](https://cryptohack.org/challenges/general/)

是图片RGB异或的隐写，可以用stegsolve或者书写以下代码直接转化：

??? tips "Writeup"

    ```python


    ```

    flag:`crypto{X0Rly_n0t!}`

## modulo

* Quadratic Residues:

    We say that an integer $x$ is a *Quadratic Residue* if there exists an $a$ such that $a^2\equiv x (\operatorname{mod}p)$. If there is no such solution, then the integer is a *Quadratic Non-Residue*.

    一般来说*Quadratic Residue*是成对出现的.

    运算法则：

    ```
    Quadratic Residue * Quadratic Residue = Quadratic Residue
    Quadratic Residue * Quadratic Non-residue = Quadratic Non-residue
    Quadratic Non-residue * Quadratic Non-residue = Quadratic Residue
    ```

    网站上给出了比较好的记忆方法：Replace "Quadratic Residue" with +1 and "Quadratic Non-residue" with −1, all three results are the same!

* Legendre Symbol:

    记$(a/p) \equiv a^{\frac{p-1}{2}} (\operatorname{mod} p)$，则可以根据以下分支情况判别$a$是否为quadratic residue.

    $$ (a/p) = \begin{cases} 1 & \text{如果}a\text{是mod p下的quadratic residue且}a\neq 0(\operatorname{mod} p) \\ -1 & \text{如果}a\text{是mod p下的quadratic non-residue}\\ 0 & a\equiv 0(\operatorname{mod} p) \end{cases}$$

    (1)如果$p = 4k+3$，那么在找到合适的$a$之后，可以这样计算出root：

    $root = \pm a^{\frac{p+1}{4}} (\operatorname{mod}p)$（由Fermat小定理易证）

    (2)如果$p = 4k+1$，那么直接使用Sagemath，不要犹豫！！！
  
### [Adrien's Signs](https://cryptohack.org/courses/modular/adrien/)

这个题是Legendre的应用.

??? tips "Writeup"

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

### [Modular Binomials](https://cryptohack.org/courses/modular/bionomials/)"

化简：

$$\begin{cases} c_1 \equiv (2p+3q)^{e_1} & (\operatorname{mod}N) \\ c_2 \equiv (5p+7q)^{e_2} & (\operatorname{mod}N) \end{cases} \Longrightarrow \begin{cases} c_1 \equiv (2p)^{e_1}+(3q)^{e_1} & (\operatorname{mod}N) \\ c_2 \equiv (5p)^{e_2}+(7q)^{e_2} & (\operatorname{mod}N) \end{cases} $$

$$\Longrightarrow \begin{cases} c_1^{e_2}5^{e_1e_2} \equiv (10p)^{e_1e_2}+(15q)^{e_1e_2} & (\operatorname{mod}N) \\ c_2^{e_1}2^{e_1e_2} \equiv (10p)^{e_1e_2}+(14q)^{e_1e_2} & (\operatorname{mod}N) \end{cases}$$

$$ \Longrightarrow d = (15^{e_1e_2}-14^{e_1e_2})q^{e_1e_2} \equiv 5^{e_1e_2}c_1^{e_2}-2^{e_1e_2}c_2 ^{e_1} (\operatorname{mod}N)$$

所以只需要计算$gcd(d,N)$即可得到$q$.

??? tips "Writeup"

    ```python
    from math import gcd
    # 参数略
    d = pow(5,e1*e2,N)*pow(c1,e2,N)-pow(2,e1*e2,N)*pow(c2,e1,N)
        
    q = gcd(d,N)
    p = N//q
    print(f"crypto{{{p},{q}}}")
    ```

## Data Formats (公私钥格式基础)

> [参考文档](https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html)

[Data Formats](https://cryptohack.org/challenges/general/)，已经在2025ZJUCTF的入门题目中出过.

### PEM格式

PEM格式是Privacy-Enhanced Mail的缩写，一般格式形如：

```plaintext
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKC... (a whole bunch of base64)
-----END RSA PUBLIC KEY-----
```

> It wraps base64-encoded data by a one-line header and footer to indicate how to parse the data within. Perhaps unexpectedly, it's important for there to be the correct number of hyphens in the header and footer, otherwise cryptographic tools won't be able to recognise the file.

> The data that gets base64-encoded is DER-encoded ASN.1 values. Confused? The resources linked below have more information about what these acronyms mean but the complexity is there for historical reasons and going too deep into the details may drive you insane.

想要从中提取出RSA私钥有两种手段，一是**openssl command line tool**，二是**PyCryptodome**.

??? tips "Writeup"
    法一：

    ```bash
    openssl pkey -in private_key.pem -text
    ```

    法二：

    ```python
    from Crypto.PublicKey import RSA

    file_path = 'pem.pem'
    with open(file_path, 'r') as f:
        pem_data = f.read()

    key = RSA.import_key(pem_data)

    params = {
        'n': key.n,
        'e': key.e,
        'd': key.d,
        'p': key.p,
        'q': key.q,
        'dp': key.dp,
        'dq': key.dq,
        'qinv': key.u
    }

    for name, val in params.items():
        print(f"{name} = {val}\n")    
    ```

### DER格式

> PEM 只是 DER 编码 ASN.1 上的一个漂亮包装器，有时可能会直接遇到 DER 文件，如许多 Windows 工具默认支持 DER 文. 然而，其他工具希望获得的是 PEM 格式，如果导入 DER 文件可能遇到困难，所以知道如何转换格式会很有帮助.

```python
from Crypto.PublicKey import RSA 
with open('2048b-rsa.der', "rb" ) as f: 
    res = RSA.importKey(f.read()) 
    print(res.n) # 可以输出任何参数
```

### SSH 密钥参数解析

这个在连接远程服务器的时候会用到.

SSH的RSA密钥格式可能如下：

```plaintext
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCtPLqba+GFvDHdFVs1Vvdk56cKqqw5cdomlu034666UsoFIqkig8H5kNsNefSpaR/iU7G0ZKCiWRRuAbTsuHN+Cz526XhQvzgKTBkTGYXdF/WdG/6/umou3Z0+wJvTZgvEmeEclvitBrPZkzhAK1M5ypgNR4p8scJplTgSSb84Ckqul/Dj/Sh+fwo6sU3S3j92qc27BVGChpQiGwjjut4CkHauzQA/gKCBIiLyzoFcLEHhjOBOEErnvrRPWCIAJhALkwV2rUbD4g1IWa7QI2q3nB0nlnjPnjjwaR7TpH4gy2NSIYNDdC1PZ8reBaFnGTXgzhQ2t0ROBNb+ZDgH8Fy+KTG+gEakpu20bRqB86NN6frDLOkZ9x3w32tJtqqrJTALy4Oi3MW0XPO61UBT133VNqAbNYGE2gx+mXBVOezbsY46C/V2fmxBJJKY/SFNs8wOVOHKwqRH0GI5VsG1YZClX3fqk8GDJYREaoyoL3HKQt1Ue/ZW7TlPRYzAoIB62C0= bschneier@facts
```

??? tips "[Writeup](https://github.com/ltduc147/Cryptohack/blob/master/GENERAL/SSH_Keys/solution.py)"

    ```python
    from Crypto.PublicKey import RSA

    f = open("bruce_rsa.pub", "r")
    key = RSA.importKey(f.read())
    print(key.n)
    """ 
    ype(key) : RsaKey
    RsaKey:
        n: RSA modulus 
        d : private exponent 
        e : public exponent 
        p: First factor of the RSA modulus
        q: Second factor of the RSA modulus
        u : Chinese remainder component (p ^ −1 mod q) 
    """
    ```

### Transparency 

查了一下需要用到fofa，于是找到[目标网站](https://thetransparencyflagishere.cryptohack.org/).

flag: `crypto{thx_redpwn_for_inspiration}`

## Brainteaser

[Broken RSA](https://cryptohack.org/challenges/maths/)

法一：

因为此处$gcd(e,\phi) \neq 1$而且$n$已经是素数，所以不能直接求逆，要使用伪造$d$的方法. 以下是使用原理：

* $n$ is prime;
* $\phi$ and $e$ are not coprime so we dont have unique decryption;
* find all $x$ that satisfy: $(mx)^e = c (\operatorname{mod} n) \Longrightarrow x^e=1 (\operatorname{mod} n)$.

```python
# https://github.com/MateaLukiccc/CryptoHack/blob/master/Mathematics/Brainteasers_Part_1/Broken_RSA.py
from Crypto.Util.number import *
from pprint import pprint

def roots_of_unity(e, phi, n, rounds=250):
    # Divide common factors of `phi` and `e` until they're coprime.
    phi_coprime = phi
    while gcd(phi_coprime, e) != 1:
        phi_coprime //= gcd(phi_coprime, e)
    # Don't know how many roots of unity there are, so just try and collect a bunch
    roots = set(pow(i, phi_coprime, n) for i in range(1, rounds))
    assert all(pow(root, e, n) == 1 for root in roots)
    return roots, phi_coprime

n = #
e = 16
ct = #

# n is prime
# Problem: e and phi are not coprime - d does not exist
phi = n - 1
roots, phi_coprime = roots_of_unity(e, phi, n)

# Use our `phi_coprime` to get one possible plaintext
d = inverse(e, phi_coprime)
pt = pow(ct, d, n)
assert pow(pt, e, n) == ct

# Use the roots of unity to get all other possible plaintexts
pts = [(pt * root) % n for root in roots]
pts = [long_to_bytes(pt) for pt in pts]
pprint(pts)
```

法二：

直接迭代在mod N意义下开根号.

```python
# https://blog.csdn.net/ligangsz/article/details/130496837
from Crypto.Util.number import long_to_bytes
n = #
e = 16
ct = #
r2,r4,r8,r16=[],[],[],[]

PR.<x>=PolynomialRing(Zmod(n))
f = x ^ 2 - ct
x0 = f.roots()
print(x0)
for kk in x0:
    r2.append(kk[0])
print("r2")
print(r2)
for i in r2:
    f = x ^ 2 - i
    x0 = f.roots()
    for kk in x0:
        r4.append(kk[0])
        
print("r4")
print(r4)
for i in r4:
    f = x ^ 2 - i
    x0 = f.roots()
    for kk in x0:
        r8.append(kk[0])
print("r8")
print(r8)
for i in r8:
    f = x ^ 2 - i
    x0 = f.roots()
    for kk in x0:
        r16.append(kk[0])
print("r16")
print(r16)
for kk in r16:
    print(long_to_bytes(kk))
```

