### Introduction

只有这个传递json有点记录的意义：

!!! tips

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

### General

#### You either know, XOR you don't

```
I've encrypted the flag with my secret key, you'll never be able to guess it.
Remember the flag format and how it might help you in this challenge!
0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104
```

丢到cyberchef里面，

<center><img src="../photos/cryptohack/xor_cc0.png" alt="rr" style="zoom: 50%;" /></center>

可以看到myXORkey了，然后把这个放到左边的框里面就行了：

<center><img src="../photos/cryptohack/xor_cc1.png" alt="rr" style="zoom: 50%;" /></center>

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

    $$\begin{cases} c_1 \equiv (2p+3q)^{e_1} & (\operatorname{mod}N) \\ c_2 \equiv (5p+7q)^{e_2} & (\operatorname{mod}N) \end{cases} \Longrightarrow \begin{cases} c_1 \equiv (2p)^{e_1}+(3q)^{e_1} & (\operatorname{mod}N) \\ c_2 \equiv (5p)^{e_2}+(7q)^{e_2} & (\operatorname{mod}N) \end{cases} $$
    
    $$\Longrightarrow \begin{cases} c_1^{e_2}5^{e_1e_2} \equiv (10p)^{e_1e_2}+(15q)^{e_1e_2} & (\operatorname{mod}N) \\ c_2^{e_1}2^{e_1e_2} \equiv (10p)^{e_1e_2}+(14q)^{e_1e_2} & (\operatorname{mod}N) \end{cases}$$

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
