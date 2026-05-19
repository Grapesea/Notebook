收录了[ZJU校巴](https://zjusec.com)、[cryptohack](https://cryptohack.org)、[NSSCTF网站](https://www.nssctf.cn)等站点的学习笔记.

!!! tips

    Resource List:

    [CTF Wiki-Crypto](https://ctf-wiki.org/crypto/introduction/)  $\quad$  [ZJU校巴](https://zjusec.com/) $\quad$ [CryptoHack](https://cryptohack.org/) $\quad$ [NSSCTF](https://www.nssctf.cn/index)

    课堂导论Slides：

    [Crypto工具资源清单-2024CTF101](https://ljcppp.github.io/mySlides/crypto_2024/site/#/5/2)

    [Crypto基础 - 2025安全攻防实践](https://courses.zjusec.com/slides/crypto-lec1/#/)
    $\quad$
    [Crypto专题1 - 2025安全攻防实践](https://courses.zjusec.com/slides/crypto-lec2/)
    $\quad$
    [Crypto专题2 - 2025安全攻防实践](https://courses.zjusec.com/slides/crypto-lec3/)

    工具类：

    [Cyberchef](https://lab.tonycrane.cc/CyberChef/#ieol=CRLF&oeol=CRLF)
    $\quad$
    [Factordb](https://factordb.com)

    [CTF在线工具-在线UUencode编码\|UU编码\|UUencode解码\|UUencode编码原理\|UUencode编码算法](http://www.hiencode.com/uu.html)

    [CTF中那些迷惑人的”base64“_ctf base64](https://blog.csdn.net/q20010619/article/details/120770872)

    [Keyword Cipher: Free Online Monoalphabetic Substitution Tool \| Educational Cryptography](https://caesarcipher.org/ciphers/keyword)
    
    [随波逐流信息安全网](http://1o1o.xyz/index.html)

    payload import 常用开头：

    ```python
    import hashlib
    import itertools
    import string
    import re                                                       # 正则
    import requests                                                 # 交互库 
    from pwn import *                                               # pwntools
    import numpy as np                                              # numpy库
    from math import *                                              # 数学库1
    from sympy import *                                             # 数学库2
    import gmpy2                                                    # 数学库3
    from fractions import Fraction                                  # 连分数展开
    from Crypto.Util.number import long_to_bytes,bytes_to_long      # 互化 
    from Crypto.Cipher import AES, RSA                              # AES,RSA直接调取
    ```
