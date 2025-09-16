收录了[ZJU校巴](https://zjusec.com)、[cryptohack](https://cryptohack.org)、[NSSCTF网站](https://www.nssctf.cn)等站点的学习笔记.

!!! tips

    Resource List:

    [CTF Wiki-Crypto](https://ctf-wiki.org/crypto/introduction/)

    [ZJU校巴](https://zjusec.com/)

    [CryptoHack](https://cryptohack.org/)

    [NSSCTF](https://www.nssctf.cn/index)

    课堂导论Slides：

    [Crypto基础 - 2025安全攻防实践](https://courses.zjusec.com/slides/crypto-lec1/#/)

    [Crypto专题1 - 2025安全攻防实践](https://courses.zjusec.com/slides/crypto-lec2/)

    [Crypto专题2 - 2025安全攻防实践](https://courses.zjusec.com/slides/crypto-lec3/)

    工具类：

    [随波逐流信息安全网](http://1o1o.xyz/index.html)

    [Factordb](factordb.com)

    [CTF在线工具-在线UUencode编码\|UU编码\|UUencode解码\|UUencode编码原理\|UUencode编码算法](http://www.hiencode.com/uu.html)

    [CTF中那些迷惑人的”base64“_ctf base64](https://blog.csdn.net/q20010619/article/details/120770872)

    [Keyword Cipher: Free Online Monoalphabetic Substitution Tool \| Educational Cryptography](https://caesarcipher.org/ciphers/keyword)

    payload import开头：

    ```python
    import hashlib
    import itertools
    import string
    import re
    import gmpy2
    import math
    import requests  # 如果在WSL中需要删掉这行
    from pwn import *
    import numpy as np
    from math import isqrt, gcd
    from fractions import Fraction
    from Crypto.Util.number import long_to_bytes, bytes_to_long
    import sympy
    from Crypto.Cipher import AES
    # from sage.all import *
    ```

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