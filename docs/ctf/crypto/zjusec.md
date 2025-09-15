---
title: ZJU校巴writeup
date: 2025-07-01
layout: post
categories: [CTF]
mermaid: true 
mathjax: true
---

本文主要是ZJU校巴题目的writeup，是自己的做题笔记.

## RSA

### EndlessRSA1 & 

参见



### EndlessRSA2-(校巴83)

过掉PoW之后：

```bash
Hint:
To get the flag, you need to solve a series of challenges, good luck!
And please encode your input answers with HEX (remove '0x').

====== Level  0 ======
### n = 0x1fa22f2cd7ed4ced776510e75135f92127a4e906fc9bf126f70fb79841dd2711d25e43b6614863026fa646f7e50780c2151f3314a5b0f75c3d8ce8c48c123718776a44649c88b6aeec1cf10f966ea7e3bed34881737d46602cce414973f35bfdf98ea117c3cf233321e6a24ccd16576b77c33e34f8c7bd0a9467fce6ac092aeb7ba92d
### e = 0x10001
### c = 0x124e5791e64b519f5a2bfc9bd70adce88ef1b694c6a41b9c1f8b1c1364f7d8def6b6ea89b3acc3b4b081db8af50bef223ef264fdac056998c3ecabd9e651579a103c6f0865397f4fca3d79e9577dde9a1787328cb73e13da8efbeba992a4d1c10ef805e1ee16bbc6a320d40bc3cdacf940b539e34e3892147314041f7d5576db6e1dec
!!! assert c == pow(m, e, n)
!!! assert randnum == getPrime(512)
!!! assert p == nextprime(0xAAA * randnum + getPrime(128))
!!! assert q == nextprime(0xBBB * randnum + getPrime(128))
@@@ m = 
```

高位爆破，







### 签名伪造(校巴-84)（没做出来，copy了题解）

PoW后，进入description：

```
In this challenge, you need to forge the signature of the string 'Plz give me the flag!'
Here are partial source codes:
def sign(m, d, n):
    return pow(bytes_to_long(m), d, n)

def verify(c, e, n):
    return 'Plz give me the flag!'  == long_to_bytes(pow(bytes_to_long(c), e, n))
```

Signature forgery is the act of creating or imitating someone else's signature without their permission or authorization, with the intent to deceive others into believing the forged signature is genuine.

题目的意思是：



最终flag：`AAA{fff0rge_@_5ignature_vvith_fac7or1zation|bf6bfdc7}`
