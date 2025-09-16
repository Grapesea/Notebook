
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


