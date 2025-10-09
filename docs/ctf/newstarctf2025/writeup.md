## Crypto

### [Easy]Sagemath使用指哪？

命令行启动sage并把代码丢进去即可：

```terminal
wsl
sage
```

结果：`flag{e142d08c-7e7d-43ed-b5ad-af51ffc512ee}`

### [Easy]初识RSA

题干如下：

```python
from Crypto.Util.number import *
import hashlib

key=b'??????'   
assert len(key)==6
KEY = hashlib.md5(key).hexdigest().encode()
print('KEY=',KEY)

flag=b'flag{?????????????}'

m=bytes_to_long(flag)

e=65537
p=getPrime(512)
q=getPrime(512)
n=pow(p,3)* pow(q,2)
c=pow(m,e,n)

P=p^(bytes_to_long(key))

print("P=",P)
print("n=",n)
print("c=",c)

'''
KEY = b'5ae9b7f211e23aac3df5f2b8f3b8eada'
P= 8950704257708450266553505566662195919814660677796969745141332884563215887576312397012443714881729945084204600427983533462340628158820681332200645787691506
n= 44446616188218819786207128669544260200786245231084315865332960254466674511396013452706960167237712984131574242297631824608996400521594802041774252109118569706894250996931000927100268277762882754652796291883967540656284636140320080424646971672065901724016868601110447608443973020392152580956168514740954659431174557221037876268055284535861917524270777789465109449562493757855709667594266126482042307573551713967456278514060120085808631486752297737122542989222157016105822237703651230721732928806660755347805734140734412060262304703945060273095463889784812104712104670060859740991896998661852639384506489736605859678660859641869193937584995837021541846286340552602342167842171089327681673432201518271389316638905030292484631032669474635442148203414558029464840768382970333
c= 42481263623445394280231262620086584153533063717448365833463226221868120488285951050193025217363839722803025158955005926008972866584222969940058732766011030882489151801438753030989861560817833544742490630377584951708209970467576914455924941590147893518967800282895563353672016111485919944929116082425633214088603366618022110688943219824625736102047862782981661923567377952054731667935736545461204871636455479900964960932386422126739648242748169170002728992333044486415920542098358305720024908051943748019208098026882781236570466259348897847759538822450491169806820787193008018522291685488876743242619977085369161240842263956004215038707275256809199564441801377497312252051117441861760886176100719291068180295195677144938101948329274751595514805340601788344134469750781845
'''
```

先用暴力破解获得key的值，然后去反解p,q（毕竟这个分解一看不像是能直接做的）

脚本如下：

```python
import hashlib
import gmpy2
from pwn import *
from Crypto.Util.number import long_to_bytes, bytes_to_long
import sympy

KEY = b'5ae9b7f211e23aac3df5f2b8f3b8eada'
P= #
n= #
c= # 略去
# 把KEY丢进 https://iotools.cloud/zh/tool/md5-decrypt/ 得到key = b'crypto'
key = b'crypto'
p = P ^ (bytes_to_long(key))
q = gmpy2.iroot(n // (p**3),2)[0]
print(p)
if gmpy2.iroot(n // (p**3),2)[1] == 0:
    print(q)
assert hashlib.md5(key).hexdigest().encode() == KEY
assert P == p ^ bytes_to_long(key)
assert sympy.isprime(p)
assert sympy.isprime(q)
assert n == pow(p,3) * pow(q,2)

phi = (p**2) * (p-1) * (q-1) * q
e = 65537
d = gmpy2.invert(e, phi)
m = pow(c, d, n)
print(m)
flag = long_to_bytes(m)
print(flag)
```

得到flag为`b'flag{W3lc0me_t0_4h3_w0rl4_0f_Cryptoooo!}'`.

### [Medium]小跳蛙

有点莫名其妙的一道题.

懒得看源码了，于是直接nc开始交互：

```bash
$ nc 8.147.134.121 28765

Welcome to Cathylin's cryptography learning platform, where we learn an algorithm through an interesting problem.

There is a frog on the grid point (a, b). When a > b, it will jump to (a-b, b); when a < b, it will jump to (a, b-a); and when a = b, it will stay where it is.

Next, I will provide five sets of (a, b), and please submit the final position (x, y) of the frog in sequence

If you succeed, I will give you a mysterious flag.

1.(a,b) is: (9,2)
Please input the final position of the frog (x,y) :(1,1)
Congratulations, you answered correctly! Keep going for 4 more times and you will get the mysterious flag!
2.(a,b) is: (10,85)
Please input the final position of the frog (x,y) :(5,5)
Congratulations, you answered correctly! Keep going for 3 more times and you will get the mysterious flag!
3.(a,b) is: (996,712)
Please input the final position of the frog (x,y) :(4,4)
Congratulations, you answered correctly! Keep going for 2 more times and you will get the mysterious flag!
4.(a,b) is: (3854,3883)
Please input the final position of the frog (x,y) :(1,1)
Congratulations, you answered correctly! Keep going for 1 more times and you will get the mysterious flag!
5.(a,b) is: (98153,90198)
Please input the final position of the frog (x,y) :(1,1)
Congratulations, you answered correctly! Keep going for 0 more times and you will get the mysterious flag!
Congratulations, you answered all the questions correctly!
Mysterious Flag:flag{Go0d_j0b_t0_Cl34r_thi5_Diff3r3nt_t45k_4_u}
```

也并不是按照他的规则给答案的，而是（竟然只是）在早期试错之后意识到返回的是计算gcd的值，所以交互一会就结束了.

### [Medium]群论

一道奇怪的题目，如果只是想拿flag的话不（怎么）需要看代码.

只需要看一下交互时的阶数，对着代码里面这个表蒙上去就行了：

```python
CATALOG = [
    # (human_key, constructor_callable, accepted_aliases)
    ("C2",  lambda: CyclicPermutationGroup(2),   {"C2","C_2","Z2","Z_2","CYCLIC2"}),
    ("C3",  lambda: CyclicPermutationGroup(3),   {"C3","C_3","Z3","Z_3","CYCLIC3"}),
    ("C4",  lambda: CyclicPermutationGroup(4),   {"C4","C_4","Z4","Z_4","CYCLIC4"}),
    ("C5",  lambda: CyclicPermutationGroup(5),   {"C5","C_5","Z5","Z_5","CYCLIC5"}),
    ("C6",  lambda: CyclicPermutationGroup(6),   {"C6","C_6","Z6","Z_6","CYCLIC6"}),
    ("C7",  lambda: CyclicPermutationGroup(7),   {"C7","C_7","Z7","Z_7","CYCLIC7"}),
    ("C8",  lambda: CyclicPermutationGroup(8),   {"C8","C_8","Z8","Z_8","CYCLIC8"}),
    ("C9",  lambda: CyclicPermutationGroup(9),   {"C9","C_9","Z9","Z_9","CYCLIC9"}),
    ("C10", lambda: CyclicPermutationGroup(10),  {"C10","C_10","Z10","Z_10","CYCLIC10"}),
    ("V4",  lambda: AbelianGroup([2,2]),         {"V4","K4","KLEIN4","KLEINGROUP","C2XC2","C2*C2","Z2XZ2","Z2*Z2"}),
    ("S3",  lambda: SymmetricGroup(3),           {"S3","S_3","SYM3","D3","D_3","DIHEDRAL6"}),
    ("S5",  lambda: SymmetricGroup(5),           {"S5","S_5","SYM5"}),
    ("D4",  lambda: DihedralGroup(4),            {"D4","D_4","DIHEDRAL8","D8","D_8"}),
    ("D5",  lambda: DihedralGroup(5),            {"D5","D_5","DIHEDRAL10"}),
    ("D6",  lambda: DihedralGroup(6),            {"D6","D_6","DIHEDRAL12"}),
    ("Q8",  lambda: QuaternionGroup(),           {"Q8","Q_8","QUATERNION","QUATERNION8"}),
    ("A4",  lambda: AlternatingGroup(4),         {"A4","A_4","ALT4"}),
    ("A5",  lambda: AlternatingGroup(5),         {"A5","A_5","ALT"}),
]
```

<del>所以这些群我其实并没有搞懂，不过还是暂且搁置吧.</del>

```powershell
✅ Correct! Progress: 5/5
🎉 Congrats! Here is your flag: flag{I_v3_b3c0m3_@n_e^3Rt_in_gr0up_7h30ry_@Ft3r_5o1ving_7hi5_+++bl3m!!!}
```

### [Medium]唯一表示

题干如下：

```python
from sympy.ntheory.modular import crt
from Crypto.Util.number import bytes_to_long
from sympy import primerange
import uuid

# 生成素数列表
primes = list(primerange(2, 114514))

# 生成随机 flag，并转换为整数
flag = "flag{" + str(uuid.uuid4()) + "}"
message_int = bytes_to_long(flag.encode())

def fun(n: int):
    """
    给定整数 n，返回它对若干个素数模的余数列表，
    直到用这些余数和模数 CRT 重建出的值恰好等于 n。
    """
    used_primes = [2]          # 当前使用的素数列表，先用 2 开始
    prime_index = 1            # primes[0] 已用，从 primes[1] 开始
    while True:
        # 计算 n 对当前所有模数的余数
        remainders = [n % p for p in used_primes]

        # 用 CRT 尝试重建 n
        reconstructed, _ = crt(used_primes, remainders)

        # 如果重建成功，返回余数列表
        if reconstructed == n:
            return remainders

        # 否则继续添加新的素数，扩大模数集合
        used_primes.append(primes[prime_index])
        prime_index += 1

# 计算 message_int 的余数表示
c = fun(message_int)

print(c)


"""
[1, 2, 2, 4, 0, 2, 11, 11, 8, 23, 1, 30, 35, 0, 18, 30, 55, 60, 29, 42, 8, 13, 49, 11, 69, 26, 8, 73, 84, 67, 100, 9, 77, 72, 127, 49, 57, 74, 70, 129, 146, 45, 35, 180, 196, 101, 100, 146, 100, 194, 2, 161, 35, 155]
"""
```

### 置换

高中的时候做过某个创新大题就是这个背景，过程略，答案：

`SUCH_A_SIMPLE_PERMUTATION_WILL_DEFINITELY_NOT_STUMP_YOU.`

## Misc

### [Easy]OSINT-威胁情报

直接把hash丢进Bing，得到[网址](https://any.run/report/2c796053053a571e9f913fd5bae3bb45e27a9f510eace944af4b331e802a4ba0/42b56959-7f3e-46b8-b286-3f5765a5d67b).

apt指的是 Advanced Persistent Threat，此处是kimsuky.

通信C2服务器域名的全称是 Command and Control，即命令与控制.

在[详细信息](https://app.any.run/tasks/42b56959-7f3e-46b8-b286-3f5765a5d67b)中应该是这个：<https://alps.travelmountain.ml/>

运行时间应该是`2021.03.31`

综合起来就能得到正确答案: `flag{kimsuky_alps.travelmountain.ml_2021-03-31}`.

### [Easy]Music(音频隐写：MIDI格式)

[参考链接](https://www.cnblogs.com/Hardworking666/p/15866111.html)

###
