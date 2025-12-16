[比赛网站，可惜截止之后无法再回看了](https://newstar.wiki/guide/2025/)

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

### [Easy]OSINT-天空Belong

<center><img src = "../figures/osint1.jpg" style = "zoom:40%"/></center>

直接打开wsl获取信息：

```wsl
$ file 1.jpg
1.jpg: JPEG image data, Exif standard: [TIFF image data, big-endian, direntries=14, height=0, manufacturer=Xiaomi, orientation=upper-right, datetime=2025:08:17 15:03:47, GPS-Data, yresolution=209, xresolution=217], baseline, precision 8, 1920x1080, components 3
```

可以知道这张图片是小米手机拍摄，并且拍摄时间为2025:08:17 15:03:47.

<center><img src = "../figures/osint2.jpg" style = "zoom:30%"/></center>

进一步通过飞机的右翼编号，在航旅纵横和Flightera上面查出来是
[地址](https://www.flightera.net/zh/flight_details/Urumqi+Air/UQ3574/ZSJN/2025-08-17)

然后就比较离谱了，这张照片究竟是在哪拍的？我习惯性以为是长沙，结果居然错了，答案是湖北湖南边界，还没到湖北.

所以flag是`flag{UQ3574_武汉市_Xiaomi}`.

### [Easy]Music(音频隐写：MIDI格式)

[参考链接](https://www.cnblogs.com/Hardworking666/p/15866111.html)

### [Hard]前有文字，所以搜索很有用

#### Track 1

首先关注到隐写段落，使用脚本看出里面的不可见字符为`U+200B`,`U+200C`,`U+200D`,`U+200E`,`U+FEFF`：

打开bing搜索到这个帖子：[零宽字符隐写](https://blog.csdn.net/qq_45927266/article/details/120423818)

按下面的方法进入[隐写工具](https://330k.github.io/misc_tools/unicode_steganography.html)勾选并处理：

并将得到的字符串丢进cyberchef里面.

所以flag第一部分是`flag{you_`.

#### Track 2

Track2的key是brainfuck代码，丢进cyberchef里面得到的结果是`brainfuckisgooooood`.

接下来端详这个.docx文件，首先有一个不明所以的加红的“雪”字，接着发现每句话后面都有一些莫名其妙的空格，所以打开'显示/隐藏编辑标记'功能，可以看到如下场景：

#### Track3

提示我需要统计一下字符，所以让Claude写了一下代码:

```python
import os
def count_characters(file_path):
    """
    统计txt文件中所有字符的出现次数
    
    参数:
        file_path: txt文件的路径
    
    返回:
        字典，键为字符，值为出现次数
    """
    char_count = {}
    
    try:
        # 打开文件并读取内容
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read()
            
            # 遍历每个字符并统计
            for char in content:
                if char in char_count:
                    char_count[char] += 1
                else:
                    char_count[char] = 1
        
        return char_count
    
    except FileNotFoundError:
        print(f"错误：找不到文件 '{file_path}'")
        return {}
    except Exception as e:
        print(f"读取文件时发生错误：{e}")
        return {}

# 使用示例
if __name__ == "__main__":
    # 将默认路径解析为与此脚本同目录下的 3.txt，避免当前工作目录不同导致找不到文件
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_path = os.path.join(script_dir, "3.txt")

    # 如果需要，你也可以把这里改成绝对路径或通过命令行参数传入
    file_path = default_path
    print(f"尝试打开的文件路径: {file_path}")
    
    # 调用函数统计字符
    result = count_characters(file_path)
    
    # 打印结果
    if result:
        print(f"共统计到 {len(result)} 种不同字符\n")
        print("字符统计结果：")
        
        # 按出现次数降序排列并打印
        sorted_result = sorted(result.items(), key=lambda x: x[1], reverse=True)
        for char, count in sorted_result:
            # 特殊字符的显示处理
            if char == '\n':
                display_char = '\\n (换行)'
            elif char == '\t':
                display_char = '\\t (制表符)'
            elif char == ' ':
                display_char = '(空格)'
            else:
                display_char = char
            
            print(f"'{display_char}': {count} 次")
    else:
        print("未能成功统计字符")
```

得到：

```bash
共统计到 95 种不同字符

字符统计结果：
'c': 1500 次
'H': 1450 次
'@': 1400 次
'1': 1350 次
'L': 1300 次
'e': 1250 次
'n': 1200 次
'G': 1150 次
'3': 1100 次
's': 1050 次
'}': 1000 次
'w': 659 次
'!': 648 次
'i': 637 次
'V': 635 次
'F': 632 次
'K': 631 次
'Q': 631 次
'A': 629 次
'.': 627 次
'v': 627 次
'9': 626 次
'd': 625 次
';': 625 次
'&': 622 次
']': 621 次
'm': 619 次
'Y': 619 次
'>': 619 次
'h': 618 次
't': 617 次
'5': 613 次
')': 612 次
'k': 612 次
'#': 610 次
'6': 608 次
'r': 607 次
'T': 607 次
'u': 606 次
'C': 605 次
'4': 605 次
'0': 601 次
'J': 601 次
'x': 600 次
'Z': 599 次
':': 598 次
'E': 597 次
'M': 597 次
'<': 597 次
'q': 597 次
'z': 596 次
'o': 596 次
'P': 594 次
'/': 594 次
'U': 594 次
'"': 594 次
'b': 593 次
'+': 593 次
'|': 592 次
'p': 592 次
'B': 591 次
'{': 591 次
'y': 590 次
'$': 590 次
'?': 588 次
'7': 587 次
'a': 585 次
'%': 584 次
'(空格)': 584 次
'*': 583 次
'~': 582 次
',': 581 次
'-': 579 次
'^': 579 次
'[': 579 次
'l': 577 次
'2': 576 次
'_': 575 次
'(': 573 次
'R': 573 次
'f': 571 次
'\': 571 次
''': 566 次
'O': 565 次
'W': 563 次
'=': 560 次
'`': 559 次
'g': 557 次
'I': 557 次
'8': 556 次
'X': 556 次
'D': 556 次
'S': 553 次
'j': 547 次
'N': 539 次
```

这明显能看出，flag最后一段是：`cH@1LenG3s}`.
