## Chapter 3: Arithmetic for Computer

Computer words are composed of bits, thus one word is a vector of binary numbers. In RISC-V, there are 32bit/word or 64bits/word, in which 32 bits contains 4 bytes.

???+ tips
    [NoughtQ佬的笔记](https://note.noughtq.top/system/co/3)

    Homework: 3.7, 3.20, 3.26, 3.27, 3.32

    林芃老师曰：“课上我们默认32bits是1 word，64bits叫做double word.

    “教材上有一些用法混乱，之后会指出。”

* 数字表示法：

    1. ASCII - text characters (External)

    2. Binary Number (Internal)

        Natural form of computers

        requires formatting routines for I/O

        Binary numbers的复杂性导致我们无法从一串二进制码中看出唯一确定的含义.

        eg.$1001_2$这个数字在Unsigned情况下值为9，在signed情况下值可能为-1或者-7

* Arithmatic Operations:

    Addition: adding bit by bit, carries $\rightarrow$ next digit

    Substraction: using 2's complement，比如00000111-00000110，先变成00000111+1_11111010，计算完之后减去.

    Overflow:

    | Operation | Operand A | Operand B | overflow judge (MSB) | Result   |
    | --------- | --------- | --------- | -------------------- | -------- |
    | +         | $\geq 0$  | $\geq 0$  | 01                   | $<0$     |
    | +         | $<0$      | $<0$      | 10                   | $\geq 0$ |
    | -         | $\geq 0$  | $<0$      | 01                   | $<0$     |
    | -         | $<0$      | $\geq 0$  | 10                   | $\geq 0$ |

    上面这张表展示了溢出的判定情况，如当$A,B>0,result<0$且最高2位显示为01时，即可认为是overflow了.

### ALU Design

* ALU (Arithmatic Logic Unit):

    设计时采用模块化设计(Modular design)的思路.

    first function: AND, OR

    second function: add (half adder / full adder)

    1 bit ALU:

    <center><img src = "../3/1.png" style="zoom: 40%" /></center>

    于是减法可以用如下的ALU实现：

    <center><img src = "../3/2.png" style="zoom: 40%" /></center>

    于是我们得到了第4个指令：`sub`.

    目前还缺少比较运算，其指令是：`slt rd,rs,rt`。具体含义：`slt`(set less than)，`rd`是register destination, `rs`是register source, `rt`是register target. 功能上，`rs < rt` 时 `rd = 1`，否则`rd = 0`.

    另外，`sne`是set not equal的意思.

    Constructing an ALU：有两种方法，Modular design (模块化设计) 和 sharable logic with "select"

#### Adder

1. ripple carry adder（行波进位加法器）: slow

    原理推导：
    $\begin{cases}
            C_{i+1} = A_iB_i + B_iC_i + C_iA_i \\
            S_i = A_i \oplus B_i \oplus C_i
        \end{cases}$

    原理图：
    <center><img src = "../3/3.png" style="zoom: 40%" /></center>

2. Group Carry Lookahead Logic

    为了加快运算速度，考虑替换掉\(C_{1,2,etc.}\)，先定义：
    $\begin{cases}
            G_i = A_iB_i & (\text{Carry generated})\\
            P_i = A_i \oplus B_i & (\text{Carry propagated})
        \end{cases}$

    原理推导：
    $\begin{cases}

        \end{cases}$

    原理：

3. Carry skip adder

4. Carry select adder

#### Multiplication

    Group Carry Lookhead Logic
