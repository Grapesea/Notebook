## Chapter 3: Arithmetic for Computer

Computer words are composed of bits, thus one word is a vector of binary numbers. In RISC-V, there are 32bit/word or 64bits/word, in which 32 bits contains 4 bytes.

!!! tips

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

* ALU (Arithmatic Logic Unit):

    设计时采用模块化设计(Modular design)的思路.

    first function: AND, OR

    second function: add (half adder / full adder)

    1 bit ALU:

    <center><img src = "../3/1.png" style="zoom: 40%" /></center>

    于是减法可以用如下的ALU实现：

    <center><img src = "../3/2.png" style="zoom: 40%" /></center>

    于是我们得到了第4个指令：sub.

    目前还缺少比较运算，其指令是：`slt rd,rs,rt`。具体含义：`slt`(set less than)，`rd`是register destination, `rs`是register source, `rt`是register target. 功能上，`rs < rt` 时 `rd = 1`，否则`rd = 0`.

    另外，sne是set not equal的意思.