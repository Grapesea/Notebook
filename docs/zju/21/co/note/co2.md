## Chapter 2

???+ info "资源链接"

    [NoughtQ的笔记](https://note.noughtq.top/system/co/2)

    [CS61C汇编器](http://venus.cs61c.org/)

    Homework: 2.4, 2.8, 2.12, 2.14, 2.17, 2.22, 2.24, 2.29

### Instructions

分成Arithmetic, Data Transfer, Logical, Shift, Conditional Branch, Unconditional Branch等部分.

#### Arithmetic

??? notes "Jumping Table"

    想要表示C语言的switch-case语句，可以使用分支地址的方法，如图：

    <center><img src = "../2/jumptable.png" style="zoom: 40%" /></center>

    比如说这段C语言代码：

    ```cpp
    switch (k) {
        case 0: f = i + j; break;
        case 1: f = g + h; break;
        case 2: f = g - h; break;
        case 3: f = i - j; break;
    }
    ```

    其中变量`f,g,h,i,j,k`分别对应寄存器`x20-x25`，寄存器x5的值为\(4\).

    完整转换的汇编如下：

    ```assembly
    .data
    JumpTable: # 跳转表：存储各个case标签的地址
        .dword L0      # JumpTable[0] -> case 0
        .dword L1      # JumpTable[1] -> case 1
        .dword L2      # JumpTable[2] -> case 2
        .dword L3      # JumpTable[3] -> case 3
    .text
    .globl main

    main: # 假设输入参数
        li   x25, 2          # k = 2 (测试用例)
        li   x5,  4          # 边界值 = 4
        la   x6, JumpTable   # x6 = 跳转表基地址
        
        # 假设变量初始值
        li   s1, 10          # g = 10
        li   s2, 3           # h = 3
        li   s3, 7           # i = 7
        li   s4, 2           # j = 2

    Boundary:
        blt  x25, x0, Exit   # 边界检查，if (k < 0) goto Exit
        bge  x25, x5, Exit   # if (k >= 4) goto Exit
        slli x7, x25, 3      # 计算跳转表索引地址，x7 = k * 8 (每个地址8字节)
        add  x7, x7, x6      # 计算 JumpTable[k] 的地址，x7 = JumpTable基址 + k*8
        ld   x7, 0(x7)       # 从跳转表加载目标地址，x7 = JumpTable[k]的内容(目标地址)
        jalr x1, 0(x7)       # 间接跳转到目标代码：跳转到x7地址，返回地址存入x1
    L0:                      # Case 0: f = i + j
        add  s0, s3, s4      # s0 = i + j
        jalr x0, 0(x1)       # 跳转到Exit (x1存的返回地址)
    L1:                      # Case 1: f = g + h
        add  s0, s1, s2      # s0 = g + h
        jalr x0, 0(x1)       # 跳转到Exit
    L2:                      # Case 2: f = g - h
        sub  s0, s1, s2      # s0 = g - h
        jalr x0, 0(x1)       # 跳转到Exit
    L3:                      # Case 3: f = i - j
        sub  s0, s3, s4      # s0 = i - j
        jalr x0, 0(x1)       # 跳转到Exit

    Exit:                    # 程序结束，s0中存储最终结果；打印结果 (系统调用)
        li   a7, 1           # 系统调用号 1 = print_int
        mv   a0, s0          # 将结果移到a0
        ecall                # 执行系统调用
        # 退出程序
        li   a7, 10          # 系统调用号 10 = exit
        ecall
    ```

### Instruction Representations

机器码是一条数字形式的指令，机器语言是指令的数字形式.

RISC-V基础指令集的所有标准指令长度都是$32\text{bits} = 4\text{bytes}$，即一个word. 为了书写方便，一般使用十六进制来压缩存储指令.

每条指令分为不同的字段，具备不同的功能.

* `opcode`: 指令要做的运算，用于区分指令格式.<br>
* `funct3`: 额外的`opcode`字段<br>
* `funct7`: 另一个额外的`opcode`字段<br>
* `rd`: 寄存器目标操作数，保存运算的结果<br>
* `rs1`: 第1个寄存器源操作数
* `rs2`: 第2个寄存器源操作数

###
