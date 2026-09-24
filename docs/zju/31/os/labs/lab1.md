# Lab 1: 内核启动与时钟中断

> [实验文档](https://os.pages.zjusct.io/fa26/doc-shoulidan/lab1/)

## 环境配置

```bash
git checkout -b lab1
git fetch upstream
git merge upstream/lab1
```

看到 `./Makefile` 显示冲突，选择保留新的 `upstream/lab1` 的情况：

```bash
#KERNEL_PATH := $(wildcard /opt/linux-*)
KERNEL_PATH := kernel
```

这个时候 `autograder` 的确是空白的，所以：

```bash
git submodule update --init --recursive
```

得到了 `autograder/`.

至此多出了一大堆文件，先没急着动.

<center><img src="./figures/lab1/0.png" alt="0" style="zoom:80%;" /></center>

## Part 1: 启动工作

>  [!NOTE]
>
>  ```c
>  int func(int a){return a;}
>  
>  int main() {
>  int r = func(10);
>  return r + 1;
>  }
>  ```
>
>  ```assembly
>  func(int):
>       addi    sp,sp,-32
>       sd      ra,24(sp)
>       sd      s0,16(sp)
>       addi    s0,sp,32
>       mv      a5,a0
>       sw      a5,-20(s0)
>       lw      a5,-20(s0)
>       mv      a0,a5
>       ld      ra,24(sp)
>       ld      s0,16(sp)
>       addi    sp,sp,32
>       jr      ra
>  main:
>       addi    sp,sp,-32
>       sd      ra,24(sp)
>       sd      s0,16(sp)
>       addi    s0,sp,32
>       li      a0,10
>       call    func(int)
>       mv      a5,a0
>       sw      a5,-20(s0)
>       lw      a5,-20(s0)
>       addiw   a5,a5,1
>       sext.w  a5,a5
>       mv      a0,a5
>       ld      ra,24(sp)
>       ld      s0,16(sp)
>       addi    sp,sp,32
>       jr      ra
>  ```
>
>  - 每个函数的开头都操作了 `sp`，这是在干什么？
>
>     这个是栈指针（stack pointer），移动是开辟栈帧（stack frame），移动后指向的寄存器不同，可以对一段内存指向的多个寄存器赋值.
>
>  - 尝试修改 C 语言代码，你会发现 `sp` 的差值总是 16 的倍数，这是为什么？
>
>     * 改 `r` 的类型为 `long int`，在汇编代码的第22-23行会变成：
>
>         ```assembly
>                 sd      a5,-24(s0)
>                 ld      a5,-24(s0)
>         ```
>     
>         其余不变；
>     
>     * 改 `func` 为复合类型的函数：
>     
>         ```c++
>         long long func(int a, double b){return (long long)a+b;}
>         
>         int main() {
>           long long r = func(10, 20);
>           return r + 1;
>         }
>         ```
>     
>         汇编变成：
>     
>         ```assembly
>         func(int, double):
>                 addi    sp,sp,-32
>                 sd      ra,24(sp)
>                 sd      s0,16(sp)
>                 addi    s0,sp,32
>                 mv      a5,a0
>                 fsd     fa0,-32(s0)
>                 sw      a5,-20(s0)
>                 lw      a5,-20(s0)
>                 fcvt.d.w        fa4,a5
>                 fld     fa5,-32(s0)
>                 fadd.d  fa5,fa4,fa5
>                 fcvt.l.d a5,fa5,rtz
>                 mv      a0,a5
>                 ld      ra,24(sp)
>                 ld      s0,16(sp)
>                 addi    sp,sp,32
>                 jr      ra
>         main:
>                 addi    sp,sp,-32
>                 sd      ra,24(sp)
>                 sd      s0,16(sp)
>                 addi    s0,sp,32
>                 lla     a5,.LC0
>                 fld     fa5,0(a5)
>                 fmv.d   fa0,fa5
>                 li      a0,10
>                 call    func(int, double)
>                 sd      a0,-24(s0)
>                 ld      a5,-24(s0)
>                 sext.w  a5,a5
>                 addiw   a5,a5,1
>                 sext.w  a5,a5
>                 mv      a0,a5
>                 ld      ra,24(sp)
>                 ld      s0,16(sp)
>                 addi    sp,sp,32
>                 jr      ra
>         .LC0:
>                 .word   0
>                 .word   1077149696
>         ```
>     
>         `sp` 差值还是不变.
>     
>     这个好像是 RISC-V 的标准规定，栈指针必须16字节对齐. 可以让内存访问的效率提高.
>
>  - 调用函数前后做了什么？
>
>     将汇编代码分成 caller (`main`) 和 callee (`func`)两个部分：
>     
>     * 调用前，caller会做：
>         * 分配栈帧：用`addi sp,sp,-32`语句给 `ra` 和 `s0` 腾出空间
>         * 传递参数：`li a0,10`第一个参数通过 `a0` 寄存器传递
>         * 执行跳转：`call func(int)`，将下一条指令的地址（`pc+4`）保存到 `ra` 寄存器中并跳转到 `func` 的地址
>     * 调用后，caller会获取值，释放栈帧并返回

伪指令是一种语法糖，能翻译成多种真实指令. 参见[其中](https://zju-os.github.io/doc/spec/riscv-asm.pdf)的Chap 29.

> [!NOTE]
>
> - 下列伪指令分别对应什么真实指令？
>
>     ```assembly
>     la nop li mv j ret call tail
>     ```
>
>     * `la`对应`auipc`，也就是将20位立即数左移12位后与`pc`值相加
>
>     * `nop`对应`addi x0, x0, 0`，功能就是流水线的一个bubble，相当于什么都没做.
>
>     * `li`指的是" load a specific numeric value into a register"，实际指令有很多，我能想到的有：
>
>         ```assembly
>         ld 
>         ```
>
>     * `mv`是复制指令，等同于`addi rd, rs, 0`.
>
>     * `j`是直接跳，等同于`jal x0, offset`.
>
>     * `ret`是` jalr x0, x1, 0`，即跳回到
>
>     * `call`
>
>     * `tail`是大地址跳转，即
>
>         ```assembly
>         auipc x6, offset[31:12]
>         jalr x0, x6, offset[11:0]
>         ```
>
>         
>
> - `call` 伪指令做了什么工作？它与 `tail` 指令有什么区别？