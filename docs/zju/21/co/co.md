---
title: 计算机组成笔记[2025-2026秋冬]
date: 2025-06-28
layout: post
categories: [CS]
mermaid: true 
mathjax: true
---
## Week 1: General Introduction

* RISC Architecture (Reduced Instruction Set Computer)
    
    指令执行使用了尽可能少的时钟周期、指令编码长度定长等，提高了CPU和编译的效率

* Computer Organization

  * Decomposability of  computer systems

  <center><img src="../co/co0.png" alt="rr" style="zoom: 40%;" /></center>

  <center><img src="../co/co01.png" alt="rr" style="zoom: 31%;" /></center>

  * Five Classic Components of Hardware

    <center><img src="../co/co1.png" alt="rr" style="zoom: 40%;" /></center>

  * CPU Processor

    Active part of the computer, containing the **datapath**(进行数据运算操作) and **control**(根据程序的指示去控制datapath, memory, I/O devices) & adding numbers, testing numbers, signaling I/O devices to activate and so on.

  * Memory:

    1. Memory: the storage area programs that are kept and that contains the data needed by the running programs
    2. Main Memory: volatile; used to hold programs while they are running.
    3. Second Memory: Nonvolatile; used to store programs and data between runs.
    4. Volatile (易失性): DRAM, SRAM
    5. Nonvolatile (非易失性): 固态硬盘/闪存, 硬盘

     

  * Software Categorization

    1. Categorize software by its use: Systems software & Application software

    2. Operating System: 

    3. Compiler: Translation of a program written in HLL

    4. Firmware: software specially designed for a piece of hardware

  * From a High-Level Language to the Language of Hardware
    1. Lower-level details are hidden to higher levels (低级语言的细节将会被隐藏);
    2. Instruction set architecture (指令集): the interface between hardware and lowest-level software;
    3. Many implementations of varying cost and performance can run identical software.
    4. 高级编程语言
    5. 汇编语言
    6. 机器语言 eg.1000110010100000 指的是将两数相加.

  

* Integrated Circuit Cost (集成电路成本)

    Yield(良率): proportion of working dies per wafer ( 晶圆上能正常工作的芯片比例 )

    $\text{Cost Per die = }\dfrac{\text{Cost per wafer}}{\text{Dies per wafer}\times \text{Yield}} \quad \text{每个芯片的成本} = \dfrac{\text{每个芯片的成本}}{\text{每个晶圆的芯片数量}\times \text{良率}}$

    $\text{Dies per wafer} \approx \dfrac{\text{wafer area}}{\text{Die area}} \quad \text{每个芯片的成本} = \dfrac{\text{晶圆面积}}{\text{芯片面积}}$

    $\text{Yield = }\dfrac{1}{(1+(\text{Defects per area} \times \frac{\text{Die area}}{2}))^2} \quad \text{良率 = }\dfrac{1}{(1+(\text{缺陷密度} \times \frac{\text{单个芯片面积}}{2}))^2}$

* Response Time and Throughput
    1. Response time/ Execution time: 响应时间/执行时间，完成任务所需时间
    2. Throughput (bandwidth): 吞吐率
    3. 影响因素：增加处理器数量；用更快的处理器

* Relative Performance

    定义$\text{Performance} = \dfrac{1}{\text{Execution time}} \Longrightarrow \dfrac{\text{Performance}_X}{\text{Performance}_Y} = \dfrac{\text{Execution time}_Y}{\text{Execution time}_X} = n$

* Measuring Execution Time:

  1. Elapsed Time: 总回复时间

  2. CPU Time: 对固定任务的总处理时间， 由User CPU time 和 System CPU time构成.

     $\text{CPU time} = \text{CPU Clock Cycles} \times \text{Clock Cycle time} = \dfrac{\text{CPU Clock Cycles}}{\text{CLock Rate}}$

  3. 时钟周期：

     <center><img src="../co/clkperiod.png" alt="rr" style="zoom: 40%;" /></center>

  4. Performance can be improved by reducing  number of clock cycles or increasing clock rate. Hardware designer must often trade off clock rate against cycle count (为了提升性能，硬件设计师经常需要在**时钟频率**和**周期数**之间做权衡取舍).

## Week 2:





## Week 3





## Week 4





## Week 5





## Week 6

