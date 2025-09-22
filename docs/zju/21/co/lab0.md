> 可能会用到的资源：[2023年实验文档](https://artessay.github.io/ZJU-Computer-Organization-Lab-2023/#/)

> [2024计算机组成与设计实验文档](https://guahao31.github.io/2024_CO/)

> [Vivado使用相关内容](https://birchtree2.github.io/%E5%B7%A5%E5%85%B7/%E7%A1%AC%E4%BB%B6%E7%9B%B8%E5%85%B3/vivado.html)

> 主要记录一下lab0的手搓过程，免得以后又忘记了Verilog里面各种东西的写法.

本学期的lab换用了新的板子，更加便携（在某宝上查了一下大概￥2600？）. 板子型号是：
`xc7a100tcsg324-1`，意味着该型号的一些参数：

```plaintext
Family: Artix7
Device: XC7A100T
Package: csg324
Speed Grade: -1
```

Lab Slides以及给出的文件多为适配Vivado2017.4版本的，直接用我的Vivado2022.4版本打开整个项目会报错，挺恶心的.

## 预热

### 流水灯Water_LED的仿真代码书写

如图为NEXYS-A7上的16个并行LED流水灯原理图, 所有的阴极（负极）接地（共阴极），当阳极接高电平时点亮.

<center><img src = "../co/lab0/1.png" style = "zoom:40%"/></center>

将学在浙大上给出的`Water_LED.v`和`Water_LED_tb.v`代码分别导入Vivado的`Design Sources`和`Simulation Sources`中.

首先看`Water_LED.v`的代码逻辑：

```verilog
`timescale 1ns / 1ps
module Water_LED(
    input CLK_i,
    input RSTn_i,
    output reg [3:0]LED_o
    );
    reg [31:0]C0;
    
always @(posedge CLK_i)
    if(!RSTn_i) begin
        LED_o <= 4'b1;
        C0 <= 32'h0;
    end
    else begin
        if (C0 == 32'd100_000_000) begin
            C0 <= 32'h0;
            if (LED_o == 4'b1000)
                LED_o <= 4'b1;
            else LED_o <= LED_o << 1;
        end
        else begin
            C0 <= C0 + 1'b1;
            LED_o <= LED_o;
        end
    end   
    
endmodule
```

这段代码里面，`C0`是中间计数器，每计数$10^8$翻转一次，产生`1Hz`时钟来更新LED亮暗状态；

通过左移一位高电平的操作来逐一点亮LED，从而在视觉上形成流水的效果.

补全`Water_LED_tb.v`的代码：

```verilog
module Water_LED_tb;
    reg CLK_i;
    reg RSTn_i;
    wire [3:0]LED_o;
    
    Water_LED Water_LED_U(
        .CLK_i(CLK_i),
        .RSTn_i(RSTn_i),
        .LED_o(LED_o)
    );
    
    always #5 CLK_i = ~CLK_i;
    
    initial begin
        CLK_i = 0;
        RSTn_i = 0;
        #100 RSTn_i = 1;
        //Your code here.
        #4000000000 $finish;
    end    
    
endmodule
```

事实上只需要添加一行就行，不过记得延长一下仿真时间，否则会很快出结果且LED全为1，因为默认的$10^6$ps还不足以让LED产生进位.

结果图大概长这样：

<center><img src = "../co/lab0/2.png" style = "zoom:60%"/></center>

### 添加约束文件

添加约束文件主要是两种方法，工具约束和脚本约束，比较推荐脚本约束。

#### 工具约束

上学期并没有讲过这个部分，但其实不麻烦，是在RTL Analysis的Schematic一节来完成，具体参见Slides.

#### 脚本约束

你也可以直接将给出的约束文件`Water_LED.xdc`加入到Constraint Sources中.

```verilog
set_property PACKAGE_PIN C12 [get_ports RSTn_i]
set_property IOSTANDARD LVCMOS33 [get_ports RSTn_i]
set_property PACKAGE_PIN H17 [get_ports {LED_o[0]}]
set_property IOSTANDARD LVCMOS33 [get_ports {LED_o[0]}]
set_property PACKAGE_PIN K15 [get_ports {LED_o[1]}]
set_property IOSTANDARD LVCMOS33 [get_ports {LED_o[1]}]
set_property PACKAGE_PIN J13 [get_ports {LED_o[2]}]
set_property IOSTANDARD LVCMOS33 [get_ports {LED_o[2]}]
set_property PACKAGE_PIN N14 [get_ports {LED_o[3]}]
set_property IOSTANDARD LVCMOS33 [get_ports {LED_o[3]}]
set_property PACKAGE_PIN E3 [get_ports CLK_i]
set_property IOSTANDARD LVCMOS33 [get_ports CLK_i]
```

实验文档里面怎么有一个不同约束文件的图？？？

## 自定义模块设计学习

