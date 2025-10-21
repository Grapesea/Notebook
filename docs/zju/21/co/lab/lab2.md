??? tips "验收要求"

    实验目的：建立一个调试CPU模块的环境，后续lab4会对SCPU模块单独构造，然后替换lab2实验中的SCPU部分，再在本实验中搭建的环境中测试SCPU功能。即lab2只需要在顶层模块中组织各子模块即可，各子模块功能只需要大概了解即可.

    验收需要在数码管和VGA上显示`I_mem.coe`的功能：

    * 数码管上：
        
        调整SW[8], SW[2] = 0, 1；观察单步时钟的结果；
        
        调整SW[8], SW[2] = 1, 0；来回拨动SW[10]观察手动调试的结果；
        
        通过调整SW[7:5]，观察`alu_res`，`pc`，`inst`等输出；
    
    * VGA上：
        
        主要观察内容：`alu_res`的结果为`alu`输出；PC显示的是字节地址，每次增加4；`inst`为指令内容；

        逻辑图中VGA模块的输入包含被显示的内容，显示器上其他部分（如寄存器组）没有接入VGA因此显示全0.

    注意PPT P89的复位按键，可以将PC置0，即demo程序从头开始运行.

参考文献：[瓜豪的2024CO文档](https://guahao31.github.io/2024_CO/Lab2/Lab2/)

??? notes "如何使用Tcl Console进行综合"

    Synthesis:

    ```bash
    reset_run synth_1
    launch_runs synth_1 -jobs 4
    wait_on_run synth_1
    # 检查综合是否真的在运行
    # 运行综合后，在 Tcl Console 中应该看到类似输出：
    launch_runs synth_1 -jobs 4
    [Sat Oct 18 XX:XX:XX 2025] Launched synth_1...
    Run output will be captured here: ...
    ```

    Implementation:
    
    ```bash
    # 重置 implementation 运行
    reset_run impl_1

    # 运行 implementation
    launch_runs impl_1 -jobs 4

    # 等待完成
    wait_on_run impl_1
    ```

!!! warning "实验吐槽"

    首先是犯下了傲慢之罪的Windows，得益于他们的更新，我的Vivado驱动被删除了；

    其次是糟糕的Vivado版本兼容问题，我为了不踩坑，把曾经嫌弃的Vivado 2024.2下载回来了，然后IP Core全部都要重新生成一遍；

    最后是设备，我没招了，经常连接不好……一个原本能10.14完成的lab硬是多拖了5天.

## IP核集成SOC设计——建立CPU调试、测试与应用环境

### 添加文件

* `Seg7_Dev_0`：添加IP Catalog中的IP核

    在Vivado中打开项目`OExp02-IP2SOC`，在`Flow Navigator`中点击`Settings`选择`IP → Repository`，点击`+`按钮，浏览到 `OExp02-IP2SOC/IP/`目录，选择包含IP核的`Seg7_Dev_0`文件夹（包含component.xml的目录）.<br>
    点击`Select`，Vivado会自动扫描并识别IP核，点击`OK`完成添加.<br>
    然后在左边栏中点击`IP Catalog`，搜索并找到你添加的IP，右键选择`Customize IP`，点击`Generate`即可.

* 顶层目录中的`.edf`和`.v`文件：直接`Add Design Sources`就行.

* VGA模块：添加其中的srcs里面所有的`.v`文件.

### IP Core的生成与文件关联

我们需要生成以下模块：Distributed Memory Generator. 它会在下面部分的<del>煎熬的</del>连线中使用到.

只需要按照lab0中的ROM生成方法操作就行了.

### 添加顶层模块`CSSTE.v`并连线

写了一份demo，眼睛快花了，这个应该是没问题的版本：

??? tips "CSSTE.v完整代码"
    ```verilog
    module CSSTE(
        input         clk_100mhz,
        input         RSTN,
        input  [3:0]  BTN_y,
        input  [15:0] SW,
        output [3:0]  Blue,
        output [3:0]  Green,
        output [3:0]  Red,
        output        HSYNC,
        output        VSYNC,
        output [15:0] LED_out,
        output [7:0] AN,
        output [7:0] segment
    );
    wire [3:0] BTN_OK;
    wire [15:0] SW_OK;
    wire rst;

    SAnti_jitter U9(
        .clk(clk_100mhz), 
        .RSTN(RSTN), 
        .readn(1'b0), 
        .Key_y(BTN_y), 
        .Key_x(), 
        .SW(SW), 
        .Key_out(), 
        .Key_ready(Key_ready), 
        .pulse_out(), 
        .BTN_OK(BTN_OK), 
        .SW_OK(SW_OK), 
        .CR(), 
        .rst(rst)
    );
    
    wire [31:0] clkdiv;
    wire Clk_CPU;
    
    clk_div U8(
        .clk(clk_100mhz),
        .rst(rst),
        .SW2(SW_OK[0]),
        .SW8(SW_OK[0]),
        .STEP(SW_OK[0]),
        .clkdiv(clkdiv),
        .Clk_CPU(Clk_CPU)
    );
    wire [31:0] Cpu_data4bus;
    wire MemRW;
    wire [31:0] Addr_out;
    wire [31:0] Data_out;
    wire [31:0] PC_out;
    wire [31:0] inst_in;
    wire CPU_MIO;
    wire MIO_ready;
    
    SCPU U1(
        .clk(Clk_CPU),
        .rst(rst),
        .Data_in(Cpu_data4bus),
        .inst_in(inst_in),
        .MIO_ready(MIO_ready),
        .MemRW(MemRW),
        .Addr_out(Addr_out),
        .Data_out(Data_out),
        .PC_out(PC_out),
        .CPU_MIO(CPU_MIO)
    );
    
    wire [31:0] data_ram_we;
    wire [9:0] ram_addr;
    wire [31:0] ram_data_in;
    wire [31:0] ram_data_out;
    wire [31:0] douta;
    wire [31:0] Peripheral_in;
    wire counter_we;
    wire [1:0] counter_set;
    wire [31:0] counter_out;
    wire counter0_OUT;
    wire counter1_OUT;
    wire counter2_OUT;
    wire EN;
    wire FN;

    MIO_BUS U4(
        .clk(clk_100mhz), 
        .rst(rst), 
        .BTN(BTN_OK), 
        .SW(SW_OK), 
        .mem_w(MemRW), 
        .Cpu_data2bus(Data_out), 
        .addr_bus(Addr_out), 
        .ram_data_out(ram_data_out), 
        .led_out(LED_out), 
        .counter_out(counter_out), 
        .counter0_out(counter0_OUT), 
        .counter1_out(counter1_OUT), 
        .counter2_out(counter2_OUT), 
        .Cpu_data4bus(Cpu_data4bus), 
        .ram_data_in(ram_data_in), 
        .ram_addr(ram_addr), 
        .data_ram_we(data_ram_we), 
        .GPIOf0000000_we(FN), 
        .GPIOe0000000_we(EN), 
        .counter_we(counter_we),
        .Peripheral_in(Peripheral_in)
    );

    Counter_x U10(
        .clk(~Clk_CPU), 
        .rst(rst), 
        .clk0(clkdiv[6]), 
        .clk1(clkdiv[9]), 
        .clk2(clkdiv[11]), 
        .counter_we(counter_we), 
        .counter_val(Peripheral_in), 
        .counter_ch(counter_set), 
        .counter0_OUT(counter0_OUT),
        .counter1_OUT(counter1_OUT), 
        .counter2_OUT(counter2_OUT), 
        .counter_out(counter_out)
    );
   
    wire [7:0] LE_out;
    wire [31:0] Disp_num;
    wire [7:0] point_out;

    Multi_8CH32 U5(
        .clk(~Clk_CPU), 
        .rst(rst), 
        .EN(EN), 
        .Test(SW_OK[7:5]), 
        .point_in({clkdiv[31:0],clkdiv[31:0]}), 
        .LES(64'b0), 
        .Data0(Peripheral_in), 
        .data1({2'b0,PC_out[31:2]}), 
        .data2(inst_in), 
        .data3(counter_out),
        .data4(Addr_out), 
        .data5(Data_out), 
        .data6(Cpu_data4bus), 
        .data7(PC_out), 
        .point_out(point_out), 
        .LE_out(LE_out), 
        .Disp_num(Disp_num)
    );
   
    Seg7_Dev_0 U6(
        .disp_num(Disp_num),
        .point(point_out),
        .les(LE_out),
        .scan({clkdiv[18],clkdiv[17],clkdiv[16]}),
        .AN(AN),
        .segment(segment)
    );
   
    SPIO U7(
        .clk(~Clk_CPU),
        .rst(rst),
        .Start(clkdiv[20]),
        .EN(FN),
        .P_Data(Peripheral_in),
        .counter_set(counter_set),
        .LED_out(LED_out),
        .led_clk(),
        .led_sout(),
        .led_clrn(),
        .LED_PEN(),
        .GPIOf0()
    );

    VGA U11(
        .clk_25m(clkdiv[1]),
        .clk_100m(clk_100mhz),
        .rst(rst),
        .pc(PC_out),
        .inst(inst_in),
        .alu_res(Addr_out),
        .mem_wen(MemRW),
        .dmem_o_data(ram_data_out),
        .dmem_i_data(ram_data_in),
        .dmem_addr(Addr_out),
        .hs(HSYNC),
        .vs(VSYNC),
        .vga_r(Red),
        .vga_g(Green),
        .vga_b(Blue)
    );
   
    RAM_B U3(
        .clka(~clk_100mhz),
        .wea(data_ram_we),
        .addra(ram_addr),
        .dina(ram_data_in),
        .douta(ram_data_out)
    );
   
    I_mem U2(
        .a(PC_out[11:2]),
        .spo(inst_in)
    );

    endmodule
    ```

## VGA处理

打开`VGAdisplay.v`:

??? tips "VGAdisplay.v代码"
    ```verilog
    module VgaDisplay(
        input wire clk,
        input wire video_on,
        input wire [9:0] vga_x,
        input wire [8:0] vga_y,
        output wire [3:0] vga_r,
        output wire [3:0] vga_g,
        output wire [3:0] vga_b,
        input wire wen,
        input wire [11:0] w_addr,
        input wire [7:0] w_data
    );

        (* ram_style = "block" *) reg [7:0] display_data[0:4095];
        initial $readmemh("D://vga_debugger.mem", display_data);

        wire [11:0] text_index = (vga_y / 16) * 80 + vga_x / 8;
        // I don't know why I need this '- (vga_y / 16)' ...
        wire [7:0] text_ascii = display_data[text_index] - (vga_y / 16);
        wire [2:0] font_x = vga_x % 8;
        wire [3:0] font_y = vga_y % 16;
        wire [11:0] font_addr = text_ascii * 16 + font_y;

        (* ram_style = "block" *) reg [7:0] fonts_data[0:4095];
        initial $readmemh("D://font_8x16.mem", fonts_data);
        wire [7:0] font_data = fonts_data[font_addr];

        assign { vga_r, vga_g, vga_b } = (video_on & font_data[7 - font_x]) ? 12'hfff : 12'h0;

        always @(posedge clk) begin
            if (wen) begin
                display_data[w_addr] <= w_data;
            end
        end
    endmodule
    ```

修改其中的两个路径：（比如我是这么存的）

```verilog
    ···
    initial $readmemh("E://Vivadodemo//lab2//OExp02-IP2SOC//vga_debugger.mem", display_data);
    ···
    initial $readmemh("E://Vivadodemo//lab2//OExp02-IP2SOC//font_8x16.mem", fonts_data);
    ···
```

## 下板
