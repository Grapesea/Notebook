??? info "参考资料与验收要求"

    [Wintermelon的笔记](https://wintermelonc.github.io/WintermelonC_Docs/zju/compulsory_courses/computer_organization/lab/lab4/)
    $\quad$
    [计算机组成与设计-2024年lab4](https://guahao31.github.io/2024_CO/Lab4/)

    验收要求：

    <center><img src = "../lab4/check.png" style = "zoom:50%"/></center>

## 4-0 CPU核集成设计

首先建构`SCPU.v`，并且将`DataPath.v`,`SCPU_ctrl.v`,`DataPath.edf`,`SCPU_ctrl.edf`文件导入.

`SCPU.v`如下：

??? tips "SCPU.v"
    ```verilog
    module SCPU(
        input wire MIO_ready,
        input wire [31:0] Data_in,
        input wire clk,
        input wire [31:0] inst_in,
        input wire rst,
        output wire MemRW,
        output wire CPU_MIO,
        output wire [31:0] Addr_out,
        output wire [31:0] Data_out,
        output wire [31:0] PC_out
        );

        wire [1:0] ImmSel;
        wire Jump;
        wire Branch;
        wire RegWrite;
        wire [2:0] ALU_Control;
        
    SCPU_ctrl U1(
        .Opcode     (inst_in[6:2]),
        .Fun3       (inst_in[14:12]),
        .Fun7       (inst_in[30]),
        .MIO_ready  (MIO_ready),
        .ImmSel     (ImmSel),
        .ALUSrc_B   (ALUSrc_B),
        .MemtoReg   (MemtoReg),
        .Jump       (Jump),
        .Branch     (Branch),
        .RegWrite   (RegWrite),
        .MemRW      (MemRW),
        .ALU_Control(ALU_Control),
        .CPU_MIO    (CPU_MIO)
    );
    DataPath U2(
        .ALUSrc_B   (ALUSrc_B),
        .ALU_Control(ALU_Control),
        .Branch     (Branch),
        .Data_in    (Data_in),
        .ImmSel     (ImmSel),
        .Jump       (Jump),
        .MemtoReg   (MemtoReg),
        .RegWrite   (RegWrite),
        .clk        (clk),
        .inst_field (inst_in),
        .rst        (rst),
        .ALU_out    (Addr_out),
        .Data_out   (Data_out),
        .PC_out     (PC_out)
    );
    endmodule
    ```

## 4-1 CPU设计之数据通路

看起来是需要写好`SCPU_ctrl.v`和`ImmGen.v`并组合成一个不完全版的数据通路.

??? tips "ImmGen.v"
    ```verilog
    module ImmGen(
        input [1:0]   ImmSel,
        input [31:0]  inst_field,
        output reg [31:0] Imm_out
    );

    always @(*) begin
        case(ImmSel)
            2'b00: begin
                    // I-Type: imm[11:0] = inst[31:20]
                    // 符号扩展到32位
                    Imm_out = {{20{inst_field[31]}}, inst_field[31:20]};
                end
            2'b01: begin
                    // S-Type: imm[11:5] = inst[31:25], imm[4:0] = inst[11:7]
                    // 符号扩展到32位
                    Imm_out = {{20{inst_field[31]}}, inst_field[31:25], inst_field[11:7]};
                end
            2'b10: begin
                    // B-Type: imm[12|10:5|4:1|11] = inst[31|30:25|11:8|7]
                    // imm[0] = 0 (最低位始终为0，因为分支地址是2字节对齐)
                    // 符号扩展到32位
                    Imm_out = {{19{inst_field[31]}}, inst_field[31], inst_field[7], 
                            inst_field[30:25], inst_field[11:8], 1'b0};
                end
            2'b11: begin
                    // J-Type (JAL): imm[20|10:1|11|19:12] = inst[31|30:21|20|19:12]
                    // imm[0] = 0 (最低位始终为0)
                    // 符号扩展到32位
                    Imm_out = {{11{inst_field[31]}}, inst_field[31], inst_field[19:12], 
                            inst_field[20], inst_field[30:21], 1'b0};
                end
            default: begin
                    Imm_out = 32'b0;
                end
            endcase
        end
    endmodule
    // ImmSel 为 0 时，生成 I-Type 指令的立即数；
    // 为 1 时，生成 S-Type 指令的立即数；
    // 为 2 时，生成 B-Type 指令的立即数；
    // 为 3 时，生成 J-Type 指令的立即数
    ```

目前还在思考SCPU.v怎么办以及指令的实现.

## 4-2 CPU设计之控制器

## 4-3 CPU设计之指令扩展

## 4-4 CPU设计之中断
