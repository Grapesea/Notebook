!!! tips 

    助教哥哥给出的验收要求：

    1. 注意`srl`操作对应：`A >> B[4:0]`;

    2. ALU仿真波形PPT1 19

        * 需要按两种⽅式实现ALU：
        
            （1）结构化描述的ALU（⼦模块调⽤的⽅法，见后续PPT⻚）；
            
            （2）功能性描述的ALU（见后续PPT⻚）

            （3）可选：采用逻辑原理图输入设计ALU

        * 两种⽅式实现ALU的都需要仿真测试得到PPT1 15⻚所示波形

        * 对应仿真激励⽂件可以参考：`lab1\OExp01\OExp01-ALU\OExp01-ALU.srcs\sim_1\new\ALU_tb.v`

    3. regfile仿真结果（PPT1 21）

        * 对应仿真激励⽂件可以参考：`lab1\OExp01\OExp01-Regs\OExp01-Regs.srcs\sim_1\new\Regs_tb.v`

    4. 三段式状态机仿真波形（PPT2 23）

        * 对应仿真激励⽂件可以参考：`lab1\OExp01\OExp01-seq_moore\seq_moore.srcs\sim_1\new\tb.v`

## ALU, Regfiles设计

### 设计实现数据通路部件ALU：采用原理图的设计方法

<del>这部分的实验文档用“颠三倒四”来形容不为过。</del>

ALU在数逻lab8中已经出现过. 此处需要新建一个项目将lab0中的一堆`.v`代码导入，再自己写一个顶层代码综合起来.

考虑到我一点也不想生成IP核，最后选择了顶层代码书写的方法.

```verilog

```