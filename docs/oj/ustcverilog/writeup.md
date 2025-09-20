### 基础

1. 输出1

    ```verilog
    module top_module(
        output out
    );
        assign out = 1;
    endmodule
    ```

2. 输出0

    ```verilog
    module top_module(
        output out
    );
        assign out = 0;
    endmodule
    ```

3. wire

    ```verilog
    module top_module(
        input in, output out
    );
        wire in, out; //其实只要编译通过的话，这句话也可以不写；
        assign out = in;
    endmodule
    ```

4. 多个端口的模块

    ```verilog
    module top_module( 
        input a,b,c,
        output w,x,y,z );
        wire w = a;
        wire x = b;
        wire y = b;
        wire z = c;
    endmodule
    ```

5. 非门

    ```verilog
    module top_module( input in, output out );
        assign out = ~in;
    endmodule
    ```

6. 与门

    ```verilog
    module top_module(
        input a, 
        input b,
        output out );
        assign out = a & b; //数据流级描述；
        
        // and a1(out,a,b); //门级描述；

        // always @(*)
        //     out = a & b; //行为级描述；
    endmodule
    ```

7. 或非门

    ```verilog
    module top_module( 
        input a, 
        input b, 
        output out );
     
        assign out = ~(a||b);
        
        // nor(out,a,b);

        // always @(*)
        //     out = ~(a||b);
    endmodule
    ```

8. 同或门

    ```verilog
    module top_module( 
        input a, 
        input b, 
        output out );
        wire t1 = ~a & ~b;
        wire t2 = a & b;
        assign out = (t1 || t2);

        // xnor(out,a,b); //直接用门级描述当然也可以 
    endmodule
    ```

9. 线网型中间信号

    ```verilog
    module top_module(
        input a,
        input b,
        input c,
        input d,
        output out,
        output out_n   
    ); 
        wire t1 = (a&b);
        wire t2 = (c&d);
        wire t3 = (t1||t2);
        assign out = t3;
        assign out_n = ~t3;
    endmodule
    ```

10. 向量

    ```verilog
    module top_module ( 
        input wire [2:0] vec,
        output wire [2:0] outv,
        output wire o2,
        output wire o1,
        output wire o0);
        assign outv = vec;  // 当然，为了严谨一点，写成assign outv = vec[2:0];也是对的
        assign o2 = vec[2];
        assign o1 = vec[1];
        assign o0 = vec[0];
    endmodule
    ```

11. 向量_续 1

    ```verilog
    `default_nettype none     // Disable implicit nets. Reduces some types of bugs.
    module top_module( 
        input	wire	[15:0]	in,
        output	wire	[7:0]	out_hi,
        output	wire	[7:0]	out_lo 
    );
        // Write your code here
        assign out_hi = in[15:8];
        assign out_lo = in[7:0];
    endmodule
    ```

12. 向量_续 2

    ```verilog
    module top_module(
    input [31:0] in,
    output [31:0] out
    );
    // assign out[31:24] = ...;
        assign out[31:24] = in[7:0];
        assign out[23:16] = in[15:8];
        assign out[15:8] = in[23:16];
        assign out[7:0] = in[31:24];
    endmodule
    ```

13. 位操作

    笨拙的写法：

    ```verilog
    module top_module( 
        input [2:0] a,
        input [2:0] b,
        output [2:0] out_or_bitwise,
        output out_or_logical,
        output [5:0] out_not
    );
        assign out_or_bitwise[2] = a[2] || b[2];
        assign out_or_bitwise[1] = a[1] || b[1];
        assign out_or_bitwise[0] = a[0] || b[0];
        
        assign out_or_logical = a || b;
        assign out_not[5] = ~b[2];
        assign out_not[4] = ~b[1];
        assign out_not[3] = ~b[0];
        assign out_not[2] = ~a[2];
        assign out_not[1] = ~a[1];
        assign out_not[0] = ~a[0];
    endmodule
    ```

    优雅的写法：

    ```verilog
    module top_module( 
        input [2:0] a,
        input [2:0] b,
        output [2:0] out_or_bitwise,
        output out_or_logical,
        output [5:0] out_not
    );

        assign out_or_bitwise = a | b;
        assign out_or_logical = a || b;
        assign out_not = {~(b),~(a)}; //这就是向量拼接

    endmodule
    ```

14. 位操作

    ```verilog
    module top_module( 
        input [3:0] in,
        output out_and,
        output out_or,
        output out_xor
    );
        and(out_and, in[3], in[2], in[1], in[0]);
        or(out_or, in[3], in[2], in[1], in[0]);
        xor(out_xor, in[3], in[2], in[1], in[0]);

        // 还有一种写法是：
        // assign out_and = &in;
        // assign out_or = |in;
        // assign out_xor = ^in;

    endmodule
    ```

> 1-14: 9.20花了1h不到写完.

15. 
