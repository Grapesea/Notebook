!!! info "slides地址"

    [Lec 1: Welcome](https://web.stanford.edu/class/archive/cs/cs106l/cs106l.1226/lectures/lecture1_spr.pdf)

### CS106L简介

与CS106B比较：

<center><img src="../figures/intro/0.png" alt="0" style="zoom: 40%;" /></center>

### C++简介

这三个都是C++能编译通过的代码：

??? tips "Ccde 1: 标准C++"

    ```cpp
    #include <iostream>
    int main() {
        std::cout << "Hello, world!" << std::endl;
    return 0;
    }
    ```

??? tips "Code 2: 类C"

    ```cpp
    #include "stdio.h"
    #include "stdlib.h"
    int main(int argc, char *argv) {
        printf("%s", "Hello, world!\n");
        // ^a C function!
    return EXIT_SUCCESS;
    }
    ```

??? tips "Code 3: 汇编"

    ```cpp
    #include "stdio.h"
    #include "stdlib.h"
    int main(int argc, char *argv) {
    asm(  
    "sub    $0x20,%rsp\n\t"             // assembly code!
    "movabs $0x77202c6f6c6c6548,%rax\n\t"
    "mov    %rax,(%rsp)\n\t"
    "movl   $0x646c726f, 0x8(%rsp)\n\t"
    "movw   $0x21, 0xc(%rsp)\n\t"
    "movb   $0x0,0xd(%rsp)\n\t"
    "leaq    (%rsp),%rax\n\t"
    "mov    %rax,%rdi\n\t"
    "call  __Z6myputsPc\n\t"
    "add    $0x20, %rsp\n\t"
        );
    return EXIT_SUCCESS;
    }
    ```

C 的劣势：

* No objects or classes
* Difficult to write generic code
* Tedious when writing large programs

C++希望做到的（设计哲学）：

<center><img src="../figures/intro/1.png" alt="0" style="zoom: 40%;" /></center>

STL库的优越性：

* Tons of general functionality
* Built in classes like maps, sets, vectors
* Accessed through the namespace `std::`
* **Extremely powerful and well-maintained**
