# 模拟面试1-with豆包

- [ ] 你的技术栈有哪些？

    回答模板：

    - **编程语言**：精通 C++（11/14/17/20 均有项目经验），熟悉 Python、Shell，了解 Java.
    - **系统**：Linux 环境开发，计算机组成与体系结构
    - **数据结构与算法**：STL 容器与算法
    - **工具链**：GCC/Clang，CMake，GDB，Valgrind，Git，Docker
    - **领域知识**：网络安全的密码学
    - 机器学习、深度学习的初步知识

    ---

- [ ] `std::vector` 如何扩容

    回答模板：

    * `std::vector`是一个动态的数组，在`size() == capacity()`并且insert新元素的时候触发扩容.
    * 通常以1.5倍或者2倍的增长因子分配新的内存
    * 过程是分配新的更大的内存块，将旧的元素拷贝/移动到新的内存中（如果 `noexcept` 则移动，否则拷贝）；析构旧元素，释放旧内存；更新内部指针. （`noexcept`是C++11引入的）

    ---

- [ ] `virtual` 是做什么的

    回答模板：

    * 是用来实现多态的.
    * 声明了虚函数，允许在基类指针/引用调用的时候动态绑定到派生类的重写函数.
    * 

    ---

- [ ] 解释这里面的各种声明关键字的含义： 

    `virtual const char* GetWordName() const noexcept override;`

    回答模板：

    * `virtual`：声明是虚函数，支持多态；
    * `const char*`：返回类型是指向常量字符的指针；
    * `const`：这个成员函数不会修改对象的成员变量，承诺逻辑上不变；
    * `noexcept`：承诺不抛出异常，编译器可以据此优化，一旦抛出则调用`std::terminate`；移动构造/赋值最好用这个标记来获得性能的优化.
    * `override`：显式指明该函数重写了基类虚函数，如果基类无匹配则编译报错

    ---

- [ ] `new`/`delete`和`malloc`/`free`的区别？

    回答模板：

    | 特性      | `new` / `delete`                                 | `malloc` / `free`              |
    | :-------- | :----------------------------------------------- | :----------------------------- |
    | 语言      | C++ 运算符                                       | C 标准库函数                   |
    | 类型      | 类型安全，返回正确类型指针                       | 返回 `void*`，需强制转换       |
    | 构造/析构 | `new` 调用构造函数，`delete` 调用析构函数        | 仅分配/释放内存，不调构造/析构 |
    | 大小      | 编译器自动计算                                   | 需手动指定字节数               |
    | 重载      | 可重载 `operator new`/`operator delete`          | 不可重载                       |
    | 错误处理  | 默认抛 `std::bad_alloc` 异常（`nothrow` 返回空） | 返回 `NULL`                    |
    | 分配失败  | 可通过 `set_new_handler` 处理                    | 必须检查返回值                 |

    * `new`/`delete`，`new[]`/`delete[]`必须配对，不能混用；
    * `malloc`分配对象时构造函数不会调用，对象未初始化；
    * `new`的底层实现常调用`malloc`，但是允许自定义内存管理.

    ---

- [ ] 环境变量是什么？

    回答模板：

    * 操作系统维护的**键值对**，存储系统和用户配置信息，影响进程行为.

    - 每个进程从父进程继承环境变量副本（在 `execve` 时可选择传递）.
    - 常见：`PATH`（可执行文件搜索路径）、`HOME`、`USER`、`LD_LIBRARY_PATH` 等.
    - 在 C/C++ 中可通过 `getenv()` 获取，`setenv()`/`putenv()` 修改（仅影响当前进程及子进程）.
    - Shell 中设置：`export VAR=value`.

    ---

- [ ] Linux的信息指的是什么？

    回答模板：

    Linux系统中的信息指

    1. **系统信息**：如内核版本、CPU、内存、磁盘等硬件和操作系统信息
    2. **进程信息**：通过 `/proc` 文件系统暴露的进程状态、资源占用等

    ---

- [ ] `std::unordered_map` 和 `std::map` 区别？

    回答模板：

    ---

- [ ] `std::map` 中 `insert` 和使用索引`[]`的区别

    回答模板：

    ---

- [ ] lambda 函数是什么，如何获取外部变量？

    回答模板：

    ---

- [ ] 显式类型转换有哪些？各自是什么情况？跟隐式类型转换相比的区别？

    回答模板：

    1. **`static_cast`**
        - 编译时检查，相关类型转换，如基本类型、`void*` 来回、基类与派生类指针/引用（上行安全，下行不检查）、隐式转换反向
        - 不能移除 const，不能用于完全不相关指针转换
    2. **`dynamic_cast`**
        - 运行时检查，用于多态类型的**安全向下转换**（基类指针/引用转派生类）
        - 要求基类有虚函数。失败时指针返回 `nullptr`，引用抛 `std::bad_cast`
        - 开销较大
    3. **`const_cast`**
        - 仅用于移除或添加 const/volatile 属性
        - 常用于接口适配，但修改原 const 对象是未定义行为（除非原对象非 const）
    4. **`reinterpret_cast`**
        - 危险的低层次转换，直接按位重新解释. 如指针与整型互转、不同指针类型互转
        - 不改变地址值，不进行任何类型调整，平台相关，极易出错

    ---

- [ ] 如果想要将`std::list`转换成`std::vector`，应该用什么转换方式？

    回答模板：

    * 利用迭代器范围构造（`std::vector` 的模板构造函数，接收两个迭代器，将范围内的元素逐一拷贝到 `vector`）

        ```cpp
        std::list<int> lst = {1, 2, 3};
        std::vector<int> vec(lst.begin(), lst.end());
        ```

    * 使用`std::copy` + `back_inserter`：

        ```cpp
        std::vector<int> vec;
        vec.reserve(lst.size());
        std::copy(lst.begin(), lst.end(), std::back_inserter(vec));
        ```

    * 还可以移动构造：

        ```cpp
        std::vector<int> vec(std::make_move_iterator(lst.begin()),
                              std::make_move_iterator(lst.end()));
        ```

        

    ---

- [ ] 系统级调用是什么？

    回答模板：

    * system call是**用户态程序请求操作系统内核服务的接口**，用户程序通过系统调用从内核获取资源或执行特权操作
    * 

    ---

- [ ] `enum`和`enum class`之间的区别是什么？

    回答模板：

    * `enum`是无作用域枚举，`enum class`是有作用域枚举，也叫强类型枚举，C++11引入，用于解决传统`enum`的缺陷.

    * `enum`枚举成员名会被**注入到外围作用域**，容易发生命名冲突;

        `enum class`：枚举成员名位于枚举类型的**独立作用域**内，必须通过枚举类型名限定访问，彻底杜绝冲突

        ```c++
        enum Color { red, green, blue };
        enum TrafficLight { red, yellow, green }; // 编译错误！red, green 重复定义
        
        enum class Color { red, green, blue };
        enum class TrafficLight { red, yellow, green }; // OK，完全独立
        Color c = Color::red;
        ```

    * `enum`可以隐式转换，容易混用；

        `enum class`：**禁止任何隐式转换**，既不能隐式转为整型，也不能从整型隐式转换构造。必须显式使用 `static_cast`

        ```c++
        enum Color { red, green, blue };
        int x = red;              // OK
        Color c = 2;              // OK，但危险（整数直接赋值）
        if (c == 1) { /*...*/ }   // 编译通过，但语义模糊
        
        enum class Color { red, green, blue };
        int x = Color::red;       // 错误！不存在隐式转换
        int x = static_cast<int>(Color::red); // OK
        Color c = 2;              // 错误！
        Color c = static_cast<Color>(2);      // OK，需要显式转换
        ```

        