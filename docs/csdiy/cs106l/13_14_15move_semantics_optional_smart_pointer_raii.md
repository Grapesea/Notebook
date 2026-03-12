## Move Semantics（移动语义）

### 回顾：Copy 的问题

考虑一个管理动态内存的 class（例如一个自制的 `Vector`）：

```cpp
class MyVector {
    int* data;   // 指向 heap（堆）上的数组
    size_t size;
};
```

当你 copy 它时，默认的 copy constructor 只会做 **shallow copy（浅拷贝）**——**只复制指针本身，而不复制指针指向的数据**：

```
MyVector a  ──→  [1, 2, 3]  ← 在 heap 上
MyVector b  ──→  [1, 2, 3]  ← 同一块内存！！
```

结果：`a` 和 `b` 指向同一块内存. 当 `a` 析构时，内存被释放，`b` 就变成了 **dangling pointer（悬空指针）**，程序崩溃！

正确做法是写 **deep copy（深拷贝）**：**重新分配一块新内存，把数据完整复制过去**. 但这很慢（$O(n)$）.

### Move Semantics 的核心思想

> 如果原对象之后**不再需要**，为什么还要复制？直接把资源"偷过来"就好！

```cpp
MyVector a  ──→  [1, 2, 3]  ← heap
// move 之后：
MyVector b  ──→  [1, 2, 3]  ← 同一块内存（偷过来了）
MyVector a  ──→  nullptr    ← a 被清空，变成 "valid but unspecified state"
```

这叫 **move（移动）**，而不是 copy. 速度变成 $O(1)$！

### rvalue reference（右值引用）：`T&&`

要实现 move，需要区分"临时对象（可以偷走资源）"和"有名字的对象（不能随便动）".

| 种类  | 英文                             | 特点               | 例子                     |
| ----- | -------------------------------- | ------------------ | ------------------------ |
| `T&`  | lvalue reference（左值引用）     | 有名字、有内存地址 | `int x = 5; int& r = x;` |
| `T&&` | **rvalue reference（右值引用）** | 临时值、即将消亡   | `int&& r = 5 + 3;`       |

右值引用 `T&&` ：**"我知道这个对象是临时的，可以放心偷走它的资源"的标志.**

### Move Constructor 和 Move Assignment Operator

```cpp
class MyVector {
    int* data;
    size_t size;
public:
    // Move constructor（移动构造函数）
    MyVector(MyVector&& other) noexcept
        : data{other.data}, size{other.size}  // 偷走 other 的指针
    {
        other.data = nullptr;  // 把 other 清空，防止双重释放
        other.size = 0;
    }

    // Move assignment operator（移动赋值运算符）
    MyVector& operator=(MyVector&& other) noexcept {
        if (this != &other) {
            delete[] data;         // 先释放自己原来的资源
            data = other.data;     // 偷走 other 的指针
            size = other.size;
            other.data = nullptr;
            other.size = 0;
        }
        return *this;
    }
};
```

### `std::move`：强制转换为右值

```cpp
MyVector a = {1, 2, 3};
MyVector b = a;             // Copy：a 还在，复制了一份给 b
MyVector c = std::move(a);  // Move：a 的资源被"偷"给 c，a 变空
```

> `std::move` **并不真的"移动"任何东西**，它只是**把一个左值强制转型为右值引用**，告诉编译器"这个对象可以被移动走".

### Rule of Five（五法则）

如果你的 class 需要自定义以下任何一个，你**五个都应该定义**：

1. **Destructor** `~MyVector()`
2. **Copy constructor** `MyVector(const MyVector&)`
3. **Copy assignment operator** `operator=(const MyVector&)`
4. **Move constructor** `MyVector(MyVector&&)`
5. **Move assignment operator** `operator=(MyVector&&)`

---

## `std::optional` and Type Safety（可选类型与类型安全）

### 问题：函数失败时怎么表示"没有结果"？

考虑"解二次方程"——方程可能无解.旧的做法：

```cpp
// 方法1：用一个 bool 标记是否有解（很丑）
std::pair<bool, double> solve(double a, double b, double c);

// 方法2：返回 -1 表示无解（magic number，不清晰）
double solve(double a, double b, double c); // 返回 -1 代表无解?

// 方法3：用指针，nullptr 代表无解（容易产生悬空指针）
double* solve(double a, double b, double c);
```

这些都很丑陋，而且容易出错.

### 引入 `std::optional<T>`

`std::optional<T>` 就是一个"可能有值、也可能没有值"的包装器.

```cpp
#include <optional>

std::optional<double> divide(double a, double b) {
    if (b == 0) return std::nullopt;  // 没有结果
    return a / b;                     // 有结果
}

int main() {
    auto result = divide(10.0, 2.0);

    if (result.has_value()) {
        std::cout << result.value();  // 5
    }

    // 或者用 .value_or() 提供默认值
    std::cout << divide(10.0, 0.0).value_or(-1.0); // -1
}
```

### `std::optional` 的核心 API

| 方法           | 作用                     | 中文解释           |
| -------------- | ------------------------ | ------------------ |
| `std::nullopt` | 空值常量                 | 相当于"没有结果"   |
| `.has_value()` | 检查是否有值             | 判断结果是否存在   |
| `.value()`     | 取出值（无值则抛出异常） | 获取结果，不安全   |
| `.value_or(x)` | 有值取值，无值取默认 x   | 安全地获取结果     |
| `*opt`         | 解引用（不检查是否有值） | 像指针一样用，危险 |

### Type Safety（类型安全）的更广含义

类型安全的目标：**让错误在编译时被发现，而不是运行时崩溃**.

`std::optional` 强迫你在使用值之前**显式地检查是否存在**，而不是靠约定（"返回 -1 意味着失败"）.

```cpp
// 类型不安全：程序员忘记检查，直接用 -1 作为除数，运行时崩溃
double result = solve_old(1, 2, 5); // 可能是 -1
use(result); // 可能出问题

// 类型安全：编译器/类型系统强迫你检查
auto result = solve_new(1, 2, 5);
if (result) use(*result); // 不检查就无法用
```

------

## RAII, Smart Pointers, and Building C++ Projects

### 先理解问题：Raw Pointer（裸指针）的危险

在 C++ 里，手动管理内存（`new` / `delete`）非常危险：

```cpp
void foo() {
    int* p = new int{42};  // 在 heap 上分配内存
    
    // ... 某处代码抛出异常，或提前 return ...
    
    delete p;  // 这行可能永远执行不到！
}
// 结果：memory leak（内存泄漏）！
```

常见的内存错误：

| 错误名               | 中文       | 描述                          |
| -------------------- | ---------- | ----------------------------- |
| **memory leak**      | 内存泄漏   | 忘记 `delete`，内存永远占用   |
| **double free**      | 双重释放   | `delete` 同一块内存两次，崩溃 |
| **dangling pointer** | 悬空指针   | `delete` 后还继续使用该指针   |
| **use after free**   | 释放后使用 | 访问已被释放的内存            |

### RAII（Resource Acquisition Is Initialization）资源获取即初始化

> 核心思想：**把资源的生命周期绑定到对象的生命周期上**.构造时获取资源，析构时自动释放.

C++ 的 destructor（析构函数）**保证**在对象离开作用域时被调用，哪怕发生了异常.利用这一点：

```cpp
// 手动管理（危险）
{
    int* p = new int{42};
    // ... 如果这里抛出异常 ...
    delete p;  // 可能不被执行！
}

// RAII（安全）
{
    std::vector<int> v = {42};  // vector 内部用 RAII 管理内存
} // 离开作用域，vector 的 destructor 自动释放内存！
```

`std::vector`, `std::string`, `std::ifstream` 都是 RAII 的体现.

### Smart Pointers（智能指针）：RAII 用于指针

#### `std::unique_ptr<T>` — 独占所有权

- 同一时间只有**一个** `unique_ptr` 可以拥有某块资源
- 离开作用域自动 `delete`
- **不可以复制（copy）**，只可以**移动（move）**

```cpp
#include <memory>

void foo() {
    std::unique_ptr<int> p = std::make_unique<int>(42);
    // p 离开作用域时，自动 delete！不需要手动 delete
    
    // 转移所有权（move）
    std::unique_ptr<int> q = std::move(p);
    // 现在 q 拥有资源，p 变为 nullptr
    
    // p = q; // ❌ 编译错误！unique_ptr 不可复制
}
```

#### `std::shared_ptr<T>` — 共享所有权

- 多个 `shared_ptr` 可以指向同一块资源
- 内部有 **reference count（引用计数）**：记录有多少个 `shared_ptr` 指向这块内存
- 当引用计数降为 0 时，自动 `delete`

```cpp
std::shared_ptr<int> p = std::make_shared<int>(42);
std::shared_ptr<int> q = p;  // ✅ 可以复制，引用计数变为 2

// p 和 q 都离开作用域后，引用计数降到 0，内存自动释放
```

#### `std::weak_ptr<T>` — 弱引用（不增加引用计数）

- 用于打破 `shared_ptr` 的**循环引用（circular reference）**问题
- 不拥有资源，使用前要先 `lock()` 转为 `shared_ptr`

### `unique_ptr` vs `shared_ptr` 对比

| 特性     | `unique_ptr`       | `shared_ptr`      |
| -------- | ------------------ | ----------------- |
| 所有权   | 独占               | 共享              |
| 可复制？ | ❌                  | ✅                 |
| 可移动？ | ✅                  | ✅                 |
| 开销     | 极低（几乎零开销） | 有引用计数开销    |
| 适用场景 | 大多数情况         | 需要多个 owner 时 |

> **原则：优先使用 `unique_ptr`，只有确实需要共享所有权时才用 `shared_ptr`.**

### 三者的联系总结

```
Move Semantics
  → 让资源转移变得高效（O(1) 而不是 O(n)）
  → unique_ptr 就依赖 move 来转移所有权！

std::optional
  → 类型安全地表示"可能没有结果"
  → 属于 RAII 思想的延伸：optional 管理"值的存在性"

RAII + Smart Pointers
  → 用对象的生命周期来管理资源
  → unique_ptr 和 shared_ptr 是 RAII 在内存管理上的完美实现
```

一句话总结：**Move Semantics 让转移资源变快，`std::optional` 让"可能无值"变安全，RAII + Smart Pointers 让内存管理变自动**.这三个合在一起，就是现代 C++ 安全、高效编程的基础！