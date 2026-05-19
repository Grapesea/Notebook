## Lambda Functions

lambda 函数相当于一个functor，其基础格式：

```cpp
auto lessThanN = [n](int x) { return x < n; };
//               ^^^  ^^^^^   ^^^^^^^^^^^^^^^^
//             capture  参数       函数体
```

capture方式：

```cpp
[x]       // 按值捕获 x（复制一份，改了外面的x，lambda里不会变）
[x&]      // 按引用捕获 x（外面改了，lambda里也会变）
[x, y]    // 同时按值捕获 x 和 y
[&]       // 按引用捕获所有外部变量
[=]       // 按值捕获所有外部变量
```

本质上，编译器将其改成了一个匿名的class：

```cpp
class __lambda_6_18 {
public:
    bool operator()(int x) const { return x < n; }
    __lambda_6_18(int& _n) : n{_n} {}
private:
    int n;   // capture 的变量变成了 class 的 field！
};
```

## operator overloading

常见2种：

### member function

左操作数是本 class 的对象.

```cpp
class Vector2D {
public:
    double x, y;
    
    // this + other
    Vector2D operator+(const Vector2D& other) const {
        return {x + other.x, y + other.y};
    }
    
    // this == other
    bool operator==(const Vector2D& other) const {
        return x == other.x && y == other.y;
    }
};

Vector2D a{1, 2}, b{3, 4};
Vector2D c = a + b; // 调用 a.operator+(b)
```

### Non-member function

适合 `<<` 这类 stream operators，因为左边是 `std::ostream`，不是当前 class： 

```cpp
// 放在 class 外面
std::ostream& operator<<(std::ostream& os, const Vector2D& v) {
    os << "(" << v.x << ", " << v.y << ")";
    return os; // 要返回 os，才能链式调用 
}

Vector2D v{3, 4};
std::cout << v; // 输出：(3, 4)
```

### Functor(`operator()`)

```cpp
template <typename T>
struct std::greater {
    bool operator()(const T& a, const T& b) const {
        return a > b;
    }
};

std::greater<int> g;
g(5, 3); // true，像调用函数一样！
```

## special member function

一共6个，在编译时会自动生成.

| 函数                          | 英文名                                         | 何时触发                  |
| ----------------------------- | ---------------------------------------------- | ------------------------- |
| `ClassName()`                 | **Default constructor（默认构造函数）**        | 创建对象时没有参数        |
| `~ClassName()`                | **Destructor（析构函数）**                     | 对象销毁时                |
| `ClassName(const ClassName&)` | **Copy constructor（拷贝构造函数）**           | 用另一个对象来初始化      |
| `operator=(const ClassName&)` | **Copy assignment operator（拷贝赋值运算符）** | 用 `=` 赋值给已存在的对象 |
| `ClassName(ClassName&&)`      | **Move constructor（移动构造函数）**           | 从临时对象初始化          |
| `operator=(ClassName&&)`      | **Move assignment operator（移动赋值运算符）** | 用 `=` 移动赋值           |

- **Copy（拷贝）**：像"复印"，原件保留，得到一份新的副本。资源被**复制**。
- **Move（移动）**：像"搬家"，把原对象的资源"偷走"，原对象变成空的。**更高效**，不需要重新分配内存。

```cpp
std::vector<int> v1 = {1, 2, 3};
std::vector<int> v2 = v1;             // Copy：v1 和 v2 都有数据
std::vector<int> v3 = std::move(v1);  // Move：v3 有数据，v1 变空了
```

默认的 **copy constructor** 会逐个 field 地复制（称为 **memberwise copy**）。对于简单的 class 这没问题，但如果你的 class 内部有**裸指针（raw pointer）**管理动态内存，就会出大问题——两个对象指向同一块内存，其中一个析构时会把内存释放，另一个就变成悬空指针！

这就是为什么要讲如何自定义这些函数的原因.