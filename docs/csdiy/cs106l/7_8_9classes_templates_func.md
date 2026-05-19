## Classes

### class封装格式

> "A struct simply feels like an open pile of bits with very little in the way of encapsulation or functionality. A class feels like a living and responsible member of society with intelligent services, a strong encapsulation barrier, and a well defined interface." - Bjarne Stroustrup

Class 可以设定 private 和 public 2个部分，使得功能与参数能够被分置设定好.

???+ tips "eg. Student.h"

    ```cpp
    // Student.h
    #ifndef STUDENT_H
    #define STUDENT_H
    class Student {
        public:
            std::string getName();
            void setName(string name);
            int getAge();
            void setAge(int age);
        private:
            std::string name;
            std::string state;
            int age;
    };
    #endif
    ```
    
    ```cpp
    // Student.cpp
    #include "Student.h"
    std::string Student::getName(){
        // Some implementations.
    }
    void Student::setName(string name){
        // ...
    }
    int Student::getAge(){
        // ...
    }
    void Student::setAge(int age){
        // ...
    }
    ```

public部分：可以立即使用student的任何功能与参数，同时定义了与private member variables 交互的入口.

private部分：包含所有的参数，无法取得或者修改其中的值.

### `this`关键字

为了将private member variable与参数名区分开，引入的新功能.

假定我们希望引入参数name，变量名也是name，原先会引发困惑的地方：

```cpp
void Student::setName(string name){
    name = name; //huh?
}
```

使用了`this`关键字之后：

```cpp
void Student::setName(string name){
    this->name = name; //better!
}
```

所以函数实现文件：

```cpp
#include "Student.h"
    std::string Student::getName(){
        return name;
    }
    void Student::setName(string name){
        this->name = name;
    }
    int Student::getAge(){
        return age;
    }
    void Student::setAge(int age){
        if(age >= 0){
            this -> age = age;
        }else{
            std::cerr << "Age should be > 0 !" << std::endl;
        }
    }
```

### Constructors (构造函数)

是对class进行初始化的函数.

```cpp
Student::Student(){
    age = 0;
    name = "";
    state = "";
}
```

相应有destructors:

```cpp
int *intarray;
intarray = new int[10];
int element = intarray[0];

delete [] intarray;
```

一般以`Class_name::~Class_name()`形式出现，只需要在`.h`中实现，不需要特意调用，因为在超出使用域之后会自动析构.

### Template Class

是一种泛型编程工具，允许编写与类型无关的代码.

原先可能需要两种class来包括不同的数据类型：

```cpp
class IntVector{
    int* data;
    // ...
};

class DoubleVector{
    double* data;
    // ...
};
```

现在可以改成这样的格式：

```cpp
template <class T>
class Vector{
    T* data;
    // ...
};
```

其中`T`表示`int`等变量类型.

举个例子（OOP的[lab6](../../zju/21/oop/lab/6.md)）：

???+ tips "Vector.h"

    ```cpp
    #ifndef VECTOR_H
    #define VECTOR_H
    
    template <class T>
    class Vector {
    public:
        Vector();                      // creates an empty vector
        Vector(int size);              // creates a vector for holding 'size' elements
        Vector(const Vector& r);       // the copy ctor
        ~Vector();                     // destructs the vector 
        T& operator[](int index);      // accesses the specified element without bounds checking
        T& at(int index);              // accesses the specified element, throws an exception of
                                    // type 'std::out_of_range' when index <0 or >=m_nSize
        int size() const;              // return the size of the container
        void push_back(const T& x);    // adds an element to the end 
        void clear();                  // clears the contents
        bool empty() const;            // checks whether the container is empty 
    private:
        void inflate();                // expand the storage of the container to a new capacity,
                                    // e.g. 2*m_nCapacity
        T *m_pElements;                // pointer to the dynamically allocated storage
        int m_nSize;                   // the number of elements in the container
        int m_nCapacity;               // the total number of elements that can be held in the
                                    // allocated storage
    };
    
    template <class T> Vector<T>::Vector() : m_pElements(nullptr), m_nSize(0), m_nCapacity(0) {}
    
    template <class T> Vector<T>::Vector(int size): m_nSize(0), m_nCapacity(size){
        m_pElements = size > 0 ? new T[size] : nullptr;
    }
    
    template <class T> Vector<T>::Vector(const Vector& r): m_nSize(r.m_nSize), m_nCapacity(r.m_nCapacity){
        m_pElements = m_nCapacity > 0 ? new T[m_nCapacity] : nullptr;
        for (int i = 0; i < m_nSize; i++)
            m_pElements[i] = r.m_pElements[i]; 
    }
    
    template <class T> Vector<T>::~Vector(){
        delete[] m_pElements;
    }
    
    template <class T> T& Vector<T>::operator[](int index){
        return m_pElements[index];
    }
    
    template <class T> T& Vector<T>::at(int index){
        if (index < 0 || index >= m_nSize)
            throw std::out_of_range("Index out of range");
        return m_pElements[index];
    }
    
    template <class T> int Vector<T>::size() const {
        return m_nSize;
    }
    
    template <class T> void Vector<T>::push_back(const T& x){
        if (m_nSize == m_nCapacity)
            inflate();
        m_pElements[m_nSize++] = x;
    }
    
    template <class T> void Vector<T>::clear(){
        m_nSize = 0;
        delete[] m_pElements；
    }
    
    template <class T> bool Vector<T>::empty() const{
        return m_nSize == 0;
    }
    
    template <class T> void Vector<T>::inflate(){
        int newCapacity = (m_nCapacity == 0) ? 1 : (2*m_nCapacity);
        T* newElements = new T[newCapacity];
        for (int i = 0; i < m_nSize; i++)
            newElements[i] = m_pElements[i];
        delete[] m_pELements;
        m_pElements = newElements;
        m_nCapacity = newCapacity;
    }
    
    #endif
    ```

模板代码的调用示例：

??? tips "Vector.cpp"

    ```cpp
    #include "Vector.h"
    #include <iostream>
    #include <string>
    using namespace std;
    
    void test(const string& name, bool condition) {
        cout << (condition ? "[PASS] " : "[FAIL] ") << name << endl;
    }
    
    int main() {
        // Test 1: Default constructor
        Vector<int> v1;
        test("Default constructor - empty", v1.empty() && v1.size() == 0);
        
        // Test 2: Constructor with size
        Vector<int> v2(5);
        test("Constructor with size", v2.size() == 0);
        
        // Test 3: push_back
        v1.push_back(10);
        v1.push_back(20);
        v1.push_back(30);
        test("push_back - size", v1.size() == 3);
        test("push_back - values", v1[0] == 10 && v1[1] == 20 && v1[2] == 30);
        
        // Test 4: operator[]
        v1[1] = 99;
        test("operator[] - modify", v1[1] == 99);
        
        // Test 5: at() with valid index
        test("at() - valid index", v1.at(0) == 10);
        
        // Test 6: at() with invalid index
        try {
            v1.at(10);
            test("at() - exception", false);
        } catch (const out_of_range&) {
            test("at() - exception", true);
        }
        
        // Test 7: Copy constructor
        Vector<int> v3(v1);
        test("Copy constructor - size", v3.size() == v1.size());
        test("Copy constructor - values", v3[0] == v1[0]);
        v1[0] = 999;
        test("Copy constructor - deep copy", v3[0] != v1[0]);
        
        // Test 8: clear
        v1.clear();
        test("clear", v1.empty() && v1.size() == 0);
        
        // Test 9: empty
        test("empty - after clear", v1.empty());
        v1.push_back(1);
        test("empty - after push_back", !v1.empty());
        
        // Test 10: Multiple push_back (test inflate)
        Vector<int> v4;
        for (int i = 0; i < 10; i++) {
            v4.push_back(i);
        }
        test("Multiple push_back", v4.size() == 10 && v4[9] == 9);
        
        // Test 11: Different types - string
        Vector<string> vs;
        vs.push_back("Hello");
        vs.push_back("World");
        test("String vector", vs.size() == 2 && vs[0] == "Hello");
        
        // Test 12: Different types - double
        Vector<double> vd;
        vd.push_back(3.14);
        vd.push_back(2.71);
        test("Double vector", vd.size() == 2 && vd[0] == 3.14);
        
        cout << "\n=== All tests completed ===" << endl;
        return 0;
    }
    ```

template class的另一些例子：

???+ tips "mypair"

    ```cpp
    #include "mypair.h"
    
    template <class first, typename second>
    First Mypair<first, second>::getFirst(){
        return first;
    } 
    
    template<class Second, typename First>
    Second MyPair<First, Second>::getSecond(){
        return second;
    }
    ```

## Templates

目标：写一次，适用于所有类型的变量



## Template Functions

`<typename T>`表示是对`T`类型的模板函数，后面跟着的`T`是函数返回类型，用`&`引用防止复制

```c++
template <typename T>
    T min(const T& a, const T& b) {
    return a < b ? a : b;
}
```

### Template Function的使用

**显式实例化：（explicit instantiation）**

```cpp
min<int>(106, 107);       // T = int
min<double>(1.2, 3.4);    // T = double
min<std::string>("cat", "dog"); // T = std::string
```

实际上编译器完成的任务：

```cpp
int min(const int& a, const int& b) { return a < b ? a : b; }
double min(const double& a, const double& b) { return a < b ? a : b; }
// ... 等等
```

核心是Templates automate code generation.

**隐式实例化：（Implicit Instantiation）**

```cpp
min(106, 107);   // compiler看到2个 int，推导出 T = int
min(1.2, 3.4);   // 推导出 T = double
```

这就等价于

```cpp
min<int>(106, 107);
min<double>(1.2, 3.4);
```

???+ warning "Pitfall-1"

    在隐式推导时，传入的“字符串”不会被自动推导成`std::string`，而是`const char*`，如：

    ```cpp
    min("Thomas", "Rachel");
    ```

    推导出的结果是：

    ```cpp
    const char* min(const char* a, const char* b) {
        return a < b ? a : b;
    }
    ```

    这是毫无意义的，因为实际上比较的是指针所在的内存地址. 所以这里就必须使用explicit instantiation：

    ```cpp
    min<std::string>("Thomas", "Rachel");  // const char* 被轉換為 std::string
    ```

???+ warning "Pitfall-2"

    第二个需要注意的问题是类别匹配问题：

    ```cpp
    min(106, 3.14);
    ```

    此时编译器无法判断类型，直接报错.

    解决方法：

    ```cpp
    min<double>(106, 3.14);  // int  double
    ```

    或者用两个模板参数：

    ```cpp
    template <typename T, typename U>
    auto min(const T& a, const U& b) {
        return a < b ? a : b;
    }
    min(106, 3.14);  // T = int, U = double，不会报错
    ```

### concepts：给template加上限制条件

如果运算被应用在了不支持运算符的template上面，就会出现实例化之前的错误，报错信息难读取. 于是C++20引入了`concept`.

比如：

```cpp
template <typename T>
concept Comparable = requires(const T a, const T b) {
    { a < b } -> std::convertible_to<bool>;
};
```

定义一个叫 `Comparable` 的 `concept`，要求`a < b`必须编译成立，同时输出类型是`bool`.

```cpp
template <typename T> requires Comparable<T> T min(const T& a, const T& b);

// 更简洁
template <Comparable T> T min(const T& a, const T& b);
```

此时传入`Stanford`，系统报错会直接落在不可比较的特性上，更加清楚.

`std::`提供了许多内建concepts，如：

```cpp
template <std::input_iterator It, typename T>
It find(It begin, It end, const T& value);
// std::input_iterator 是内建 concept，确保 It 是合法的迭代器
```

### 可变参数模板（Variadic Templates）

我们希望让模板函数可以接受任意数量的参数.

```cpp
template <Comparable T> T min(const T& v){
    return v;
}

template <Comparable T, Comparable... Args> T min(const T& v, const Args&... args){
    auto m = min(args...);
    return v < m ? v : m;
}
```

### Template Metaprogramming（C++20以前）

原因：template所有工作都在编译期完成，因此可以做一些计算.

```cpp
// 用 template struct 计算 Factorial
template <size_t N>
struct Factorial {
    enum { value = N * Factorial<N-1>::value };  // 递归
};

template <>
struct Factorial<0> {     // Base case：N=0 
    enum { value = 1 };
};

std::cout << Factorial<7>::value;  // output: 5040
```

`Factorial<7>::value` 在编译时就已经是 5040 了！执行之后直接输出常数5040.

???+ tips "`constexpr`和`consteval`"

    C++20引入了`constexpr`和`consteval`，这进一步简化了求值：

    ```cpp
    // constexpr：「尽量在编译期执行」
    constexpr size_t factorial(size_t n) {
        if (n == 0) return 1;
        return n * factorial(n - 1);
    }

    // consteval：「必须在编译期执行，否则报错」
    consteval size_t factorial(size_t n) {
        if (n == 0) return 1;
        return n * factorial(n - 1);
    }
    ```