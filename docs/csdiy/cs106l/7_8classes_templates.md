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

### 例子：realVector.cpp

回顾iterator，它是vector的一个**member type**.

