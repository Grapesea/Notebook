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

template <class T> Vector<T>::Vector(int size): m_nsize(0), m_nCapacity(size){
    m_pElements = size > 0 ? new T[size] : nullptr;
}


```