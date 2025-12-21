## Classes

> "A struct simply feels like an open pile of bits with very little in the way of encapsulation or functionality. A class feels like a living and responsible member of society with intelligent services, a strong encapsulation barrier, and a well defined interface." - Bjarne Stroustrup

Class 可以设定 private 和 public 2个部分，使得功能与参数能够被分置设定好.

eg. Student

```cpp
class Student {
    public:
        std::string getName();
        void setName(string 
        name);
        int getAge();
        void setAge(int age);
    private:
        std::string name;
        std::string state;
        int age;
};
```

public部分：可以立即使用student的任何功能与参数，同时定义了与private member variables 交互的入口.

private部分：包含所有的参数，无法取得或者修改其中的值.

