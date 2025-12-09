!!! info "slides地址"

    [Lec 2: Types and Structs](https://web.stanford.edu/class/archive/cs/cs106l/cs106l.1226/lectures/lecture2_spr.pdf)

## Types

C++基础的type有： `int`, `char`, `float`, `double`, `bool`.

类型举例：

```cpp
string a = “test”;
double b = 3.2 * 5 - 1;
int    c = 5 / 2; // int/int → int, what’s the value?
int d(int foo) { return foo / 2; }
double e(double foo) { return foo / 2; }
int f(double foo) { return int(foo / 2); }
void g(double c) {
    std::cout << c << std::endl;            
}
```

C++是一个statically typed language，意思是，在运行之前，所有出现过的名称都必须给出其类型(像python就不同，Python是dynamic typed language).

Static Types + Functions:

```cpp
int add(int a, int b);       //int, int -> int
string echo(string phrase);  //string -> string
string helloworld();         //void -> string
double divide(int a, int b); //int, int -> double
```

这里引发了一个问题：Overloading. 如果我们希望同一个函数针对不同的类型可以有两个版本，应该怎么做？

基础的例子：

```cpp
int half(int x);
double half(double x);
```

此时如果输入的是3，自动使用第1个；如果输入3.0，自动使用第2个.

更复杂一点的例子：

```cpp
int half(int x, int divisor = 2);
double half(double x);
```

如果调用语句为`half(3)`，则为第1个，除数默认为2;<br>
如果调用语句为`half(3.0)`，则为第2个;<br>
如果调用语句为`half(3,3)`，则为第1个，此时除数是3.

总的来讲，函数重载允许多个函数使用相同的名字，但具备不同的参数类型/数量，让编译器根据调用时的参数自动选择正确的版本，从而实现**多态性**.

## Structs

定义：a group of named variables each with their own type. A way to bundle different types together.

最简单的例子：

```cpp
struct Student {
    string name; // these are called fields
    string state; // separate these by semicolons
    int age;
};
Student s;
s.name = "Frankie"; 
s.state = "MN";
s.age = 21; // use . to access fields
```

相同的表达：

```cpp
Student s;
s.name = "Frankie"; 
s.state = "MN";
s.age = 21; 
//is the same as below
Student s = {"Frankie", "MN", 21};
```

这引出了一些新的问题，比如是否具有一些简化表达的STL模板？

于是引出了`std::pair`，这是专用于两个object的struct.

比如：

```cpp
std::pair<int, string> numSuffix = {1,"st"};
cout << numSuffix.first << numSuffix.second; 
//prints 1st
```

其内部构造实际上是：

```cpp
struct Pair {
    fill_in_type first; 
    fill_in_type second; 
};
```

我们可以用这个模板一次性返回两个值，比如：

```cpp
std::pair<bool, Student> lookupStudent(string name){
    Student blank;
    if (notFound(name)) return std::make_pair(false,blank);
    Student result = getStudentWithName(name);
    return std::make_pair(true,result); 
}

std::pair<bool, Student> output = lookupStudent("Keith");
```

如果我们想更省力一点，可以使用`auto`这个变量类型，这这类型并不代表没有规定变量类型，而是让编译器自己推测：

```cpp
auto a = 3;
auto b = 4.3;
auto c = 'x';
auto d = "Hello";
auto e = std::make_pair(3,"Hello");
```
