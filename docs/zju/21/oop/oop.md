## Week 1: Introduction

Linux命令行编译cpp程序：

<img src="../photos/oop/1.png" style="zoom:70%;" />



## Week 2: Using Objects

``` cpp
#include <iostream>
#include <string>

using namespace std;

int main(){
    string init_str1("hello");
    string init_str2(init_str1);
    string init_str3 = "Hello,World!";
    string init_str4(init_str3, 7, 5); // 从第7个位置开始截取，取5个字符

    cout << "init_str1:" << init_str1 << endl;
    cout << "init_str2:" << init_str2 << endl;
    cout << "init_str3:" << init_str3 << endl;
    cout << "init_str4:" << init_str4 << endl;

    //其余初始化方法
    
    char charArray[] = "C++ str example";
    string str2 = charArray;    // 可以用字符数组来赋值
    cout << "str2:" << str2 << endl;

    string str3(10,'A');        // 可以直接写(10,char)来初始一个长度为10全为char的字符数组
    cout << "str3:" << str3 << "\n" << endl;

    // 一些其他的内容

    string sub = init_str3.substr(7,5);
    cout << "Substring:" << sub << "\n" << endl;

    
    

}

```