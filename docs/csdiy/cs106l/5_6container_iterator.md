## Intro to STL

STL(Standard Template Library) is the core of modern C++, involving containers, iterators, functions and algorithms.

## Containers

All containers can hold almost all elements.

<center><img src="../figures/containers.png"  style="zoom: 50%;" /></center>

这里提到了Stanford自制的库以及STL的比较，是在CS106B用到Qt Creator时会尝试使用.

<center><img src="../figures/stfstl.png"  style="zoom: 50%;" /></center>

### 6种container的实现和用法

C++中`std::vector`内部是一个固定大小的array，但是会自动resize.

```cpp
// Adding numElems elements to the end of the vector
for (int i = 0; i < numElems; ++i)
    vec.push_back("Read Book #" + std::to_string(i));

// Adding numElems elements to beginning of vector
for (int i = 0; i < numElems; ++i)
    vec.insert(vec.begin(), "Get Book #" + std::to_string(i));

// accessing all of the elements without any operations
for (int i = 0; i < numElems; ++i)
    (void)vec[i];
```

`std::deque`的情况稍显复杂：

内存空间前后都有NULL等待元素进去，`push_front(elem)`是将元素放在最前，`push_back(elem)`是将元素放在最后，如果超出已分配的部分就创建新块然后塞进去.

`std::list`：a list provides fast insertion anywhere, but no random (indexed) access

```cpp
std::list<int> list{5,6}; //{5,6}
list.push_front(3);       //{3,5,6}
list.pop_back();          //{3,5}
```

<center><img src="../figures/when2use.png"  style="zoom: 60%;" /></center>

总结：

* `std::vector`: use for almost everything
* `std::deque`: use if you are frequently inserting/removing **at front**
* `std::list`: use very rarely, and only if you need to split/join multiple lists

### container adaptors

这部分讲了容器适配器.

<center><img src="../figures/containers2.png"  style="zoom: 50%;" /></center>

Container adapters provide a specific interface by adapting other containers:

* `std::stack`: Implements a Last-In-First-Out (LIFO) structure.
* `std::queue`: Implements a First-In-First-Out (FIFO) structure.
* `std::priority_queue`: Implements a heap for prioritized access.

### associative containers

1. `map`/`set`（红黑树实现）
存储原理：

```cpp
// PPT核心原理：存成pair
map<string, int> ages; 
ages["Alice"] = 30;  
// 实际存入：pair<const string, int>{"Alice", 30}
```

key是const（不可修改），并且具有自动按键排序（需元素支持`<`运算符）.

2. `unordered_map`（哈希表实现）

局限：

```cpp
// 错误！vector不能直接哈希
unordered_map<vector<int>, string> cityMap;  
```

解决方法是用指针作为key（可哈希）或者自定义哈希函数

3. `stack`/`queue`

```cpp
stack<int, list<int>> myStack;  // 基于链表的栈
queue<int, deque<int>> myQueue; // 基于双端队列的队列
```

### looping over collections

vector尚且可以使用i来索引遍历，像set和map就只能用更通行的迭代器遍历，也就是下一小节的东西.

```cpp
std::vector<char> vec{'a','b','c'};
for (std::size_t i = 0; i < vec.szie(); ++i){
    const auto& elem = vec[i];
    cout << elem << endl;
}

// 遍历 set
std::set<int> mySet{1, 2, 3, 4, 5, 6};
for (auto it = mySet.begin(); it != mySet.end(); ++it) {
    const auto& elem = *it;  // 解引用迭代器获取元素
    std::cout << elem << "\n";
}

// 遍历 map
std::map<int, std::string> myMap{{1, "Apple"}, {2, "Banana"}};
for (auto it = myMap.begin(); it != myMap.end(); ++it) {
    const auto& key = it->first;      // 使用 -> 访问成员
    const auto& value = it->second;
    std::cout << key << ": " << value << "\n";
}
```

## Iterators and Pointers

迭代器可以取得container中的元素，whether ordered, unordered, sequence, or associative.

Iterator has an "ordering" over elements i.e. it knows what the "next" element is.

所以书写的语句是

```cpp
it = container.begin(); 
++it; // it knows what the "next" element is and points to it.
*it; // access the element pointed at by the iterator (dereference)
```

[Iterators](https://www.cplusplus.com/reference/iterator/) are objects that point to elements inside containers.

* Each STL container has its own iterator, but all of these iterators exhibit a similar behavior!
* Generally, STL iterators support the following operations:

```cpp
std::set<type> s = {0, 1, 2, 3, 4};
std::set::iterator iter = s.begin(); // at 0
++iter; // at 1
*iter; // 1
(iter != s.end()); // can compare iterator equality
auto second_iter = iter; // "copy construction"
```

现代新的语法糖迭代写法：

```cpp
// 原始迭代器循环（PPT底层实现）
for(auto iter=vec.begin(); iter!=vec.end(); ++iter) {
    cout << *iter << " ";
}

// 现代简化循环（语法糖）
for(int n : vec) {
    cout << n << " ";
} // 两者完全等价
```

一个小要点：Why `++iter` and not `iter++`?

Answer: `++iter` returns the value after being incremented! `iter++` returns the previous value and then increments it. (wastes just a bit of time)

指针（类似C）:

```cpp
string word = "Hello";
// 迭代器方式
auto iter = word.begin();   // 指向'H'
// 指针方式
char* charPtr = &word[0];   // 指向'H'
// 两者均可这样操作：
cout << *iter;      // H
cout << *(charPtr+1);// e
```
