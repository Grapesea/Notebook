## Defining and Using Classes

Java中的所有代码都必须是一个class的一部分（所以是完全OOP的）

Command Line Arguments:

比如这段代码

```java
public class ArgsDemo {
    public static void main(String[] args) {
        System.out.println(args[0]);
    }
}
```

会产生这样的效果：

```bash
$ java ArgsDemo these are command line arguments
these
```

## Reference, Recursion

这部分的textbook很简单.

## List

### Basics

```java
public class IntList {
    public int first;
    public IntList rest;
    
    public IntList(int f, IntList r) {
        first = f;
        rest = r;
    }
}
```

List可以这样赋值：

```java
IntList L = new IntList(5, null);
L.rest = new IntList(10,null);
L.rest.rest = new IntList(15,null);
```

也可以这样初始化;

```java
IntList L = new IntList(15, null);
L = new IntList(10, L);
L = new IntList(5, L);
```

`size`和`iterativeSize`:

```java
public int size() {
    if (rest == null) {
        return 1;
    }
    return 1 + this.rest.size();
}
```

```java
public int iterativeSize() {
    IntList p = this;
    int totalSize = 0;
    while (p != null) {
        totalSize += 1;
        p = p.rest;
    }
    return totalSize;
}
```

`get`方法:

```java
public int recursiveGet(int pos) {
    if (pos == 0) {
        return this.first;
    } else {
        return this.rest.iterativeGet(pos - 1);
    }
}

public int iterativeGet(int pos) {
    IntList p = this;
    int t = pos;
    while (t > 0) {
        p = p.rest;
        t--;
    }
    return p.first;
}
```

### SLLists

```java
public class SLList {
    public IntNode first;
    public SLList(int x) {
        first = new IntNode(x, null);
    }
}
```



## Arrays



## Testing



## ArrayList



## Inheritance





## Asymptotics





## Disjoint Sets

 