# Tree

## ADTs and BSTs



## B-Trees



## Red Black Trees



## Tree traversal

前序遍历：

```java
public void static preOrder(BSTNode x) {
    if (x == null) return;
    System.out.println(x.key);
    preOrder(x.left);
    preOrder(x.right);
}
```

中序遍历：

```java
public void static inOrder(BSTNode x) {
    if (x == null) return;
    inOrder(x.left);
    System.out.println(x.key);
    inOrder(x.right);
}
```

后序遍历：

```java
public void static postOrder(BSTNode x) {
    if (x == null) return;
    postOrder(x.left);
    postOrder(x.right);
    System.out.println(x.key);
}
```

