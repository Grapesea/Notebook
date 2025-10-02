## Lec 3 Leftist Heap(左式堆) & Skew Heap(斜堆)

### Leftist Heap

左偏堆是普通堆的改进版，支持快速的堆合并操作.

一个左偏堆的节点维护了左右地址，键值以及距离dist：

```cpp
# define ElementType xx; // xx is the val type, eg. int 

struct Node{
    ElementType val;
    int dist;
    Node* ls, * rs;
}
```

dist = 0表示至少有一个孩子节点为空，并称这个节点为外节点.

如果左右都不为空，则该节点的$\text{dist} = \min{(\text{dist}_{\text{leftchild}},\text{dist}_{\text{rightchild}})} + 1$.

左偏堆是节点键值不大于（或者不小于）其孩子节点键值的二叉树，并且左偏——$\text{dist}_{\text{leftchild}} \geq \text{dist}_{\text{rightchild}}$，因此得到：

$\text{dist}_{\text{node}} = \text{dist}_{\text{rightchild}}$

### Amortized Annalysis for Skew Heap

## Lec 4 Binomial Queue

## Lec 5
