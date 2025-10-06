## Lec 4 Leftist Heap(左式堆) & Skew Heap(斜堆)

!!! tips
    [修佬的笔记](https://note.isshikih.top/cour_note/D2CX_AdvancedDataStructure/Lec04)
    $\quad$
    [Wintermelon的笔记](https://wintermelonc.github.io/WintermelonC_Docs/zju/compulsory_courses/ADS/ch4/)

### Leftist Heap

左偏堆是普通堆的改进版，支持快速的堆合并操作.

一个左偏堆的节点维护了左右地址，键值以及距离dist（在另外的资料中，如wyh学长的ADS讲义，使用NPL作为变量名. 此处采用了修佬的命名方法）：

```cpp
#define ElementType int // 太久不写代码了，#define宏定义里面不需要加分号!
// 或者 typedef ElementType int;
// 或者 using ElementType = int;

struct Node
{
    ElementType val;
    int dist;
    Node *ls, *rs;
};
```

dist = 0表示至少有一个孩子节点为空，并称这个节点为外节点.

如果左右都不为空，则该节点的$\text{dist} = \min{(\text{dist}_{\text{leftchild}},\text{dist}_{\text{rightchild}})} + 1$.

左偏堆是节点键值不大于（或者不小于）其孩子节点键值的二叉树，并且左偏——$\text{dist}_{\text{leftchild}} \geq \text{dist}_{\text{rightchild}}$，因此得到：

$$\text{dist}_{\text{node}} = \text{dist}_{\text{rightchild}}+1$$

$\text{dist}$的另一种理解是，某个节点距离其子树中$\text{dist}=0$的节点的最小距离，不存在的孩子节点视作$\text{dist}=-1$.

!!! tips
    定理：在右路径上有$r$个节点的左式堆一定至少有$2^r-1$个节点.

    证明：这可以由数学归纳法得到.

#### 合并操作

有两种合并的方法：递归式、迭代式.

递归式的思路是：首先确保$X,Y$合并时，$X$的值比$Y$小（不满足则交换$X,Y$）；其次将$Y$放到$X$的右子树上去比较，相当于递归地与右子节点合并；当某一个值为NULL时递归结束.

这个过程中，为了确保左式堆的性质，我们需要对合并的树进行一些调整：如果合并之后左右子树dist数量关系错误，则交换$X->ls,X->rs$；接着对$X$的dist重新计算，确保递归过程中每一层$X$的值能倒着更新回去.

完整代码：

```cpp
void swap(Node *X, Node *Y){
    Node *temp = X;
    X = Y;
    Y = temp;
}

Node *merge(Node *X, Node *Y){
    if (X == nullptr) return Y;
    if (Y == nullptr) return X;
    if (X->val > Y->val) swap(X, Y);

    X->rs = merge(X->rs, Y);

    // 如果合并之后左右子树dist数量关系错误，则交换$X->ls,X->rs$
    if (X->ls == nullptr || (X->rs != nullptr && X->ls->dist < X->rs->dist))
        swap(X->ls, X->rs);

    // 对$X$的dist重新计算，确保递归过程中每一层$X$的值能倒着更新回去
    if (X->rs == nullptr)
        X->dist = 0;
    else
        X->dist = X->rs->dist + 1;
    return X;
}
```

### Amortized Analysis for Skew Heap

## Lec 5 Binomial Queue
