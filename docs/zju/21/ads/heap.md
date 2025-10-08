## Lec 4 Leftist Heap(左式堆) & Skew Heap(斜堆)

!!! tips
    [修佬的笔记](https://note.isshikih.top/cour_note/D2CX_AdvancedDataStructure/Lec04)
    $\quad$
    [Wintermelon的笔记](https://wintermelonc.github.io/WintermelonC_Docs/zju/compulsory_courses/ADS/ch4/)

### Leftist Heap

左偏堆是普通堆的改进版，支持快速的堆合并操作.

一个左偏堆的节点维护了左右地址，键值以及距离$\text{dist}$（在另外的资料中，如wyh学长的ADS讲义，使用`NPL`作为变量名. 此处采用了修佬的命名方法）：

```cpp
#define ElementType int // 太久不写代码了，#define宏定义里面不需要加分号!
// 或者 typedef ElementType int;
// 或者 using ElementType = int;

struct Node{
    ElementType val;
    int dist;
    Node *ls, *rs;
};

int dist(Node *node){
    return node == NULL ? -1 : node->dist;
}
```

dist = 0表示至少有一个孩子节点为空，并称这个节点为外节点.

如果左右都不为空，则该节点的$\text{dist} = \min{(\text{dist}_{\text{leftchild}},\text{dist}_{\text{rightchild}})} + 1$.

左偏堆是节点键值不大于（或者不小于）其孩子节点键值的二叉树，并且左偏——$\text{dist}_{\text{leftchild}} \geq \text{dist}_{\text{rightchild}}$，因此得到：

$$\text{dist}_{\text{node}} = \text{dist}_{\text{rightchild}}+1$$

$\text{dist}$的另一种理解是，某个节点距离其子树中$\text{dist}=0$的节点的最小距离，不存在的孩子节点视作$\text{dist}=-1$.

!!! tips
    定理：在右路径上有$r$个节点的左式堆一定至少有$2^r-1$个节点.

    证明：这可以由数学归纳法得到.

#### Merge

有两种合并的方法：递归式、迭代式.

递归式的思路是：首先确保$X,Y$合并时，$X$的值比$Y$小（不满足则交换$X,Y$）；其次将$Y$放到$X$的右子树上去比较，相当于递归地与右子节点合并；当某一个值为NULL时递归结束.

这个过程中，为了确保左式堆的性质，我们需要对合并的树进行一些调整：如果合并之后左右子树dist数量关系错误，则交换$X\rightarrow ls,X\rightarrow rs$；接着对$X$的$\text{dist}$重新计算，确保递归过程中每一层$X$的值能倒着更新回去.

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

    // 如果合并之后左右子树dist数量关系错误，则交换X->ls,X->rs
    if (X->ls == nullptr || (X->rs != nullptr && X->ls->dist < X->rs->dist))
        swap(X->ls, X->rs);

    // 对X的dist重新计算，确保递归过程中每一层X的值能倒着更新回去
    if (X->rs == nullptr)
        X->dist = 0;
    else
        X->dist = X->rs->dist + 1;
    return X;
}
```

容易看出，这个操作的时间复杂度是$O(rpl_1+rpl_2) = O(\log N_1 + \log N_2) = O(\log N_1N_2) = O(\log \sqrt{N_1N_2}) = O(\log(N_1+N_2)) = O(\log N).$

流程图实例：

<center><img src = "../ads/recmerge.jpg" style = "zoom:30%"/></center>

迭代式：这个部分的思路跟归并排序差不多，都需要双指针来动态移动.

以下是修佬给出的代码的延展版，其中的adjust函数使得插入操作之后，整个左式堆能递归地调整成为符合我们定义的情况：

```cpp
Node *adjust(Node *root){
    if (root == nullptr) return root;
    root->rs = adjust(root->rs);
    if (dist(root->ls) < dist(root->rs))
        swap(root->ls, root->rs);

    root->dist = dist(root->rs) + 1;
    return root;
}

Node *_merge(Node *X_, Node *Y_) // iterative merge
{
    if (X_ == nullptr) return Y_;
    if (Y_ == nullptr) return X_;

    Node *X = X_, *Y = Y_;
    Node *res = nullptr, *cur = nullptr;

    while (X != nullptr && Y != nullptr) {
        if (X->val > Y->val) swap(X, Y);

        if (res == nullptr){
            res = X;
            cur = res;
        }else{
            cur->rs = X;
            cur = cur->rs;
        }
        X = X->rs;
    }

    while (Y != nullptr){
        cur->rs = Y;
        cur = cur->rs;
        Y = Y->rs;
    }

    res = adjust(res);
    return res;
}
```

流程图实例：

<center><img src = "../ads/itemerge0.jpg" style = "zoom:30%"/></center>

<center><img src = "../ads/itemerge1.jpg" style = "zoom:30%"/></center>

#### Insertion

视作原左式堆与一个大小为1的左式堆进行合并操作即可.

#### Deletion

可以将单点删除视作将需要删掉的节点左侧的堆与右侧的堆合并.

```cpp
Node *del(Node *cur, ElementType x)
{
    if (cur->val == x)
        return merge(cur->ls, cur->rs);
    else{
        if (cur->val > x) return cur;
        if (cur->ls != NULL) del(cur->ls, x);
        if (cur->rs != NULL) del(cur->rs, x);
        adjust(cur);
    }
}
```

???+ tips
    After inserting a node into a Leftist heap H (which is equivalent to merging a one-node Leftist heap with H), we need to swap the children of at most 1 node to make the resulting tree a Leftist heap.

    这句话是错误的，考虑以下情况：
    <center><center>

### Skew Heap

> 修佬在笔记中说：“要想将左偏堆改变地能够进行自上而下维护，就需要改变甚至放弃它的左偏性质的严格性——而这就是斜堆的由来。”

> wyh学长的讲义中说：“斜堆与左式堆的关系就像Splay Tree和AVL Tree之间的关系。”

所以在插入元素/合并堆的过程中，并不需要为了维护结构性质，进行一些围绕dist的额外操作。

Skew Heap放弃了左偏属性，在[wiki](https://en.wikipedia.org/wiki/Skew_heap)上是使用递归定义的：

> Skew heaps may be described with the following recursive definition:
>
> * A heap with only one element is a skew heap.

> * The result of skew merging two skew heaps $sh_1$ and $sh_2$ is also a skew heap.

#### Merge

ADS课程的merge是对wiki等地方的定义做出了一点修改的（……），本课程版本的merge如此：

> When two skew heaps are to be merged, we can use a similar process as the merge of two leftist heaps:
>
> * Compare roots of two heaps; let p be the heap with the smaller root, and q be the other heap. Let r be the name of the resulting new heap.
>
> * Let the root of r be the root of p (the smaller root), and let r's right subtree be p's left subtree.
>
> * Now, compute r's left subtree by recursively merging p's right subtree with q.
>
> !: **if H merges with a NULL node, in leftist heap we just need to return H, but in skew heap we should swap ls and rs.**

<center><img src = "../ads/sh0.jpg" style = "zoom:30%"/></center>

<center><img src = "../ads/sh1.jpg" style = "zoom:30%"/></center>

<center><img src = "../ads/sh2.jpg" style = "zoom:30%"/></center>

skew heap的删除和插入节点方法与leftist heap原理上基本一致，略去.

???+ tips
    wyh学长的讲义思考题（英文版）：

    (1)The result of inserting keys $1,2,\cdots, 2^{k}-1$for any $k>4$ in order into an initially empty leftist heap is always a full binary tree. (T/F)

    (2)The result of inserting keys $1,2,\cdots, 2^{k}-1$for any $k>4$ in order into an initially empty skew heap is always a full binary tree. (T/F)

    两道题答案都是T，因为

#### Amortized Analysis for Skew Heap

首先需要定义一个结点的light/heavy属性：

> A node p is heavy if the number of descendants of p's right subtree is at least half of the number of descendants of p, and light otherwise. Note that the number of descendants of a node includes the node itself.

也就是说，对于节点H构成的skew heap，如果

$$\text{size}_{\text{H.right_descendent}} \geq \dfrac12 \text{size}_{\text{H}}$$

则称$H$是heavy node，否则是light node.

接着定义势能函数$\Phi(H)$： $\Phi(H) = number of heavy nodes in H$

通过一系列推导可以得知，merge操作的时间复杂度是$O(\log N)$.
