## Lec 4 Leftist Heap(左式堆) & Skew Heap(斜堆)

???+ warning "Cheating List"

    |                | Leftist Heap（左式堆）| Skew Heap（斜堆）| Binomial Queue（二项队列）|
    | -------------- | ----------------------------- | --------------------------- | ----------------------------- |
    | 节点数/树高关系 | 最坏树高 \( O(N) \)，摊还树高 \( O(\log N) \)；节点数 \( N \) 与树高 \( h \) 满足 \( F_{h+2} - 1 \leq N \)（\( F \) 为斐波那契数列） | 最坏树高 \( O(N) \)，摊还树高 \( O(\log N) \) | 树高 \( h \leq \log_2 (N + 1) \)；节点数 \( N \) 与树高 \( h \) 满足 \( 2^h \leq N < 2^{h+1} \) |
    | 搜索           | 无（堆结构不支持高效搜索，需线性遍历）| 无（堆结构不支持高效搜索，需线性遍历） | 无（堆结构不支持高效搜索，需线性遍历） |
    | 插入           | 摊还 \( O(\log N) \)（基于合并操作实现）| 摊还 \( O(\log N) \)（基于合并操作实现） | \( O(\log N) \) |
    | 删除（删除最小元） | 摊还 \( O(\log N) \)（基于合并操作实现）| 摊还 \( O(\log N) \)（基于合并操作实现） | \( O(\log N) \) |

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

<center><img src = "../figures/ads/recmerge.jpg" style = "zoom:30%"/></center>

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

<center><img src = "../figures/ads/itemerge0.jpg" style = "zoom:30%"/></center>

<center><img src = "../figures/ads/itemerge1.jpg" style = "zoom:30%"/></center>

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

??? tips "2.1-9"
    After inserting a node into a Leftist heap H (which is equivalent to merging a one-node Leftist heap with H), we need to swap the children of at most 1 node to make the resulting tree a Leftist heap.

    这句话是对的，添加之后最多让一个parent的深度增加并产生矛盾，即某个节点$dist = d+1$，其左右节点$dist = d,d+1$，此时只要交换其左右节点就能够解决矛盾，不需要进行多余交换.

### Skew Heap

> 修佬在笔记中说：“要想将左偏堆改变地能够进行自上而下维护，就需要改变甚至放弃它的左偏性质的严格性——而这就是斜堆的由来。”

> wyh学长的讲义中指出：“Leftist Heap与Skew Heap的关系就像Splay Tree和AVL Tree之间的关系。”

所以在插入元素/合并堆的过程中，并不需要为了维护结构性质，进行一些围绕dist的额外操作。

Skew Heap放弃了左偏属性，在[wiki](https://en.wikipedia.org/wiki/Skew_heap)上是使用递归定义的：

> Skew heaps may be described with the following recursive definition:
>
> * A heap with only one element is a skew heap.
>
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

<center><img src = "../figures/ads/sh0.jpg" style = "zoom:30%"/></center>

<center><img src = "../figures/ads/sh1.jpg" style = "zoom:30%"/></center>

<center><img src = "../figures/ads/sh2.jpg" style = "zoom:30%"/></center>

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

接着定义势能函数$\Phi(H)$： $\Phi(H) = \text{number of heavy nodes in} H$

通过一系列推导可以得知，merge操作的时间复杂度是$O(\log N)$.

#### PTA习题

??? tips "2025fall-yy-mid"
    To build a skew heap, we can start with an emtpy heap, and merge each single-node heap into the resulting heap one by one.
    Then the best description of the time complexity of this procedure is: $\textcolor{red}{O(N\log N)}$.

    这个递推应该是$T(N) = T(N-1) + \log N$，所以由Sterling公式得到结果.

    While inserting n elements into a skew heap, the insertion of the last element may cost $O(n)$ time.

    这是对的，考虑降序的序列即可.

??? tips "2025fall-ch-mid"

    What is the defining mechanical difference between the merge operation in a Skew Heap and in a Leftist Heap?<br>
    A. Skew Heaps merge along the left spines, while Leftist Heaps merge along the right spines.<br>
    B. Skew Heaps unconditionally swap the left and right children of every node on the merge path, while Leftist Heaps only swap if the NPL property is violated.<br>
    C. Skew Heaps have an $O(\log n)$ worst-case merge time, while Leftist Heaps have an $O(\log n)$ amortized merge time.<br>
    D. Skew Heaps do not need to maintain the min-heap property during the merge, only at the end.

    选B，这是最关键的点.

??? tips "xyx-1"
    The result of inserting keys 1 to 2k−1 for any k>4 in order into an initially empty skew heap is always a full binary tree.<br>
    这个明显对.

    The right path of a skew heap can be arbitrarily long.<br>

    <center><img src = "../figures/ads/xyx-left.png" style = "zoom:50%"/></center>

??? tips "2024mid"

    <center><img src = "../figures/ads/2024mid3.png" style = "zoom:50%"/></center>

??? tips "2.1-10,11"

    <center><img src = "../figures/ads/2.1-1011.png" style = "zoom:50%"/></center>

## Lec 5 Binomial Queue

!!! tips "资源"
    [Wintermelon的笔记](https://wintermelonc.github.io/WintermelonC_Docs/zju/compulsory_courses/ADS/ch5/)
    $\quad$
    [wiki](https://en.wikipedia.org/wiki/Binomial_heap)
    $\quad$
    [修佬的笔记](https://note.isshikih.top/cour_note/D2CX_AdvancedDataStructure/Lec05)

二项队列是一群heap的集合，其中每个heap都是1个二项队列.

首先定义二项树：

> A binomial tree, $B_k$, of height $k$ is formed by attaching a binomial tree, $B_{k – 1}$, to the root of another binomial tree, $B_{k – 1}$.

其图示如下：

<center><img src = "../figures/ads/bt0.png" style = "zoom:30%"/></center>

于是有：

> $B_k$ consists of a root with $k$ children, which are $B_0,B_1,\cdots,B_{k-1}$. $B_k$ has exactly $2^k$ nodes.  The number of nodes at depth $d$ is $C_k^d$.

接下来引出二项队列的定义：

> A binomial queue is not a heap-ordered tree, but rather a collection of heap-ordered trees, known as a forest.  Each heap-ordered tree is a binomial tree.

也就是说，二项队列是类似二进制加和下二项树的集合，因此这一表示是唯一的，比如$size = 13$的二项队列，其二进制下为：

$$13 = 2^3 + 2^2 + 2^0 = (1101)_2$$

于是构成为：

<center><img src = "../figures/ads/bq0.png" style = "zoom:50%"/></center>

### Findmin

只需要找每个根节点中的min就行了，时间复杂度$O(\log N)$.

### Merge

> 在理解二项队列过程中，可以试图从两个纬度同时理解这些操作：

> 1. 树/堆的纬度，具体观察数据的转移与变化过程；<br>
> 2. 二进制的纬度，将$k$阶二项树抽象为 bit vector 第$k$位的 1，从二进制加法的角度理解；

<center><img src = "../figures/ads/bqmerge.jpg" style = "zoom:50%"/></center>

下面是这个函数具体的实现代码：

???+ tips "merge代码"

    ```c
    BinQueue Merge( BinQueue H1, BinQueue H2 ){
        BinTree T1, T2, Carry = NULL;
        int i, j;
        if ( H1->CurrentSize + H2-> CurrentSize > Capacity )  ErrorMessage();
        H1->CurrentSize += H2-> CurrentSize;
        for ( i=0, j=1; j<= H1->CurrentSize; i++, j*=2 ) {
            T1 = H1->TheTrees[i]; T2 = H2->TheTrees[i]; /*current trees */
            switch( 4*!!Carry + 2*!!T2 + !!T1 ) {
            case 0: /* 000 */
            case 1: /* 001 */  break;
            case 2: /* 010 */  H1->TheTrees[i] = T2; H2->TheTrees[i] = NULL; break;
            case 4: /* 100 */  H1->TheTrees[i] = Carry; Carry = NULL; break;
            case 3: /* 011 */  Carry = CombineTrees( T1, T2 );
                            H1->TheTrees[i] = H2->TheTrees[i] = NULL; break;
            case 5: /* 101 */  Carry = CombineTrees( T1, Carry );
                            H1->TheTrees[i] = NULL; break;
            case 6: /* 110 */  Carry = CombineTrees( T2, Carry );
                            H2->TheTrees[i] = NULL; break;
            case 7: /* 111 */  H1->TheTrees[i] = Carry;
                            Carry = CombineTrees( T1, T2 );
                            H2->TheTrees[i] = NULL; break;
            } /* end switch */
        } /* end for-loop */
        return H1;
    }
    ```

    这里我们将`T1,T2,Carry`的是否为空视作二进制bit组合起来，考察需要进行的操作. 

    * 如果`T1`存在但是`Carry`和`T2`不存在，则循环已经可以终止，表明合并结束了;
    * 如果`T1,T2`均存在，

### Insertion

类似之前的heap，插入操作看作是与一个结点的二项堆的merge.

<center><img src = "../figures/ads/bqinsert.jpg" style = "zoom:50%"/></center>

If the smallest nonexistent binomial tree is $B_i$ , then $Tp = Const \times (i + 1)$. Performing $N$ Insertions on an initially empty binomial queue will take $O(N)$ worst-case time.  Hence the average time is $O(1)$.

### DeleteMin

这是一个综合性操作：

1. Findmin<br>
2. Merge

??? tips "过程"

    <center><img src = "../figures/ads/deletemin_bq.jpg" style = "zoom:30%"/></center>

### PTA习题

??? tips "2.1-13,14"

    <center><img src = "../figures/ads/2.1-1314.png" style = "zoom:60%"/></center>

    第1题的情况是，

    第2题的反例是101001这棵树，考虑min指向的是最高位子树的root，那么merge过程是11111+1011，merge次数超过了k.

??? tips "(2.3-7) Multiple Answers"

    Right after we perform some operation (Merging, Insertion or DeleteMin) on a Binomial queue, we may have to merge some pairs of the resulting Binomial trees to make the resulting forest a Binomial queue.<br>
    Suppose that $B_{i1},B_{i2},B_{i3}$ of size $2^{k−1},2^{k-1},2^k(k\geq 1)$ respectively are Binomial trees to merge. Consider the case that $B_{i1}$ is merged with $B_{i2}$, and the resulting Binomial tree is then merged with $B_{i3}$. We call this case “cascading merge”.<br>
    Which of the following statements about “cascading merge” is/are correct?

    A.We may have to perform “cascading merge” right after deleting the minimum key of a Binomial queue.<br>
    B.We may have to perform “cascading merge” right after merging two Binomial queues of the same size.<br>
    C.We must perform “cascading merge” right after inserting a key into a Binomial queue of odd size.<br>
    D.Consider the case that we perform consecutive insertions into a Binomial queue. Assume that we have performed “cascading merge” after inserting a key. Then in the next 3 insertions, we do not have to perform “cascading merge”.

    答案是AD，B不可能出现cascading，因为

??? tips "(2.3-8) Multiple Answers"

    Consider a binomial queue Q of n nodes with binomial trees $B_1,\cdots,B_k$. To delete the minimum key from Q, there are the following four steps to go.

    Step 1: Find the minimum key. Assume the minimum key is in $B_j, 1\leq j\leq k$.<br>
    Step 2: Remove $B_j$ from $Q$. The resulting queue is $Q'$.<br>
    Step 3: Construct a binomial queue $Q''$ using the subtrees rooted at the children of the root of $B_j$.<br>
    Step 4: Merge $Q'$ with $Q''$.

    Of which step(s), the worst-case running time is $\Theta(\log n)$?
    
    A. Step 1.$\quad$ B. Step 2.$\quad$ C. Step 3.$\quad$ D. Step 4.

??? tips "xyx-1"

    <center><img src = "../figures/ads/xyx1-7.png" style = "zoom:50%"/></center>

    For a binomial queue, __ takes a constant time on average.<br>
    A.merging<br>
    B.find-max<br>
    C.delete-min<br>
    D.insertion

    其他三个都是 O(log N)；在空 binomial queue 上连续插入 N 个是 O(N) 的

??? tips "2025fall-yy-mid"

    In a binomial queue with 180 nodes, how many nodes have depth 1(the root has depth 0)?

    应该是18个，只需要将180转化成$2^2+2^4+2^5+2^7$，并算出$2+4+5+7$即可.

??? tips "2021mid"

    To implement a binomial queue, left-child-next-sibling structure is used to represent each binomial tree.

    对.
