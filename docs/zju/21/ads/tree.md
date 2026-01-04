???+ warning "数值规模Cheating List"
    以下是Cheating List，是对4种树的各类数值规模的总结：

    |                 | AVL Tree                    | Splay Tree                  | RB Tree               | B+ Tree（$M-\text{order}$）                          |
    | --------------- | --------------------------- | --------------------------- | --------------------- | ---------------------------------------------------- |
    | 节点数/树高关系 | $h = \log N$                | 最坏$O(N)$，摊还$O(\log N)$ | $h \leq 2\log_2(N+1)$ | $h\leq \log_{\lceil \frac M2\rceil}N$                |
    |                 | $F_{h+3}-1\leq N\leq 2^h-1$ |                             | $bh\geq \dfrac h2$    | $2\cdot (\lceil \frac M2\rceil)^{h-1}\leq N\leq M^h$ |
    | 搜索            | $O(\log N)$                 | 最坏$O(N)$，摊还$O(\log N)$ | $O(\log N)$           | $O(h\log M) = O(\log N)$                             |
    | 插入            | $O(\log N)$                 | 最坏$O(N)$，摊还$O(\log N)$ | $O(\log N)$           | $O(h\log M) = O(\log N)$                             |
    | 删除            | $O(\log N)$                 | 最坏$O(N)$，摊还$O(\log N)$ | $O(\log N)$           | $O(h\log M) = O(\log N)$                             |

## Lec 1: AVL Tree & Splay Tree & Amortized Analysis(摊还分析)

### AVL Tree

是BST的改进版本之一，主要思想仍然是尽可能平衡.

Definition:

(1)An empty binary tree is height balanced.

(2)If T is a nonempty binary tree with $T_L, T_R$ as its left and right subtrees, then $T$ is height balanced iff :

* $T_L, T_R$ are height balanced;
* $\vert h_L-h_R \vert \leq 1$  where $h_L,h_R$ are the heights of $T_L,T_R$, respectively.

Define balance factor $BF(node) = h_L-h_R$. In an AVL tree, $BF(node) = \pm1,0$.

以上是判断是否为AVL tree的方法.

于是我们先写出一些关于height的定义：

```c++
struct AVLNode{
    int data;
    int height;
    AVLNode* left;
    AVLNode* right;
};

int getheight(AVLNode* node){
    if(node == nullptr) return 0;
    return node->height;
}

void updateheight(AVLNode* node){
    if (node == nullptr) return;
    node->height = 1 + max(getheight(node->left),getheight(node->right));
}

int calcBalanceFactor(AVLNode* node){
    if(node == nullptr) return 0;
    return (getheight(node->left) - getheight(node->right));
}
```

#### 四种Rotation

> 旋转操作是多数平衡树能够维持平衡的关键，能在不改变一棵合法 BST 中序遍历结果的情况下改变局部节点的深度。
>
> ——[OI wiki](https://oi-wiki.org/ds/rbtree/)
>
> 旋转的理解：按我个人来看，这四种旋转都是需要先找到"Trouble Maker",即从插入的节点出发，一直向上走**第一个不平衡的节点。然后，对这个节点做操作**，具体可以看下面的代码实现。另外，LR与RL其实是由LL与RR组成的。
>
> ——[AVL树,Splay树,红黑树与B+树 - Starstone3's bed](https://starstone3.github.io/incourse/ADS/Tree/#avl树的特点与性质)

RR Rotation: 如果新插入一个元素在右子树的最右节点，导致破坏了AVL Tree（$h_R-h_L = 2$），则需要进行Rotation，将root的右节点旋转成为root.

```cpp
AVLNode* rrRotation(AVLNode* root){  
    // root 是第一个出问题的节点，即troublemaker
    if (root == nullptr || root->right == nullptr){
        return root;
    }
    AVLNode* newroot = root->right;
    root->right = newroot->left;
    newroot->left = root;
    updateheight(root);
    updateheight(newroot);  //先root后newroot，因为newroot的更新需要使用root的新数据.
    return newroot;
}
```

<center><img src="../figures/ads/rr.png" alt="rr" style="zoom: 75%;" /></center>

LL Rotation类似，代码如下：

```cpp
AVLNode* llRotation(AVLNode* root){
    if (root == nullptr || root->left == nullptr){
        return root;
    }
    AVLNode* newroot = root->left;
    root->left = newroot->right;
    newroot->right = root;
    updateheight(root);
    updateheight(newroot);
    return newroot;
}
```

<br/>

接下来是LR Rotation. 我们这么起名主要是因为从root起，需要先遍历左节点再遍历右节点才能到达增加了节点的子树.

LR Rotation过程：

<center><img src="../figures/ads/lr-1.jpg" alt="lr" style="zoom: 75%;" /></center>

**LR rotation过程可以看作是一次RR Rotation和一次LL Rotation的叠加**，拆解如下：

<center><img src="../figures/ads/lr-2.jpg" alt="lr" style="zoom: 75%;" /></center>

所以代码为：

```cpp
AVLNode* lrRotation(AVLNode* root){
    if (root == nullptr || root->left == nullptr){
        return root;
    }
    root->left = rrRotation(root->left);
    return llRotation(root);
}
```

类似地，RL Rotation为：

```cpp
AVLNode* rlRotation(AVLNode* root){
    if (root == nullptr || root->right == nullptr){
        return root;
    }
    root->right = llRotation(root->right);
    return rrRotation(root);
}
```

容易知道插入操作的效率是$T_P = O(h)$，rotation操作的效率是$O(1)$.

#### AVL Tree 最小节点数计算推导

我们希望从节点数倒推出高度$h$的值.

对于一个AVL Tree，我们希望它在固定$h$的情况下节点数尽可能少，于是只能是一边为$h-1$高度，另一边为$h-2$高度.

假设第$h$高度的AVL Tree至少有$n_h$个节点，于是容易得到：$n_h = n_{h-1} + n_{h-2} + 1$

这是一个变形的Fibonacci数列，因为$F_0 = 0, F_1 = 1, F_2 = 1; n_0 = 0, n_1 = 1, n_2 = 2$，而且$(n_h+1) = (n_{h-1}+1)+(n_{h-2}+1).$

所以可以自然地推导出$\boxed{F_{i+2} = n_i+1}.$

于是时间复杂度估计：$F_i \approx \dfrac{1}{\sqrt{5}}(\dfrac{1+\sqrt{5}}{2})^i\Longrightarrow n_h \approx \dfrac{1}{\sqrt{5}}(\dfrac{1+\sqrt5}{2})^{h+2-1} \Longrightarrow h = O(\ln n)$

#### PTA作业题整理

??? notes "1.1-1"

    Consider an AVL tree. Immediately after we insert a node (without restoring the tree balance), the parent of the newly inserted node may become imbalanced. 

    是错的，因为新插入的节点本身是叶子节点，其平衡因子为0（左右子树高度都是0），父节点不会立即出现问题. 失衡只可能发生在祖先节点上（祖父节点或更高层），而不是直接父节点

??? notes "1.1-2"

    For every AVL tree, there exists a sequence of nodes such that we can obtain this AVL tree by inserting the nodes in the sequence one by one into an initiallly empty tree.

    这句话的意思是，我们能通过逐一插入节点到一棵空树中，来获得这个最终的树.

    是对的，比如：

    ```plaintext
        4
       / \
      2   6
     / \ / \
    1  3 5  7
    ```

    考虑前序遍历的方式，按4,2,6,1,3,5,7就能得到这棵树.

??? notes "1.3-2"

    <center><img src="../figures/ads/1.3-2.png" style="zoom: 60%;" /></center>

    A. 画图可知.

    After inserting a node, we need to perform at most 1 rotation to rebalance the tree.<br>

??? notes "xyx-1"
    <center><img src="../figures/ads/xyx1-1.png" style="zoom: 60%;" /></center>

    举一个例子.

??? tips "2021mid"

    <center><img src="../figures/ads/2021mid-avl.png" style="zoom: 60%;" /></center>

    iff是“当且仅当”的意思.

??? tips "Final Practice 1 Code Completion"

    An AVL tree is a self-balancing binary search tree. In an AVL tree, the heights of the two child subtrees of any node differ by at most one; if at any time they differ by more than one, rebalancing is done to restore this property. Figures 1-4 illustrate the rotation rules.

    ![F1.jpg](https://images.ptausercontent.com/3fb1ef21-3ece-4adf-ae42-00bfeeaf6f86.jpg)

    ![F2.jpg](https://images.ptausercontent.com/d8528f9d-2d3b-480b-93f5-358209fe2f5b.jpg)

    ![F3.jpg](https://images.ptausercontent.com/958bb922-0eaf-4cc3-ab73-ce74b5f2fbc3.jpg)

    ![F4.jpg](https://images.ptausercontent.com/d26bb82b-1f4b-41ea-8514-584e513f1f92.jpg)

    Now given a sequence of insertions, you are supposed to build the AVL tree. Then given a sequence of statements about the structure of the resulting tree, you are supposed to tell if they are correct or not. A statment is one of the following:

    (1) A is the root  
    (2) A and B are siblings  
    (3) A is the parent of B  
    (4) A is the left child of B  
    (5) A is the right child of B

    Format of functions:

    ```c
    Tree Build_AVL ( int input[ ], int n );
    int Judge ( Tree T, int type, int A, int B );
    ```

    The function `Build_AVL` is supposed to build an AVL tree according to the input sequence.

    Here `Tree` is defined as the following:

    ```
    typedef struct TNode *Tree;
    struct TNode {
        int key;    //key of the node
        int height; //height of the subtree with this node as the root
        Tree left, right; //pointing to the left and right children of this node
    };
    ```

    The array `input` contains `n` (a positive integer) distinct keys to be inserted in order into an initially empty AVL tree. The root pointer of the resulting tree is supposed to be returned by `Build_AVL`.

    The function `Judge` is supposed to test if a given statement for an AVL tree `T` is correct or not, and return `1` if the result is true, or `0` otherwise. The parameter `type` is an integer in \[1, 5\], which gives the index of a statement, as listed in the problem description; and `A` and `B` are the corresponging key values. For type 1, the value of `B` can be ignored. It is guaranteed that both `A` and `B` in the statements are in the tree.

    Sample program of judge:

    ```c
    #include <stdio.h>
    #include <stdlib.h>

    typedef struct TNode *Tree;
    struct TNode {
        int key;    //key of the node
        int height; //height of the subtree with this node as the root
        Tree left, right; //pointing to the left and right children of this node
    };

    Tree Build_AVL ( int input[ ], int n );
    int Judge ( Tree T, int type, int A, int B );

    int main()
    {
        int n, *input;
        int m, type, A, B, i;
        Tree T;

        scanf("%d", &n);
        input = (int *)malloc(sizeof(int) * n);
        for (i=0; i<n; i++) scanf("%d", &input[i]);
        T = Build_AVL(input, n);
        scanf("%d", &m);
        for (i=0; i<m; i++) {
            scanf("%d %d", &type, &A);
            if (type != 1) scanf("%d", &B);
            if (Judge(T, type, A, B)) printf("Yes\n");
            else printf("No\n");
        }
        return 0;
    }

    /* Your function will be put here */
    ```

    Sample Input 1 (Figure 1):

    ```in
    3
    88 70 61
    8
    1 70
    1 61
    2 61 88
    2 88 70
    3 88 70
    3 70 61
    4 88 70
    5 88 70
    ```

    Sample Output 1:

    ```out
    Yes
    No
    Yes
    No
    No
    Yes
    No
    Yes
    ```

    Sample Input 2 (Figure 2):

    ```in
    5
    88 70 61 96 120
    7
    1 70
    2 96 88
    3 96 120
    4 88 70
    4 88 96
    5 120 96
    5 88 70
    ```

    Sample Output 2:

    ```out
    Yes
    No
    Yes
    No
    Yes
    Yes
    No
    ```

    Sample Input 3 (Figure 3):

    ```in
    6
    88 70 61 96 120 90
    8
    1 70
    1 88
    2 90 61
    3 70 61
    3 96 70
    4 90 96
    5 90 88
    5 96 88
    ```

    Sample Output 3:

    ```out
    No
    Yes
    No
    Yes
    No
    Yes
    No
    Yes
    ```

    Sample Input 4 (Figure 4):

    ```in
    7
    88 70 61 96 120 90 65
    7
    1 88
    2 96 70
    2 61 70
    3 61 65
    4 65 88
    4 70 88
    5 70 65
    ```

    Sample Output 4:

    ```out
    Yes
    No
    Yes
    No
    Yes
    No
    Yes
    ```

    解答：
    
    ```c
    int getHeight(Tree T) {
        if (T == NULL) return 0;
        return T->height;
    }

    void updateHeight(Tree T) {
        if (T == NULL) return;
        int leftHeight = getHeight(T->left);
        int rightHeight = getHeight(T->right);
        T->height = (leftHeight > rightHeight ? leftHeight : rightHeight) + 1;
    }

    Tree createNode(int key) {
        Tree newNode = (Tree)malloc(sizeof(struct TNode));
        newNode->key = key;
        newNode->height = 1;
        newNode->left = NULL;
        newNode->right = NULL;
        return newNode;
    }

    Tree LL(Tree T) {
        Tree newRoot = T->left;
        T->left = newRoot->right;
        newRoot->right = T;
        updateHeight(T);
        updateHeight(newRoot);
        return newRoot;
    }

    Tree RR(Tree T) {
        Tree newRoot = T->right;
        T->right = newRoot->left;
        newRoot->left = T;
        updateHeight(T);
        updateHeight(newRoot);
        return newRoot;
    }
    Tree LR(Tree T) {
        T->left = RR(T->left);
        return LL(T);
    }
    Tree RL(Tree T) {
        T->right = LL(T->right);
        return RR(T);
    }

    Tree insert(Tree T, int key) {
        if (T == NULL) 
            return createNode(key);
        
        if (key < T->key) {
            T->left = insert(T->left, key);
        } else if (key > T->key) {
            T->right = insert(T->right, key);
        }
        
        updateHeight(T);
        
        int balanceFactor = getHeight(T->left) - getHeight(T->right);

        if (balanceFactor > 1 && key < T->left->key)
            return LL(T);
        if (balanceFactor < -1 && key > T->right->key)
            return RR(T);
        if (balanceFactor > 1 && key > T->left->key)
            return LR(T);
        if (balanceFactor < -1 && key < T->right->key)
            return RL(T);
        return T;
    }

    Tree Build_AVL(int input[], int n) {
        Tree T = NULL;
        for (int i = 0; i < n; i++)
            T = insert(T, input[i]);
        return T;
    }

    Tree findNode(Tree T, int key) {
        if (T == NULL) return NULL;
        if (T->key == key) return T;
        if (key < T->key) return findNode(T->left, key);
        return findNode(T->right, key);
    }

    Tree findParent(Tree T, int key) {
        if (T == NULL || T->key == key) return NULL;
        
        if ((T->left && T->left->key == key) || (T->right && T->right->key == key))
            return T;
        
        if (key < T->key) return findParent(T->left, key);
        return findParent(T->right, key);
    }

    int Judge(Tree T, int type, int A, int B) {
        if (type == 1) return (T != NULL && T->key == A);
        
        Tree nodeA = findNode(T, A);
        Tree nodeB = findNode(T, B);
        
        if (nodeA == NULL || nodeB == NULL) return 0;
        
        switch (type) {
            case 2: { // A and B are siblings
                Tree parentA = findParent(T, A);
                Tree parentB = findParent(T, B);
                return (parentA != NULL && parentA == parentB);
            }
            case 3: { // A is the parent of B
                Tree parentB = findParent(T, B);
                return (parentB != NULL && parentB->key == A);
            }
            case 4: { // A is the left child of B
                return (nodeB->left != NULL && nodeB->left->key == A);
            }
            case 5: { // A is the right child of B
                return (nodeB->right != NULL && nodeB->right->key == A);
            }
        }
        return 0;
    }
    ```

### Splay Tree

!!! tips "资源"
    [Splay tree - Wikipedia](https://en.wikipedia.org/wiki/Splay_tree) $\quad$ [Wintermelon的笔记-lec1](https://wintermelonc.github.io/WintermelonC_Docs/zju/compulsory_courses/ADS/ch1)

#### 理论分析

我们希望将任意的$M$次操作的时间复杂度降低至$O(M\log N)$.（这里其实不是很严谨，N可以指整个过程中节点总数量最大值）

**核心idea: 每次访问（`Find`）完一个元素之后，把它移动到root位.**

（我们称 2次左旋/右旋 和 1次左旋和右旋的组合 分别为single/double rotation，命名原因是**两次旋转之间方向是否有改变**.）

访问后将目标$x$提升到root位的思路：$\text{Find}~x \Longrightarrow \text{judge rotation type} \Longrightarrow \text{rotate} \Longrightarrow x~\text{is the root}$

Splaying Operation：是由一系列的Splaying Step构成的，每一步都使得被访问的$x$移动到离$root$更近的地方.

现在需要对我们访问的X的父节点P进行分类讨论：

* P 是根节点，则只需要进行zig操作来rotation X & P

    <center><img src = "../figures/ads/zig.jpg" style="zoom: 30%;"/></center>

* P 不是根节点，则需要分情况，选择操作zig-zag(Double Rotation)或者zig-zig(Single Rotation)

    <center><img src = "../figures/ads/dr.jpg" style="zoom: 30%;"/></center>

#### 搜索、插入

这个比较容易，是类似BST的操作.

#### 删除

将节点$X$删去分成4步：

1. Find X, 此时X被放到了root位置；<br>
2. remove X, 这样产生了左子树$T_L$和右子树$T_R$;<br>
3. findmax($T_L$), 将其旋到root位;<br>
4. 把$T_R$变成$T_L$根节点的右孩子，这样相当于merge操作，但是很简明，因为root在左子树最大保证了右孩子节点为空，所以直接把右子树挂上去就可以了.

#### PTA习题

??? tips "1.3-3"

    <center><img src = "../figures/ads/1.3-3.png" style="zoom: 60%;"/></center>

    全选.

??? tips "[xyx-1](https://www.yuque.com/xianyuxuan/coding/ads_exam_1)"

    <center><img src = "../figures/ads/xyx1-2.png" style="zoom: 60%;"/></center>

    <center><img src = "../figures/ads/xyx1-3.jpg" style="zoom: 60%;"/></center>

    All of the Zig, Zig-zig, and Zig-zag rotations not only move the accessed node to the root, but also roughly half the depth of most nodes on the path. <br>
    这是对的，并且是Splay的核心特性.

    <center><img src = "../figures/ads/xyx1-3.png" style="zoom: 60%;"/></center>

    选D，流程应该是如下的：

    <center><img src = "../figures/ads/xyx1-4.jpg" style="zoom: 60%;"/></center>

    <center><img src = "../figures/ads/xyx1-6.png" style="zoom: 60%;"/></center>

    <center><img src = "../figures/ads/xyx1-6.jpg" style="zoom: 60%;"/></center>

??? tips "2025fall-ch-mid"

    <center><img src = "../figures/ads/2025midch-1.png" style="zoom: 60%;"/></center>

    <center><img src = "../figures/ads/2025midch-1.jpg" style="zoom: 50%;"/></center>

??? tips "Final Practice 2 2-17"

    <center><img src = "../figures/ads/f2.2-17.png" style = "zoom:60%"/></center>

    1错2对3错.
    
    4错，如果不旋上去是没有意义的（？）

    5错，因为zigzig先把P旋转上去，之后把X旋上去，并不是upward twice.

    6对，看知识点即可.

## Lec 2 Red-Black Tree & B+ Tree

!!! info "资源"
    [OI wiki](https://oi-wiki.org/ds/rbtree/)
    $\quad$
    wyy的ADS讲义，这似乎指示着我需要去看看算法导论的讲解.
    $\quad$
    [修佬的笔记](https://note.isshikih.top/cour_note/D2CX_AdvancedDataStructure/Lec02)

### Red-Black Tree

Red-Black Tree 是一个满足以下red-black property的BST：

1. 节点非黑即红 Every node is red/black;

2. 根节点为黑 The root is black; （值得一提的是这一条并不需要满足，见OI wiki）

3. 叶节点为黑 Every leaf(NIL) is black;

4. 红节点的所有孩子为黑 If a node is red, then both its children are black;

5. 所有从某个节点到叶子的路径上的黑色节点数相同 For each node, all simple paths from the node to descendant leaves contain the same number of black nodes.

!!! tips "举例"
    上面的定义比较抽象，可以参考这个示例图来理解：
    <center><img src = "../figures/ads/rbtree.png" style="zoom: 60%;"/></center>
    A red-black tree with \(n\) internal nodes has height at most 2\(\ln (N+1)\).
    这可以由归纳法进行证明，略.

#### 插入

此处介绍的是bottom-up的插入思路. 由于插入红色节点不会影响红黑树的平衡，但是黑色节点会让平衡破坏，所以所有插入节点$X$都默认设置为红色.

以下的所有case都考虑的是自插入以后节点$X$向上移动过程中它附近局部的特征（主要考察跟grandparent, parent, uncle结点的关系），其中图示的黑色方框可以指的是NIL或者子树，但root一定是黑色的，这可以由刚插入时左右全是NIL节点，以及后续操作的染色处理来保证，看完操作之后这是不言自明的.

最简单的一种情况是，$X$插入后其父亲节点本身就是黑色的，此时不需要旋转或者染色，我们直接可以休息了.

于是只需要考虑$X$插入之后其父亲节点是红色的情况.

为了叙述的方便，下面采用跟Isshikih修佬一样的顺序，从最简单的case3倒推到case1，进一步引出整个插入操作的状态机.

首先是case3，只需要LL Rotation或者RR Rotation的情况：

<center><img src = "../figures/ads/case3.jpg" style="zoom: 50%;"/></center>

接着是case2，这里只需要进行一次LR/RL Rotation并且染色就能达到平衡：

<center><img src = "../figures/ads/case2.jpg" style="zoom: 50%;"/></center>

最后是最为复杂的case1，我们针对节点G的上一级进行分类，由对称性化简，最后共分成4个小的case：

<center><img src = "../figures/ads/case1.jpg" style="zoom: 50%;"/></center>

<center><img src = "../figures/ads/case121.jpg" style="zoom: 50%;"/></center>

<center><img src = "../figures/ads/case122.jpg" style="zoom: 50%;"/></center>

<center><img src = "../figures/ads/case123.jpg" style="zoom: 50%;"/></center>

<img src = "../figures/ads/case124.jpg" style="zoom: 30%;"/>

完整状态机：

<center><img src = "../figures/ads/statemachine.png" style="zoom: 70%;"/></center>

#### 删除

首先回顾BST的删除操作（假设被删掉的节点是$X$）：

1. 如果$X$没有孩子，则直接删除即可；

2. 如果$X$有1个孩子，则只需要让孩子接替$X$的位子即可；

3. 如果$X$有2个孩子，则需要先让$X$与其左子树的最大节点或者右子树的最小节点交换，这样就可以转化成case 1或者2.

红黑树的删除操作基于BST的分析，不过细节更多.

总的思路分析：

<center><img src = "../figures/ads/rbdel0.jpg" style="zoom: 80%;"/></center>

首先是case3.当$X$有2个孩子的时候，我们只需要将$X$与其左子树最大节点或者右子树最小节点的**键值**交换，保持红黑属性不变，就可以转换成case1或者2.

而case1,2其实没有显著的不同，所以讨论的时候可以合并来看（以下已经注明，case1真包含于cases12.3，因为NIL节点是黑色的.）

<center><img src = "../figures/ads/rbdel1.jpg" style="zoom: 80%;"/></center>

<center><img src = "../figures/ads/rbdel2.jpg" style="zoom: 60%;"/></center>

状态机：

<center><img src = "../figures/ads/rbdel3.jpg" style="zoom: 60%;"/></center>

搜索到$X$节点需要的时间是$O(\log N)$，而向上转移所谓的双黑属性时间复杂度是$O(h) = O(\log N)$，每个转移操作的时间复杂度是$O(1)$，于是整个删除操作的复杂度是$O(\log N)$.

总算是完成了红黑树的总结，接下来摘录吴一航学长在讲义中的一段话，这使我更加深入地了解了这几种树的学习中我究竟在为将来的学习做什么准备：

!!! tips "2.1.4 再论 AVL 树和红黑树的区别"

    开头我们已经提到，AVL 树的平衡条件太严苛，因此更新树（即插入和删除）操作会更频繁，所以我们希望有一个条件更松的平衡要求但也能保证树高被控制在$O(\log n)$的量级。除此之外，AVL 树和红黑树似乎都是通过旋转恢复平衡，没有很大的差别。但其实有一个很有趣的现象，又非常多的库函数在选择平衡搜索树实现功能的时候，会更常用红黑树，例如大家最熟悉的 C++ 的 `std::map`，以及 Java 8 开始的 HashMap 和 Microsoft .NET 框架的部分代码，甚至 Linux 内核中内存管理也使用了红黑树（可以参考[这个 GitHub 上的 Linux 文档](https://github.com/torvalds/linux/blob/master/Documentation/core-api/rbtree.rst)）。那这其中的原因可能是什么呢？

    事实上这一问题应当是没有标准答案的，毕竟是当年工程师的多方面考虑综合后的选择，但我们可以通过这个问题看一看 AVL 树和红黑树的一些更细致的区别：

    1. 我们都知道，AVL 树平衡条件更严格，推导 AVL 树高的时候我们用到了斐波那契数列，实际上，可以验证的是 AVL 树最差高度大约为 $1.44 \log n$，红黑树最差则可以达到 $2 \log n$，事实上讨论题 1 隐含了这一点，从这一层面来看，**如果对一棵树的查询操作居多，那么 AVL 树会是更好的选择**；

    2. 但上一节我们提到，AVL 树虽然插入只需要常数次旋转即可，但在删除时可能需要$O(\log n)$次旋转，而红黑树插入和删除都是常数次，有人提到在代码实现时旋转是插入和删除最耗时的操作，因此如果插入删除操作多，AVL 树不如红黑树快速，而我们知道使用 `std::map` 时**的确可能遇到较多插入删除操作**；

    3. AVL 树需要维护树高或者 balance factor 属性，这是一个整数的大小，而红黑树只需要 1 个 bit 存储颜色即可，因此**更省空间**；

    4. 红黑树是**可持久化**的数据结构，因此在函数式编程中容易实现；并且红黑树也可以支持分裂、合并等操作，这使得它可以做批量并行的插入、删除操作（实际上这与讲义最后红黑树与 B 树的关联是相关的），具体已经超出课程范畴，不再详细讨论。

#### PTA习题

??? tips "2025fall-yy-mid"

    After deleting 10 from the red-black tree given in the figure, which one of the following statements must be FALSE?

    <center><img src = "../figures/ads/yymid1.png" style="zoom: 50%;"/></center>

    A. 8 is the parent of 6, and 6 is black<br>
    B. 6 is the parent of 8, and 8 is red<br>
    C. 11 is the parent of 15, and 15 is black<br>
    D. 13 is the parent of 14, and 13 is black

    选B.红黑树的节点删除之后有两种处理方法：把左子树最大的移动过来/右子树最小的移动过来.

    <center><img src = "../figures/ads/yymid1-1.jpg" style="zoom: 30%;"/></center>

??? tips "xyx-1"

    <center><img src = "../figures/ads/xyx15.png" style="zoom: 50%;"/></center>

    <center><img src = "../figures/ads/xyx1-5.png" style="zoom: 50%;"/></center>

??? tips "2021mid"

    In a red-black tree, if an internal black node is of degree 1, then it must have only 1 descendant node.

    对.

??? tips "Final Practice 2 2-6"

    <center><img src = "../figures/ads/f2.2-6.png" style = "zoom:60%"/></center>

    self-adjusting structure指的是splay, skew/leftist heap这些，balanced指的是AVL, rb tree.
    **注意审题.**

### B+ Tree

Definition:

一个M序的B+ Tree 是具备以下结构特征的树：

1. The root is either a leaf or has between 2 and \(M\) children.

2. All nonleaf nodes (not root) have between \([\dfrac M 2]+1\) and \(M\) children.

3. All leaves are at the same depth.

比如2-3-4树的举例如下：

<center><img src = "../figures/ads/bplus0.png" style="zoom: 50%;"/></center>

其中所有数据存储在叶子节点中，拼接起来就是一个严格单调递增/减的数列；

非叶子节点的第$i$个键值 = 第$(i+1)$颗子树的最小/大值，所以非叶节点最多存$M-1$个值.

**一颗$\text{order} = 4$的B+树也称为$2-3-4$树，其中internal node键值最多3个，指针最多4，与order相等.**（这部分跟wiki的定义是不一样的）

B+树的深度是$O(\lceil \log_{\lceil \frac{M}{2} \rceil}N\rceil)$，因为最浪费深度的放置方法是每层$\lceil \frac{M}{2} \rceil$个节点.

#### 搜索、插入

搜索操作是极其简单的，只需要逐层搜索下去就行.

插入操作的探讨要分成2部分，第一是插入之后的叶子节点内数量没有超过order，因而不需要split，此时已经结束；第二是需要split的情形，此时需要递归向上进行分裂.

过程图如下：

???+ tips "B+树搜索插入操作"
    <center><img src = "../figures/ads/bplus0.jpg" style="zoom: 80%;"/></center>
    <center><img src = "../figures/ads/bplus1.jpg" style="zoom: 80%;"/></center>
    <center><img src = "../figures/ads/bplus2.jpg" style="zoom: 80%;"/></center>

#### *删除

!!! warning
    ADS考试不要求掌握，DB可能需要掌握.

#### PTA作业题整理

??? notes "2.1-2"

    Consider an insertion in a B+ tree. We may need to update some keys stored in some internal nodes even if no leaf is split during the insertion.

??? notes "2.1-3"

    Consider an initially empty B+ tree of order $M$. Whatever the value of $M$, after inserting $n$ keys, the cost of a findkey operation on the resulting B+ tree is $\Theta(\log n)$.

    这显然是对的，不知道为啥做错了.

??? notes "2.1-9"

    After inserting a node into a Leftist heap $H$ (which is equivalent to merging a one-node Leftist heap with $H$), we need to swap the children of at most $1$ node to make the resulting tree a Leftist heap.

??? notes "2.2-2"

    Insert 1,6,7,3,5,2 one by one into an initially empty 2-3 tree (B+ tree of order 3). Which of the following statements is true? We assume that the height of a single node is 1.

    A.The root has 1 key.<br>
    B.3 and 6 are in the same leaf.<br>
    C.The height of the resulting tree is 3.<br>
    D.The resulting tree is the same as that generated by inserting 1,2,3,5,6,7 one by one into an initially empty 2-3 tree.

    选D

??? notes "2.3-2"

    Consider a 2-3 tree. Initially, it has 2 leaves, with keys 1,2,5 and 11,17,19 respectively. Now we perform the following operations one by one:
    <center>Insert 15;  Insert 21;  Insert 22;  Delete 15;  Delete 5.</center>
    Among the following statements, which is/are correct?

    A.The height of the tree increases after 15 is inserted.<br>
    B.Some key in some internal node changes after 21 is inserted.<br>
    C.The height of the tree increases after 22 is inserted.<br>
    D.The height of the tree decreases after 15 is deleted.<br>
    E.Some key in some internal node changes after 15 is deleted.<br>
    F.The height of the tree decreases after 5 is deleted.

??? notes "2025fall-yy-mid"

    In a B+ tree, internal nodes store both index keys and actual data records.

    这是错的，不包含data records.

??? notes "2025fall-yy-mid"

    Insert 10, 20, 30, 40, 50, 60, 70, 80 into an initially empty 3-order B+ tree (i.e., each internal node can hold at most 2 keys). After all insertions, which of the following statements is TRUE?
    
    A. There are 3 leaf nodes<br>
    B. The root node contains key 60<br>
    C. The height of the tree is 3<br>
    D. The leftmost leaf node contains keys [10, 20, 30]

    选C.
    
    <center><img src = "../figures/ads/yymid2.png" style="zoom: 50%;"/></center>

    来源：[USFCA可视化板-B+树](https://www.cs.usfca.edu/~galles/visualization/BPlusTree.html)

??? tips "xyx-1"

    A B+ tree of order 3 with 21 numbers has at least __ nodes of degree 2. 

    答案是0.

    Which of the following statements concerning a B+ tree of order $M$ is TRUE?
    A.the root always has between $2$ and $M$ children<br>
    B.not all leaves are at the same depth<br>
    C.leaves and nonleaf nodes have some key values in common<br>
    D.all nonleaf nodes have between $\lceil M/2 \rceil$ and $M$ children

    选C.<br>
    A: The root is either a leaf or has between $2$ and $M$ children.<br>
    D: All nonleaf nodes (except the root) have between $\lceil M/2 \rceil$ and $M$ children.
