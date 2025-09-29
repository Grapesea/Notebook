## Lec 1: AVL Tree & Splay Tree & Amortized Analysis （摊还分析）

### AVL Tree

#### 定义

主要思想：尽可能平衡

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

<br/>

#### 四种Rotation

!!! tips
    > 旋转操作是多数平衡树能够维持平衡的关键，能在不改变一棵合法 BST 中序遍历结果的情况下改变局部节点的深度。
    >
    > 摘自[OI wiki](https://oi-wiki.org/ds/rbtree/)
    >
    > 旋转的理解：按我个人来看，这四种旋转都是需要先找到"Trouble Maker",即从插入的节点出发，一直向上走**第一个不平衡的节点。然后，对这个节点做操作**，具体可以看下面的代码实现。另外，LR与RL其实是由LL与RR组成的。
    >
    > 摘自[AVL树,Splay树,红黑树与B+树 - Starstone3's bed](https://starstone3.github.io/incourse/ADS/Tree/#avl树的特点与性质)

RR Rotation: 如果新插入一个元素在右子树的最右节点，导致破坏了AVL Tree（$h_R-h_L = 2$），则需要进行Rotation，将root的右节点旋转成为root.

```c++
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

<center><img src="../ads/rr.png" alt="rr" style="zoom: 75%;" /></center>

LL Rotation类似，代码如下：

```c++
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

<center><img src="../ads/lr-1.jpg" alt="lr" style="zoom: 75%;" /></center>

**LR rotation过程可以看作是一次RR Rotation和一次LL Rotation的叠加**，拆解如下：

<center><img src="../ads/lr-2.jpg" alt="lr" style="zoom: 75%;" /></center>

所以代码为：

```c++
AVLNode* lrRotation(AVLNode* root){
    if (root == nullptr || root->left == nullptr){
        return root;
    }
    root->left = rrRotation(root->left);
    return llRotation(root);
}
```

类似地，RL Rotation为：

```c++
AVLNode* rlRotation(AVLNode* root){
    if (root == nullptr || root->right == nullptr){
        return root;
    }
    root->right = llRotation(root->right);
    return rrRotation(root);
}
```

容易知道插入操作的效率是$T_P = O(h)$，rotation操作的效率是$O(1)$.

<br/>

#### AVL Tree 最小节点数计算推导

我们希望从节点数倒推出高度$h$的值.

对于一个AVL Tree，我们希望它在固定$h$的情况下节点数尽可能少，于是只能是一边为$h-1$高度，另一边为$h-2$高度.

假设第$h$高度的AVL Tree至少有$n_h$个节点，于是容易得到：$n_h = n_{h-1} + n_{h-2} + 1$

这是一个变形的Fibonacci数列，因为$F_0 = 0, F_1 = 1, F_2 = 1; n_0 = 0, n_1 = 1, n_2 = 2$，而且$(n_h+1) = (n_{h-1}+1)+(n_{h-2}+1).$

所以可以自然地推导出$\boxed{F_{i+2} = n_i+1}.$

于是时间复杂度估计：$F_i \approx \dfrac{1}{\sqrt{5}}(\dfrac{1+\sqrt{5}}{2})^i\Longrightarrow n_h \approx \dfrac{1}{\sqrt{5}}(\dfrac{1+\sqrt5}{2})^{h+2-1} \Longrightarrow h = O(\ln n)$

<br/>

### Splay Tree

!!! tips
    [Splay tree - Wikipedia](https://en.wikipedia.org/wiki/Splay_tree) $\quad$ [Wintermelon的笔记-lec1](https://wintermelonc.github.io/WintermelonC_Docs/zju/compulsory_courses/ADS/ch1)

#### 理论分析

> 我们希望将任意的$M$次操作的时间复杂度降低至$O(M\log N)$.
>
>（这里其实不是很严谨，N可以指整个过程中节点总数量最大值.
>
> 核心idea: 每次访问完一个元素之后，把它移动到root位

（我们称 2次左旋/右旋 和 1次左旋和右旋的组合 分别为single/double rotation，命名原因是**两次旋转之间方向是否有改变**.）

访问后将目标$x$提升到root位的思路：$\text{Find}~x \Longrightarrow \text{judge rotation type} \Longrightarrow \text{rotate} \Longrightarrow x~\text{is the root}$

Splaying Operation：是由一系列的Splaying Step构成的，每一步都使得被访问的$x$移动到离$root$更近的地方.

现在需要对我们访问的X的父节点P进行分类讨论：

* P 是根节点，则只需要进行zig操作来rotation X & P

    <center><img src = "../ads/zig.jpg" style="zoom: 30%;"/></center>

* P 不是根节点，则需要分情况，选择操作zig-zag(Double Rotation)或者zig-zig(Single Rotation)

    <center><img src = "../ads/dr.jpg" style="zoom: 30%;"/></center>

#### 搜索操作

这个比较容易，是类似BST的操作.

#### 删除操作

#### 插入操作

### Amortized Analysis

这一想法的来源是我们希望估计某个数据结构经过一系列操作的平均花费时间

Aggregate Analysis：找到时间开销最大的一种情形，计算$n$次操作之后的开销$T(n)$，则amortized cost是$\dfrac{T(n)}{n}$.

!!! tips
    举例：一个具有Multipop函数的大小为$k$的栈，从空栈开始只能选择push 1, pop 1, multipop三种操作，所以aggregate cost就是先压入$n-1$个元素，再进行一次Multipop，开销是$2n-2$，所以$\dfrac{T(n)}{n} = O(1)$.

现在我们试图证明splay tree中，$T_{\text{amortized}} = O(\log{n})$.

首先证明zig/zig-zag/zig-zig操作的开销上限（摊还成本）分别为：

$$\text{zig}:~~ \hat{c_i} \leq 1+(R_2(X)-R_1(X))$$

$$\text{zig-zag}: \hat{c_i} \leq 2(R_2(X)-R_1(X))$$

$$\text{zig-zig}: \hat{c_i} \leq 3(R_2(X)-R_1(X))$$

推导如下：

???+ tips
    <center><img src = "../ads/zig1.jpg" style="zoom: 25%;"/></center>
    <center><img src = "../ads/zigzag.jpg" style="zoom: 30%;"/></center>
    <center><img src = "../ads/zigzig.jpg" style="zoom: 30%;"/></center>

而假设$X$的高度是$H(X)$的情况下，可能的旋转次数是

$$k = \begin{cases} \dfrac{H(X)}{2} & H(X)\text{是偶数}\\ \dfrac{H(X)-1}{2} + 1 & H(X)\text{是奇数}\end{cases}$$

即在高度为奇数时进行$\dfrac{H(X)-1}{2}$次的zig-zig/zig-zag，再进行1次zig将$X$转到root位；

在高度为偶数时进行$\dfrac{H(X)}{2}$次的zig-zig/zig-zag.

于是对于root为$T$的Splay Tree，想要找到它的$X$节点并进行splay操作，开销的摊还成本最大是$3(R(T)-R(X))+1 = O(\log(N))$，此时进行了1次zig和一堆zig-zig.

!!! tips
    Splay Tree的搜索、插入、删除操作的摊还复杂度都是$O(\log N)$.

## Lec 2 Red-Black Tree & B+ Tree

!!! tips
    [OI wiki](https://oi-wiki.org/ds/rbtree/)

### Red-Black Tree

Red-Black Tree 是一个满足以下red-black property的BST：

1. 节点非黑即红 Every node is red/black;

2. 根节点为黑 The root is black; （值得一提的是这一条并不需要满足，见OI wiki）

3. 叶节点为黑 Every leaf(NIL) is black;

4. 红节点的所有孩子为黑 If a node is red, then both its children are black;

5. 所有从某个节点到叶子的路径上的黑色节点数相同 For each node, all simple paths from the node to descendant leaves contain the same number of black nodes.

!!! tips
    A red-black tree with \(n\) internal nodes has height at most 2\(\ln (N+1)\).
    这可以由归纳法进行证明，略.

#### 插入

#### 删除

### B+ Tree

Definition:

一个M序的B+ Tree 是具备以下结构特征的树：

1. The root is either a leaf or has between 2 and \(M\) children.

2. All nonleaf nodes (not root) have between \([\dfrac M 2]+1\) and \(M\) children.

3. All leaves are at the same depth.
