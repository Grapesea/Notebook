## Huffman code

<center><img src = "../figures/greedy/huffmancode.png" style="zoom: 40%;"/></center>

??? tips "2025fall-zgc-mid"

    <center><img src = "../figures/greedy/zgcmid-1.png" style="zoom: 50%;"/></center>

    喜欢Huffman编码吗？

## PTA问题举例

??? tips "5.2-1"

    <center><img src = "../figures/greedy/5.2-1.png" style="zoom: 50%;"/></center>

    选C.

    反例： 考虑硬币面额集合 $S = \{1, 4, 5\}$（$k=3$），目标金额 $n = 8$.
    
    贪心算法： 选最大的 $5 \to 8-5=3$,选最大的 $4$ (不能) $\to$ 选 $1, 1, 1$，于是方案：5, 1, 1, 1 (共 4 枚硬币).
    
    最优解： 选 $4, 4$. 方案：4, 4 (共 2 枚硬币). 由于贪心算法给出的解 (4枚) 不是最优解 (2枚)，所以陈述 (III) 是错误的.

??? tips "5.5-1"

    设有n个独立的作业$\{1,2,\cdots,n\}$，由$m$台相同的机器$\{1,2,\cdots,m\}$进行加工处理；作业$$i$ 所需的处理时间为$t_i（1\leq i\leq n）$，每个作业均可在任何一台机器上加工处理，但未完工前不允许中断，任何作业也不能拆分成更小的子作业.

    该多机调度问题要求给出一种贪心法作业调度方案，把$n$个作业按用时长从大到小顺序安排在最先空闲的机器上加工处理.

    ```c
    #include<stdio.h>
    #include<stdlib.h>
    #define N 100  //作业数上限
    int n;   //作业数
    int m;   //机器数
    struct NodeType
    {
        int no;         //作业序号
        int t;          //执行时间
        int mno;        //机器序号
    };
    struct NodeType A[N];
    struct NodeType machine[N];   //机器最后一个作业，（结束时间） 
    int cmp(const void *a, const void *b) // 排序比较函数 
    {
        return  -(((struct NodeType *)a)->t - ((struct NodeType *)b)->t);    // 从大到小 
    }

    struct NodeType get_min(struct NodeType machine[]) 
    {   // 选择最先空闲机器
        struct NodeType e = machine[0];
        int min = machine[0].t, index = 0, i;
        for( i=1; i<m; i++)
                if(machine[i].t < min) {
                    min = machine[i].t; 
                    e = machine[i]; 
                    /* Blank 1 */;
                }
        e.mno = index+1;   // 最先空闲机器号 
        return e;
    }

    void solve()          //求解多机调度问题
    {
        struct NodeType e;
        int i,j;
        if (n<=m)
            return;
        qsort(A, n, sizeof(struct NodeType), cmp); // 快速排序 

        for (i=0; i<m; i++)
        {
            A[i].mno=i+1;
            printf("%d %d %d-%d\n",
                    A[i].mno, A[i].t, 0, A[i].t);
            machine[i]=A[i];
        }

        for (j=m; j<n; j++)
        {   e = /* Blank 2 */; 
            printf("%d %d %d-%d\n",
                    e.mno, A[j].t, e.t, e.t+A[j].t);
            machine[e.mno-1].t /* Blank 3 */;    
        }
    }

    int main()
    {   int i;
        scanf("%d %d",&n, &m);

        for(i=0; i<n; i++)
            scanf("%d %d", &A[i].no, &A[i].t);
        solve();
        return 0;
    }
    ```

    输入格式：
    第一行输入作业数$n$和机器数$m$，用一个空格分隔；接着的$n$行输入作业编号和处理时长（均为正整数，用空格分隔）.

    输出格式：
    按照处理的作业顺序输出$n$行，每行输出机器编号、处理时长、占用时间区间，用空格分隔.

    输入样例：
    ```plaintext
    5 2
    1 2
    2 5
    3 4
    4 2
    5 3
    ```

    输出样例：

    ```plaintext
    1 5 0-5
    2 4 0-4
    2 3 4-7
    1 2 5-7
    1 2 7-9
    ```

    答案：
    1.`index = i` 2.`get_min(machine)` 3.`+= A[j].t`

??? tips "2020mid"

    <center><img src = "../figures/greedy/2020mid1.png" style="zoom: 50%;"/></center>
    <center><img src = "../figures/greedy/2020mid2.png" style="zoom: 50%;"/></center>
