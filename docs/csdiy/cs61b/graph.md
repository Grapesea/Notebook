# Graph

## Introduction

图论常见问题：

- **s-t Path**: Is there a path between vertices s and t?
- **Connectivity**: Is the graph connected, i.e. is there a path between all vertices?
- **Biconnectivity**: Is there a vertex whose removal disconnects the graph?
- **Shortest s-t Path**: What is the shortest path between vertices s and t?
- **Cycle Detection**: Does the graph contain any cycles?
- **Euler Tour**: Is there a cycle that uses every edge exactly once?
- **Hamilton Tour**: Is there a cycle that uses every vertex exactly once?
- **Planarity**: Can you draw the graph on paper with no crossing edges?
- **Isomorphism**: Are two graphs isomorphic (the same graph in disguise)?

图论问题的难度是差别很大的，比如Euler Tour早在1873年就有$O(E)$的解法了，但是Hamilton Tour目前没有很高效的解答，最优的仅指数级复杂度.

s-t Path：检测两个节点之间连通性的问题，通常用DFS解决.

流程：

* Mark $v$;
* for each unmarked adjacent vertex $w$:
    * set $\text{edgeTo}[w] = v$;
    * $\text{DFS}(w)$.

代码：

```java
public static bool Connectivity(int src, int dest, Graph G) {
    boolean[] marked = new boolean[G.V()];
    dfs(G, src, marked);
    return marked[dest];
}

private static void dfs(Graph G, int v, boolean[] marked) {
    marked[v] = true;
    for (int w : G.adj(v)) {
        if (!marked[w]) {
            dfs(G, w, marked);
        }
    }
}
```

## Graph Traversals

### BFS & DFS

BFS:

```java
public static List<Integer> bfs(Graph G, int src, int dest) {
    boolean[] marked = new boolean[G.V()];
    int[] edgeTo = new int[G.V()];
    Arrays.fill(edgeTo, -1);
    
    Queue<Integer> queue = new LinkedList<>();
    queue.add(src);
    marked[src] = true;
    
    while (!queue.isEmpty()) {
        int v = queue.poll();
        for (int w : G.adj(v)) {
            if (!marked[w]) {
                marked[w] = true;
                edgeTo[w] = v;
                queue.add(w);
            }
        }
    }
    
    if (!marked[dest]) return null;
    List<Integer> path = new LinkedList<>();
    for (int v = dest; v != src; v = edgeTo[v]) {
        path.add(0, v);
    }
    path.add(0, src);
    return path;
}
```

DFS:

```java
public static List<Integer> dfs(Graph G, int src, int dest) {
    boolean[] marked = new boolean[G.V()];
    int[] edgeTo = new int[G.V()];
    Arrays.fill(edgeTo, -1);
    
    Stack<Integer> fringe = new Stack<>();
    
    fringe.push(src);
    
    while (!fringe.isEmpty()) {
        
    }
}
```



### Representing Graphs



## Shortest Paths



## Minimum Spanning Trees

### MSTs and Cut Property

