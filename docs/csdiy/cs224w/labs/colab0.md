# Colab 0

???+ info "资源"

    [NetworkX](https://networkx.org/documentation/stable/)
    
    [Pytorch Geometric](https://pytorch-geometric.readthedocs.io/en/latest/)

---

## 基础语法

### Graph

```python
G = nx.Graph()   # 无向图
print(G.is_directed())

H = nx.DiGraph() # 有向图

G.graph["Name"] = "Bar"

print(H.is_directed())
print(G.graph)
```

结果：

```python
False
True
{'Name': 'Bar'}
```

### Node

重要的函数：

* `add_node`, `nodes()`, `add_nodes_from`

* `number_of_nodes()`

```python
G.add_node(0, feature = 5, label = 1)

node_0_attr = G.nodes[0]
print("Node 0 has the attributes {}".format(node_0_attr))

# 输出：Node 0 has the attributes {'feature': 5, 'label': 1}
```

查看所有节点的属性 (`data=True`表示显示节点相关的数据，默认`data=False`表示查看有哪些节点)：

```python
G.nodes(data = True)

# 输出：NodeDataView({0: {'feature': 5, 'label': 1}})

G.nodes()

# 输出：NodeView((0,))
```

一次性添加多个节点：

```python
G.add_nodes_from([
    (1, {"feature": 1, "label": 1}),
    (2, {"feature": 2, "label": 2})
])
```

查看所有节点信息：

```python
for n in G.nodes(data=True):
    print(node)
    
num_nodes = G.number_of_nodes()
print("G has {} nodes".format(num_nodes))

# 输出： 
# (0, {'feature': 5, 'label': 1})
# (1, {'feature': 1, 'label': 1})
# (2, {'feature': 2, 'label': 2})
# G has 3 nodes
```



