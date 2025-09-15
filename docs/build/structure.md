## 本文档的结构

powershell中使用`tree`指令可以看出：

```bash
PS E:\paperstudio> tree
卷 新加卷 的文件夹 PATH 列表
卷序列号为 E843-9950
E:.
├─.git //省略了.git文件夹结构
├─.github
│  └─workflows
├─docs
│  ├─build
│  │  └─figures
│  ├─graph
│  ├─instruct
│  │  ├─1.workflow
│  │  ├─2.text
│  │  │  └─figures
│  │  ├─3.art
│  │  │  └─figures
│  │  ├─4.distribute
│  │  └─5.score
│  │      └─figures
│  ├─interview
│  ├─product
│  ├─resource
│  │  ├─etc
│  │  ├─font
│  │  ├─media
│  │  └─photo
│  └─rule
│      ├─constitution
│      ├─detail
│      └─method
└─site //省略了site文件夹结构
```

我们的文档修改只需要关注docs文件夹以及mkdocs.yml这份设置文件。

另外，site文件夹是根据`mkdocs.yml`和`docs`文件夹内的文件，搭配workflow生成的静态html，是用于本地部署的静态网站文件，所以可以定期使用以下命令来清理：

```bash
mkdocs build --clean
```