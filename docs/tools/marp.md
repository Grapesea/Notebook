> Marp是一款将markdown转换成slides的插件.

##  Setup

在VSCode中下载Marp插件，并在 `.md` 文件的 front matter 里声明 `marp: true` ，以激活幻灯片预览模式. 如：

```markdown
---
marp: true
---

# 第一张幻灯片

---

# 第二张幻灯片
```

需要注意的是，插件 Markdown Preview Enhanced 会接管 VSCode 的 Markdown 预览功能，替换成它自己的预览——而它不支持 Marp. 工具栏的预览图标也会被替换成 MPE 的版本.

**解决方法：** 不要点工具栏上的预览按钮，而是用命令面板：

1. 按 `Ctrl+Shift+P`（Mac 用 `Cmd+Shift+P`）
2. 输入并选择 **"Markdown: Open Preview to the Side"**（注意不是 MPE 的那个）

或者临时禁用 MPE 插件再试.

## 添加自定义CSS文件

从截图来看，右侧预览已经是 Marp 幻灯片效果了（分页、有页码），但**主题样式没有生效**——没有蓝色 header、没有 ZJU logo，字体也不对。这是主题加载失败的问题，不是预览功能的问题。

---

## 根本原因：自定义主题未在 VSCode 中注册

Marp 插件不会自动扫描 CSS 文件，必须在 VSCode 设置里手动指定主题路径.

* 打开 VSCode 设置（`Ctrl+,`），搜索 `marp themes`，找到 **Marp: Themes** 项，点击 **Add Item**，填入你的 CSS 文件的**相对路径**（相对于工作区根目录），例如：

    ```
    ./themes/zju.css
    ```

    或者直接编辑 `.vscode/settings.json`：

    ```json
    {
      "markdown.marp.themes": [
        "./themes/zju.css"
      ]
    }
    ```

* 确认文件结构

    ```
    你的项目/
    ├── .vscode/
    │   └── settings.json
    ├── themes/
    │   └── zju.css        ← CSS 文件在这里
    └── demo.md
    ```

* 关掉预览面板，重新 `Ctrl+Shift+P` → **Markdown: Open Preview to the Side**。

## DIY配置

???+ notes "自己折腾的基础配置"

    ```markdown
    ---
    marp: true
    theme: gaia
    paginate: true
    _footer: "" 
    headingDivider: [1, 4]
    style: |
      /* 全局字号调整 */
      section {
        font-size: 25px;
        font-family: "Times New Roman", "Simsun", serif;
        padding: 40px;
        justify-content: flex-start !important; /* 顶部对齐 */
        align-items: flex-start !important;    /* 左对齐 */
        text-align: left;           /* 文本左对齐 */
        padding: 50px;
      }
      section::after {
        display: none;
      }
      /* 让列表更紧凑 */
      li {
        margin-bottom: 5px;
      }
      img {
        max-width: 100%;
        max-height: 70%; /* 留出 30% 给文字空间 */
        object-fit: contain; /* 保持比例 */
        display: block;
        margin: 0 auto;
      }
    ---
    ```