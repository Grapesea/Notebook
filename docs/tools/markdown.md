> 用markdown写markdown备忘录，这行为怎么看起来这么抽象。

??? tips "多种Admonition语法类型"

    信息类：

    - `note` - 笔记/注释
    - `abstract` / `summary` / `tldr` - 摘要
    - `info` / `todo` - 信息/待办

    成功/提示类：

    - `tip` / `hint` / `important` - 提示/重要信息
    - `success` / `check` / `done` - 成功/完成

    警告类：

    - `question` / `help` / `faq` - 问题/帮助
    - `warning` / `caution` / `attention` - 警告/注意
    - `failure` / `fail` / `missing` - 失败/缺失
    - `danger` / `error` - 危险/错误

    其他：

    - `bug` - Bug 说明
    - `example` - 示例
    - `quote` / `cite` - 引用

    - 基本语法

    ```markdown
    !!! note "自定义标题"
        这是内容

    !!! warning
        这是警告内容（使用默认标题）

    ??? info "可折叠的框"
        点击展开才能看到内容

    ???+ tip "默认展开的可折叠框"
        默认是展开状态
    ```

    - 语法变体

    - `!!!` - 普通框
    - `???` - 可折叠框（默认折叠）
    - `???+` - 可折叠框（默认展开）
