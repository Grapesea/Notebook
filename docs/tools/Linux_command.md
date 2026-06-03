# 杂项Linux指令

## 格式整理

* 只显示最后一级目录并且将其设置为青色.

    ```bash
    export PS1="\[\e[36m\]\W\[\e[0m\]\$ "
    ```

    如果希望持久化：

    ```bash
    echo 'export PS1="\[\e[36m\]\W\[\e[0m\]\$ "' >> ~/.bashrc
    source ~/.bashrc
    ```