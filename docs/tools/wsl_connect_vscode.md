想要在Windows的VSCode中打开WSL2中的文件，可以先：

```bash
vim ~/.bashrc
```

添加：

```bash
export http_proxy="http://127.0.0.1:7890" # 7890是本机系统代理端口
export https_proxy="http://127.0.0.1:7890"
```

保存设置：

```bash
source ~/.bashrc
```

然后返回VScode，点击最左下角的双箭头标志，等待连接即可.