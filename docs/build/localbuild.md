## Git环境安装

### 软件安装

首先安装Git bash（针对Windows系统）：[Git - Downloading Package](https://git-scm.com/downloads/win)

安装一个可以提供Git功能的IDE，常用的是Visual Studio Code（即VSCode）：[Visual Studio Code - Code Editing. Redefined](https://code.visualstudio.com/)

### 配置Git环境

Windows系统中：打开cmd或者windows自带的powershell；

配置全局用户名：

```bash
git config --global user.name "你的用户名"
```

配置全局邮箱：

```bash
git config --global user.email "你的邮箱@example.com"
```

此时为了验证配置成功，可以使用指令：

```bash
git config --list
```

效果图示例：

<center><img src="../figures/3.png" style="zoom: 40%;" /></center>

!!! tips

    cmd打开方式：键盘上按住`Win+R`，打开窗口中输入cmd并确定即可；
        
    <center><img src="../figures/1.png" style="zoom: 50%;" /></center>
        
    powershell打开方式：键盘上按住`Win`，在搜索框中输入`powershell`并打开对应界面；
        
    <center><img src="../figures/2.png" style="zoom: 40%;" /></center>

### 在VSCode中配置Git

VSCode通常会自动检测Git，你也可以：

打开VSCode设置（Ctrl + ,），搜索"git.path"。如果需要，手动指定Git路径（默认是 `C:\Program Files\Git\bin\git.exe`）

### Clash for Windows的安装



## Git Clone：将文档文件夹所有内容放置到自己的电脑中

本站点GitHub仓库是https://github.com/grapesea/paperstudio，你可以在电脑的某个空间足够的磁盘中（如E盘）输入以下命令来克隆：

```bash
PS E:\> git clone https://github.com/grapesea/paperstudio
```

如果只想要最近的1次git记录，可以：

```bash
PS E:\> git clone --depth 1 https://github.com/grapesea/paperstudio
```

这样你的E盘中就出现paperstudio这个文件夹了！

## 本地预览

首先安装

只需要输入以下命令即可：

```bash
mkdocs serve
```