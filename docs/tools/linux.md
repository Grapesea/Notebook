> 我安装的是WSL以及VMWare Workstation，配置Ubuntu 20.04 LTS.

??? tips "Firefox浏览器连接Github"

    Firefox令人讨厌的安全限制导致github都登陆不了.
    
    于是我先下载了一下Watt Toolkit，运行之后终端里使用指令：
    
    ```bash
    nslookup github.com
    ```
    
    返回的一段中有：
    
    ```bash
    Name:   github.com
    Address: 127.0.0.1
    ```
    
    这是非常错误的，因为github被设置到了回环地址上，所以访问不了.
    
    使用：
    
    ```bash
    sudo nano /etc/hosts
    ```
    
    删除文件中所有关于github网址的字段，然后`ctrl+X`退出.
    
    再回到命令行验证nslookup就会发现连接成功.
    
    打开Firefox浏览器，能连接到github.

??? tips "下载stegsolve并运行`.jar`文件"

    省流能用版：
    
    按以下顺序依次执行：
    
    ```bash
    sudo apt update
    sudo apt install default-jdk
    mkdir ~/tools
    cd ~/tools
    wget http://www.caesum.com/handbook/Stegsolve.jar -O stegsolve.jar
    chmod +x stegsolve.jar
    java -jar stegsolve.jar
    ```
    
    在Ubuntu上下载并运行Stegsolve的方法如下：
    
    首先确保系统已安装Java：
    
    ```bash
    # 检查是否已安装Java
    java -version
    
    # 如果未安装，安装OpenJDK
    sudo apt update
    sudo apt install default-jre
    
    # 或者安装完整的JDK
    sudo apt install default-jdk
    ```
    
    下载Stegsolve：
    
    **方法一：使用wget直接下载**
    
    ```bash
    # 创建工具目录
    mkdir ~/tools
    cd ~/tools
    
    # 下载stegsolve.jar
    wget http://www.caesum.com/handbook/Stegsolve.jar -O stegsolve.jar
    
    # 或者从GitHub下载
    wget https://github.com/eugenekolo/sec-tools/raw/master/stego/stegsolve/stegsolve.jar
    ```
    
    **方法二：使用git克隆整个工具集**
    
    ```bash
    git clone https://github.com/eugenekolo/sec-tools.git
    cd sec-tools/stego/stegsolve/
    ```
    
    <br/>
    
    运行Stegsolve：
    
    ```bash
    # 给予执行权限
    chmod +x stegsolve.jar
    
    # 运行Stegsolve
    java -jar stegsolve.jar
    ```
    
    创建桌面快捷方式：
    
    **方法一：创建shell脚本**
    
    ```bash
    # 创建启动脚本
    nano ~/tools/stegsolve.sh
    
    # 添加以下内容：
    #!/bin/bash
    cd ~/tools
    java -jar stegsolve.jar
    
    # 给予执行权限
    chmod +x ~/tools/stegsolve.sh
    ```
    
    **方法二：创建.desktop文件**
    
    ```bash
    nano ~/.local/share/applications/stegsolve.desktop
    ```
    
    <br/>
    
    添加以下内容：
    
    ```
    [Desktop Entry]
    Name=Stegsolve
    Comment=Steganography solver
    Exec=java -jar /home/yourusername/tools/stegsolve.jar
    Icon=applications-graphics
    Terminal=false
    Type=Application
    Categories=Graphics;
    ```
    
    添加到PATH（可选）：
    
    ```bash
    # 编辑.bashrc文件
    nano ~/.bashrc
    
    # 添加别名
    echo "alias stegsolve='java -jar ~/tools/stegsolve.jar'" >> ~/.bashrc
    
    # 重新加载配置
    source ~/.bashrc
    ```
    
    解决可能的问题：
    
    **如果遇到显示问题：**
    
    ```bash
    # 安装必要的图形库
    sudo apt install libxtst6 libxrender1 libxi6
    
    # 如果使用远程连接，确保X11转发
    ssh -X username@hostname
    ```
    
    **权限问题：**
    
    ```bash
    # 确保文件有执行权限
    chmod 755 stegsolve.jar
    ```
    
    使用方法：
    
    运行后会打开图形界面，可以：
    
    * File → Open 打开图片文件
    * 使用左右箭头浏览不同的颜色通道
    * Analyse → Data Extract 进行数据提取
    * Analyse → Image Combiner 进行图片对比
    
    这样就可以在Ubuntu上成功运行Stegsolve进行隐写术分析了.

??? tips "临时将虚拟机中的文件传输到win主机中"

    虚拟机中进入对应文件夹，然后：
    
    ```bash
    python3 -m http.server 8000
    ```
    
    打开另一个终端查看虚拟机ip：
    
    ```bash
    $ hostname -I
    #举例
    192.168.1.1
    ```
    
    在Win主机的浏览器中输入：`192.168.1.1/8000`即可访问这个文件夹
    
    但是总感觉丢了数据，虚拟机中225K的图片传到win里面只有220K，奇怪.

??? tips "解决VMWare虚拟机卡顿问题"

    安装 VMware 后电脑卡顿是常见问题,这里有一些实用的解决方法:
    
    **VMware 内部设置优化:**
    - 降低虚拟机分配的内存和 CPU 核心数,只分配实际需要的资源(建议主机保留至少 4GB 内存)
    - 关闭不用的虚拟机,避免多个虚拟机同时运行
    - 禁用不必要的虚拟硬件(如软驱、打印机、USB 控制器等)
    - 将虚拟硬盘存储在固态硬盘(SSD)上而非机械硬盘
    - 关闭虚拟机的 3D 图形加速(如果不需要)
    
    **Windows 系统优化:**
    - 关闭 VMware 的后台服务:打开"服务"(services.msc),找到 VMware 相关服务(如 VMware Authorization Service),将启动类型改为"手动",只在使用时启动
    - 禁用 Hyper-V(如果同时安装了):在"启用或关闭 Windows 功能"中取消勾选 Hyper-V
    - 调整 Windows 电源计划为"高性能"
    - 关闭不必要的启动项和后台程序
    
    **硬件层面:**
    - 增加物理内存(RAM)是最直接有效的方法
    - 确保有足够的硬盘空间(至少保留 20% 空闲)
    - 检查 CPU 和硬盘使用率,找出具体瓶颈
    
    如果只是偶尔使用虚拟机,可以考虑将 VMware 设置为需要时才手动启动,而不是开机自动运行所有服务。这样能显著减少对系统资源的占用。

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

