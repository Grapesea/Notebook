# Ascend C 学习笔记

> 华为Ascend C算子开发之路.

## Lab01: CANN环境配置

环境：VMWare Workstation + Debian 13.5

### 工具链配置

```bash
sudo apt-get install -y gcc make net-tools python3 python3-dev python3-pip 
```

conda安装：

```bash
~$ ~/miniconda3/bin/conda init bash
no change     /home/grapesea/miniconda3/condabin/conda
no change     /home/grapesea/miniconda3/bin/conda
no change     /home/grapesea/miniconda3/bin/activate
no change     /home/grapesea/miniconda3/bin/deactivate
no change     /home/grapesea/miniconda3/etc/profile.d/conda.sh
no change     /home/grapesea/miniconda3/etc/fish/conf.d/conda.fish
no change     /home/grapesea/miniconda3/shell/condabin/Conda.psm1
no change     /home/grapesea/miniconda3/shell/condabin/conda-hook.ps1
no change     /home/grapesea/miniconda3/lib/python3.14/site-packages/xontrib/conda.xsh
no change     /home/grapesea/miniconda3/etc/profile.d/conda.csh
modified      /home/grapesea/.bashrc
==> For changes to take effect, close and re-open your current shell. <==

~$ source ~/.bashrc
(base) ~$ which conda
conda --version
/home/grapesea/miniconda3/bin/conda
conda 26.5.3
```

新建conda虚拟环境：

```bash
conda create -n cann python=3.10
conda activate cann
```

安装其他的库：

```bash
pip3 install attrs cython numpy==1.24.0 decorator sympy cffi pyyaml pathlib2 psutil protobuf==3.20 scipy requests absl-py
```

安装cmake:

```bash
mkdir -p cmake-3.16 && wget -qO- "https://cmake.org/files/v3.16/cmake-3.16.0-rc1-Linux-x86_64.tar.gz" | tar --strip-components=1 -xz -C cmake-3.16
export PATH=`pwd`/cmake-3.16/bin:$PATH

# 验证
(cann) ~$ cmake --version
cmake version 3.16.0-rc1

CMake suite maintained and supported by Kitware (kitware.com/cmake).
```

### CANN 环境搭建

把[CANN资源](https://www.hiascend.com/developer/download/community/result?module=cann&cann=9.0.0)中下载得到的传入Debian虚拟机中：

```bash
scp Ascend-cann-toolkit_9.0.0_linux-x86_64.run grapesea@192.168.159.128:home/grapesea/tools
```

增加权限、校验完整性：

```bash
chmod +x Ascend-cann-toolkit_9.0.0_linux-x86_64.run
./Ascend-cann-toolkit_9.0.0_linux-x86_64.run --check
./Ascend-cann-toolkit_9.0.0_linux-x86_64.run --install
```

显示：

```bash
===========
= Summary =
===========

Driver:   Not installed.
Toolkit:  Ascend-cann-toolkit_9.0.0_linux-x86_64 install success, installed in /home/grapesea/Ascend.

Please make sure that the environment variables have been configured.
-  To take effect for current user, you can exec command below: source /home/grapesea/Ascend/cann/set_env.sh or add "source /home/grapesea/Ascend/cann/set_env.sh" to ~/.bashrc.
```

最后配一下环境变量就成功了：

```bash
source ~/Ascend/ascend-toolkit/set_env.sh
```

## Lab2: Hello World 算子实现

```bash
scp -r 2.3.4 grapesea@192.168.159.128:home/grapesea/codingspace/cann
```

