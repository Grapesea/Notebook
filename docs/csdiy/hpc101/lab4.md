# Lab 4: AMSS-NCKU 数值相对论程序优化

<center>Grapesea</center>

[TOC]

> [Lab4 实验文档](https://hpc101.zjusct.io/lab/Lab4-AMSS-NCKU)
>
> [[2509.21652] A User-Friendly Python Interface for the Numerical Relativity Code AMSS-NCKU](https://arxiv.org/abs/2509.21652)

## 准备工作

环境配置没什么难点：

```bash
npx degit ZJUSCT/HPC101/src/lab4 lab4
./compile.sh # 发现缺个matplotlib包
pip install matplotlib
export AMSS_MPIEXEC="mpiexec --allow-run-as-root --use-hwthread-cpus" 
# 原本是默认使用物理核的，这样会触发 'not enough slots available in the system to satisfy the 30 slots that were requested by the application'
./run.sh --twop-cache
```

### CPU版本运行脚本

整合成一份`4.sh`脚本：

```bash
#!/bin/bash
#HPC --partition=lab4
#HPC --cpu=60
#HPC --mem=100Gi
#HPC --time=30m
set -euo pipefail

# hpc 默认在提交命令所在目录运行
echo "PWD=$(pwd)"
echo "Start: $(date)"

# 4.sh always means the CPU baseline. Keep the source configuration and
# environment consistent, even if a previous GPU run left it set to "yes".
sed -i -E 's/^(GPU_Calculation[[:space:]]*=[[:space:]]*).*/\1"no"      ## Use CPU version ABE/' AMSS_NCKU_Input.py
export AMSS_GPU_CALCULATION=no
export AMSS_MPI_PROCESSES=30
export AMSS_OMP_THREADS=1
export AMSS_ENABLE_GPU=OFF
export AMSS_ENABLE_OPENMP=OFF
export AMSS_BUILD_DIR="$PWD/build"
export AMSS_OUTPUT_ROOT="$PWD"
export AMSS_CACHE_DIR="$PWD/twopuncture_cache"
unset CUDACXX AMSS_CUDA_ARCHITECTURES

./compile.sh
./run.sh --twop-cache

# The CPU run stops at t=40, while the shipped golden trajectory extends to
# t=100.  Build the matching golden prefix from the configured final time.
FINAL_TIME=$(python3 -c 'import AMSS_NCKU_Input as cfg; print(cfg.Final_Evolution_Time)')
mkdir -p golden_cpu
awk -v cutoff="$FINAL_TIME" '
  /^[[:space:]]*#/ || NF == 0 { print; next }
  ($1 + 0) < cutoff { print }
' golden/bssn_BH.dat > golden_cpu/bssn_BH.dat

./check.sh GW250118/AMSS_NCKU_output golden_cpu
```

这里使用了扩展正则表达式来修改`GPU_Calculation`的值.

在lab2使用的x86机器上提交：（不知道怎么回事，如果使用Kunpeng arm64 920B环境一直报127错误）

```bash
hpc submit -p lab4 -c 60 -d -o 'results/4-%j.log' "./4.sh"
```

然后就是坐等运行完看baseline了，有一说一确实慢. 会在 lab4 所在容器中的`results/`目录下出现想要的结果.

（使用CPU验证时需要增加一道验证，将前面的40项裁剪出来跑验证程序，因为默认跑的是GPU的100道测评）

CPU baseline结果放在`4-85843.log`中:

```bash
 This Program Cost = 1742.2476229667664 Seconds

 The AMSS-NCKU-Python simulation is successfully finished.

Golden: /home/h3240104505/HPC101_lab/lab4/golden_cpu
Result: /home/h3240104505/HPC101_lab/lab4/GW250118/AMSS_NCKU_output
Trajectory: matched times 40/40, effective terms 236
Trajectory RMS: 0 (0.000000%)
Trajectory: PASS - RMS <= 0.001 (0.100000%)
Constraints: 40 time groups, 9 levels per group
Constraint maxima (level 0): Ham=0.27739667, Px=0.028132512, Py=0.031488238, Pz=0.026503396
Constraints: PASS - all maxima <= 2
FINAL: PASS
```

baseline总时长为1742.2476229667664s.

### GPU版本运行脚本

在前面的脚本的基础上，还需要修改一点东西才行：

```bash
#!/bin/bash
#HPC --partition=lab4g10
#HPC --cpu=16
#HPC --gpu=1
#HPC --mem=24Gi
#HPC --time=30m
set -euo pipefail

# hpc 默认在提交命令所在目录运行
echo "PWD=$(pwd)"
echo "Start: $(date)"

# 4g.sh always means the one-GPU baseline. Keep the source configuration and
# environment consistent, even if a previous CPU run left it set to "no".
sed -i -E 's/^(GPU_Calculation[[:space:]]*=[[:space:]]*).*/\1"yes"     ## Use GPU version ABEGPU/' AMSS_NCKU_Input.py
export AMSS_GPU_CALCULATION=yes
export AMSS_MPI_PROCESSES=1
export AMSS_OMP_THREADS=1
export AMSS_ENABLE_GPU=ON
export AMSS_ENABLE_OPENMP=OFF
export AMSS_CUDA_ARCHITECTURES=80
export AMSS_BUILD_DIR="$PWD/build_gpu_a100"
export AMSS_OUTPUT_ROOT="$PWD/gpu_output"
export AMSS_CACHE_DIR="$PWD/twopuncture_cache"
export CUDACXX=/usr/local/cuda/bin/nvcc
[[ -x "$CUDACXX" ]] || { echo "CUDA compiler missing: $CUDACXX" >&2; exit 1; }
mkdir -p "$AMSS_OUTPUT_ROOT"
nvidia-smi -L

echo "GPU_Calculation=$AMSS_GPU_CALCULATION"
echo "MPI ranks=$AMSS_MPI_PROCESSES, OMP threads=$AMSS_OMP_THREADS"
echo "Build=$AMSS_BUILD_DIR"
echo "Output=$AMSS_OUTPUT_ROOT"
echo "CUDA compiler=${CUDACXX:-disabled}"

./compile.sh
./run.sh --twop-cache
./check.sh "$AMSS_OUTPUT_ROOT/GW250118/AMSS_NCKU_output" golden
```

这样实现了自动修改`AMSS_NCKU_Input.py`中的`GPU_Calculation  = "yes"`开关，从而自动切换CPU/GPU模式.

提交方式：

```bash
hpc submit -p lab4g10 -c 16 -d -o 'results/4g-%j.log' "./4g.sh"
```

会在 lab2 所在容器中的`results/`目录下出现想要的结果.

于是得到了GPU版本的用时baseline（放在`4g-85694.log`中）:

```bash
 This Program Cost = 1721.3482825756073 Seconds

 The AMSS-NCKU-Python simulation is successfully finished.

Golden: /home/h3240104505/HPC101_lab/lab4/golden
Result: /home/h3240104505/HPC101_lab/lab4/gpu_output/GW250118/AMSS_NCKU_output
Trajectory: matched times 100/100, effective terms 596
Trajectory RMS: 0 (0.000000%)
Trajectory: PASS - RMS <= 0.001 (0.100000%)
Constraints: 100 time groups, 9 levels per group
Constraint maxima (level 0): Ham=0.28974817, Px=0.039343259, Py=0.047298107, Pz=0.044686547
Constraints: PASS - all maxima <= 2
FINAL: PASS
```

baseline总时长为1721.3482825756073s.

## 性能分析

### CPU Profiling

首先定好脚本：

```bash
```



### GPU Profiling





## 共享优化阶段：TwoPuncture 初值求解



## ABE CPU演化优化



## ABEGPU GPU 演化优化



## 思考题

> 1.AMSS-NCKU 的主要热点更接近规则 stencil、稠密线性代数，还是通信/调度开销？请结合 profile 结果说明.





> 2.在 CPU 平台上，MPI rank 数和 OpenMP thread 数如何权衡？描述你的最佳配置并解释选择这个配置的原因。MPI 和 OMP 同样作为并行化工具，虽然有自己的同步、通信方法，但是都可以达到并行的目的，可不可以只采用 MPI 或者 OMP 进行呢？有必要同时使用两者进行优化吗？





> 3.AMSS-NCKU 程序中从高到低有非常多的并行层级，例如最简单的 MPI 分块并行和 OMP 循环并行等；而你在分析源码的过程中或许还发现了其他可以并行的结构。简述一下你优化后的程序都在哪些并行结构上实现了并行。





>  4.如果优化前后结果精度出现小幅差异，如何判断它是合理的浮点误差还是程序错误？





> 5.对于只分配一个 MIG 实例的情况，你是否尝试过让 MPI 进程数（`MPI_processes`）大于 1？如果是，你观察到了什么问题？NVIDIA 是否为多个进程共享同一个 GPU 实例提供了相应方案？





> 6.在本实验的 GPU kernel 优化操作中，模板操作（Stencil，比如三维求导等）是一个广泛需要优化的部分。一味地使用 Shared Memory 加速是否一定是更好的？引入共享内存本身带来了什么性能问题？如果你在实验过程中有类似现象，也可以举例说明。





> 7.之前我们提到过，我们提供给大家的三张 A100 有 -40GB 和 -80GB 两种配置，虽然实测中本实验的性能没有明显区别，但是理论上是存在性能差异的。你能否说出有什么差异？请给出参考引用以佐证你的答案。





> 8.（Bonus）今年是我们首次直接将一个超算竞赛题目修改成实验，也是首次把一个完整的科学计算程序引入到实验中，并且首次在科学计算实验中着眼于 GPU 优化加速。欢迎你跟我们分享本次实验的体验，也欢迎你给出改进建议（锐评也可以，不会扣分的！）

体验是环境配置的基础要求不是很明确，花了很长时间去试错，导致baseline复现花了很长时间.
