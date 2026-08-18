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

我最绷不住的是这个问题，在8月13日晚上才发现这个逆天问题，白白浪费了3次提交机会和2h的debug时间：

<center><img src="./figures/lab4/whatcanisay.png" alt="what can i say" style="zoom:100%;" /></center>

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

input_backup="AMSS_NCKU_Input.py.4sh.$$"
cp AMSS_NCKU_Input.py "$input_backup"
trap 'cp "$input_backup" AMSS_NCKU_Input.py; rm -f "$input_backup"' EXIT
sed -i '/^[[:space:]]*Final_Evolution_Time[[:space:]]*=/c\Final_Evolution_Time = 40.0' AMSS_NCKU_Input.py
sed -i '/^[[:space:]]*Evolution_Step_Number[[:space:]]*=/c\Evolution_Step_Number = 10000000' AMSS_NCKU_Input.py

# 4.sh always means the CPU baseline. Keep the source configuration and
# environment consistent, even if a previous GPU run left it set to "yes".
export AMSS_GPU_CALCULATION=no
unset AMSS_FINAL_EVOLUTION_TIME AMSS_EVOLUTION_STEPS
export AMSS_MPI_PROCESSES=30
export AMSS_OMP_THREADS=1
export AMSS_ENABLE_GPU=OFF
export AMSS_ENABLE_OPENMP=OFF
export AMSS_OPT="-Ofast -ffast-math"
export AMSS_ARCH_FLAGS="-mcpu=native"
export AMSS_BUILD_DIR="$PWD/build_cpu_arm"
export AMSS_OUTPUT_ROOT="$PWD"
export AMSS_CACHE_DIR="$PWD/twopuncture_cache"
unset CUDACXX AMSS_CUDA_ARCHITECTURES

echo "Mode=CPU (ABE), MPI ranks=$AMSS_MPI_PROCESSES, OMP threads=$AMSS_OMP_THREADS"
echo "Build=$AMSS_BUILD_DIR"

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

提交：

```bash
hpc submit -p lab4 -c 60 -d -o 'results/4-%j.log' "./4.sh"
```

然后就是坐等运行完看baseline了，有一说一确实慢. 会在 lab4 所在容器中的`lab4-cpu/results/`目录下出现想要的结果.

（使用CPU验证时需要增加一道验证，将前面的40项裁剪出来跑验证程序，因为默认跑的是GPU的100道测评）

CPU baseline结果放在`4-85843-baseline.log`中:

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
export AMSS_MPI_PROCESSES=30
export AMSS_OMP_THREADS=1
export AMSS_ENABLE_GPU=ON
export AMSS_ENABLE_OPENMP=ON
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

提交方式：

```bash
hpc submit -p lab4g10 -c 16 -d -o 'results/4g-%j.log' "./4g.sh"
```

会在 lab2 所在容器中的`lab4-gpu/results/`目录下出现想要的结果.

于是得到了GPU版本的用时baseline（放在`4g-85694-baseline.log`中）:

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

首先定好脚本，为了快速确定热点，将原先的

```python
Final_Evolution_Time   = 100.0 if GPU_Calculation == "yes" else 40.0
...
Evolution_Step_Number    = 10000000               ## stop the calculation after the maximal step number
```

设置成shell脚本`4_s.sh`中的：

```shell
sed -i '/^[[:space:]]*Final_Evolution_Time[[:space:]]*=/c\Final_Evolution_Time = 1.0' AMSS_NCKU_Input.py
sed -i '/^[[:space:]]*Evolution_Step_Number[[:space:]]*=/c\Evolution_Step_Number = 1' AMSS_NCKU_Input.py
```

指令格式基本不变：

```bash
hpc submit -p lab4 -c 60 -d -o 'results/4_s-%j.log' ./4_s.sh
```

一次运行的时间（`4g_s-90496.log`中）：

```text
This Program Cost = 47.99874305725098 Seconds
```



### GPU Profiling

类似上面的小节，为了快速确定热点，将原先的

```python
Final_Evolution_Time   = 100.0 if GPU_Calculation == "yes" else 40.0
...
Evolution_Step_Number    = 10000000               ## stop the calculation after the maximal step number
```

设置成shell脚本`4g_s.sh`中的：

```shell
sed -i '/^[[:space:]]*Final_Evolution_Time[[:space:]]*=/c\Final_Evolution_Time = 1.0' AMSS_NCKU_Input.py
sed -i '/^[[:space:]]*Evolution_Step_Number[[:space:]]*=/c\Evolution_Step_Number = 1' AMSS_NCKU_Input.py
```

指令格式基本不变：

```bash
hpc submit -p lab4g10 -c 16 -d -o 'results/4g_s-%j.log' ./4g_s.sh
```

一次运行的时间（`4g_s-90496.log`中）：

```text
This Program Cost = 22.397433042526245 Seconds
```



## 共享优化阶段：TwoPuncture 初值求解

### 编译优化

文档给出的指导是：

> 包括增加编译选项，也包括为目标平台选择更合适的完整工具链. 

#### 编译选项

>   可以尝试：
>
> * -O2、-O3 等优化等级；
> * -march、-mtune 或对应编译器的目标架构选项；
> * 自动向量化；
> * OpenMP 编译和运行时选项；
>
> 架构选项必须与实际评测节点支持的指令集匹配. 课程 GPU 为 NVIDIA A100，其 compute capability 为 8.0（sm_80），当前 CMAKE_CUDA_ARCHITECTURES=80 已与目标架构匹配. CMakeLists.txt 中的 AMSS_OPT 只作用于 C++ 和 Fortran，CUDA 架构与其他 NVCC 参数需要单独设置. -Ofast、GCC/Clang 的 -ffast-math 或其他编译器对应的 fast-math 选项可能重排浮点表达式，改变求解器收敛过程或数值结果；使用后必须重新完成端到端正确性验证. 

首先我尝试了多种优化等级（`-O2`, `-O3`, `-Ofast`等），这个优化等级和目标架构选项是最优的，可以将单个evolve的时间从44s降低至38s：

```cmake
set(AMSS_OPT "-Ofast -ffast-math" CACHE STRING "C/C++/Fortran optimization level")
set(AMSS_ARCH_FLAGS "-mcpu=native" CACHE STRING "Architecture-specific compiler flags")
```

然而并不够，我跑了几次觉得可以竞争全HPC101最忧郁之人了：

<center><img src="./figures/lab4/fail.png" alt="what can i say" style="zoom:100%;" /></center>

<center><img src="./figures/lab4/timeout.png" alt="what can i say" style="zoom:100%;" /></center>

跑到第39个evolve恰好超时这谁绷得住……我以为代码日志中的1750s没超过30min就能直接提交看架构理解的，然而却触及了一个矛盾：只有优化到一定程度才能跑通测试不超时，那么基础的就有30分了吧……

后来我成功提交了一次，不知道是不是OJ的设置修改过了，只拿到了6分.

然而我其实很早就得到了31s单步的结果. 追踪了好久编译链，才发现是在`4.sh`中显式指定了本地 ABE 模块用 Arm 编译器，而提交到OJ上却仍然是GNU编译，所以没有任何的加速.



### 初值求解优化

首先还是老老实实 profile. `TwoPunctures.C` 中的`TwoPunctureABE` 里面最热的几个函数大概是：

```text
LineRelax_be        32.22%
LineRelax_al        23.13%
ThomasAlgorithm     16.77%
vectorized cos       9.02%
malloc/free            ~7%
```

也就是说，最显眼的是线松弛、Thomas 三对角求解和它们高频触发的动态内存分配. 于是我依次试了下面这些：

1. 把 `LineRelax_be`、`LineRelax_al` 和 `ThomasAlgorithm` 里的 `new[]/delete[]` 提到外层，每个线程预分配并复用工作区；
2. 把原来碎成 `NRELAX` 次的 `relax()` 调用合并到一个并行区，减少 OpenMP 反复 fork-join；
3. 利用 `nphi=26`，尝试让 13 个线程分别处理 red/black 阶段中独立的 `k` 平面；
4. 把 `NRELAX` 从 200 降到 100，观察 BiCGStab 和 Newton 的收敛；
5. 继续尝试并行 `J_times_dv`，并把 `JFD_times_dv` 的临时导数数组改成复用工作区. 

看上去每一项都非常合理，实则不是特别好. 单独做内存复用时，TwoPuncture 仍然在 247s 左右；OpenMP 版本在开发环境里反而跑到了 254--286s. 这里主要有三个原因：

* `nphi=26` 的并行粒度太小，理论上最多也就 13 个独立平面，线程启动、barrier 和调度开销很容易把收益吃干净；
* `LineRelax` 本身有较强的数据依赖和不规则访存，不能像普通三重循环一样随便 `collapse`；
* 只减少 `malloc/free` 没有改变求解器迭代次数，而真正的大头仍然是松弛和矩阵向量计算. 

`NRELAX=100` 是唯一看起来比较像正优化的方案，冷启动大约从 247s 降到了 205s；`puncture_parameters_new.txt` 一致，`Ansorg.psid` 最大绝对误差约为 `5.33e-14`. 但继续叠加 `J_times_dv` 并行后没有完成可靠的长程验证，而且在目标环境出现了明显的性能回退，不得不回滚.

回滚以后我用相同的 `TwoPunctureinput.par` 做了短测，Newton/BiCGStab 前 11 次残差和 `4-90943.log` 逐项一致：

```text
Newton 初始 |F| = 9.566257e-03
bicgstab #1 = 1.064e+00
bicgstab #11 = 4.014e-04
```

所以这次共享优化阶段的最终结论比较朴素：初值求解确实有可优化空间，但目前尝试的 OpenMP 粒度不合适.


### TwoPuncture GPU 化（Bonus）




## ABE CPU演化优化

在 ABE 代码里我实际保留的一项优化是关闭 RHS 的全数组 sanity scan. 原来的 `src/bssn_rhs.f90` 每次进入 `compute_rhs_bssn` 都会对 22 个三维数组执行 `sum()` 来检查 NaN. 这对调试很有用，但放在每个 RK stage 的高频路径上，相当于反复把整片内存扫一遍. 现在通过 CMake 开关控制：

```bash
# 正式评测，默认关闭
AMSS_ENABLE_SANITY_CHECK=OFF ./compile.sh

# 调试数值问题时重新打开
AMSS_ENABLE_SANITY_CHECK=ON ./compile.sh
```

这个修改不改变 RHS 的数学计算，只删除生产路径上的诊断扫描，因此比直接改 stencil、精度或物理参数安全得多. 至于把 ABE 本身强行改成 OpenMP，我最后没有采用：程序已经用 30 个 MPI rank，粗网格又不一定有足够并行度，如果每个 rank 再开一堆线程，很可能是负优化. 





## ABEGPU GPU 演化优化



## 思考题

> 1.AMSS-NCKU 的主要热点更接近规则 stencil、稠密线性代数，还是通信/调度开销？请结合 profile 结果说明.

主要是通信调度开销：

* 在CPU baseline的perf文件（`results/perf_cpu_baseline/perf_report.txt`）中可以看出（仅截取所有＞0.25%的）：

    ```text
    # Overhead  Command  Shared Object                                       Symbol                                                                                                                                                    
    # ........  .......  ..................................................  ..........................................................................................................................................................
    #
        55.68%  ABE      libopen-pal.so.80.0.5                               [.] 0x00000000000f13c4
         7.74%  ABE      ABE                                                 [.] compute_rhs_bssn_
         5.91%  ABE      libmpi.so.40.40.7                                   [.] 0x0000000000230c1c
         5.90%  ABE      libmpi.so.40.40.7                                   [.] 0x0000000000230f24
         4.08%  ABE      libopen-pal.so.80.0.5                               [.] 0x00000000000f1324
         3.53%  ABE      libopen-pal.so.80.0.5                               [.] 0x00000000000f13b0
         1.46%  ABE      libc.so.6                                           [.] __memcpy_sve
         1.28%  ABE      ABE                                                 [.] polint_
         1.22%  ABE      ABE                                                 [.] fdderivs_
         1.11%  ABE      ABE                                                 [.] kodis_
         1.05%  ABE      ABE                                                 [.] lopsided_
         0.96%  ABE      libopen-pal.so.80.0.5                               [.] opal_progress
         0.91%  ABE      libc.so.6                                           [.] __memset_sve_zva64
         0.61%  ABE      libc.so.6                                           [.] malloc
         0.54%  ABE      ABE                                                 [.] prolong3_
         0.51%  ABE      libmpi.so.40.40.7                                   [.] 0x0000000000230c28
         0.51%  ABE      libopen-pal.so.80.0.5                               [.] 0x00000000000608c8
         0.45%  ABE      libc.so.6                                           [.] cfree@GLIBC_2.17
         0.39%  ABE      ABE                                                 [.] fderivs_
         0.32%  ABE      libmpi.so.40.40.7                                   [.] 0x0000000000287ec0
         0.26%  ABE      libopen-pal.so.80.0.5                               [.] 0x0000000000027238
         0.26%  ABE      libopen-pal.so.80.0.5                               [.] 0x00000000000f1230
    ...
    ```

    可以看出`libopen-pal.so`的无符号地址占了大头，65%以上的都是OpenMPI的opal运行时库；BSSN的求解核心函数占比并不大，最高的5项是7.74%的`compute_rhs_bssn_`+1.28%的`polint_`+1.22%的`fdderivs_`+1.11%的`kodis_`+1.05%的`lopsided_`，也只有12.4%. 也就是说，CPU 时间里真正用来做数值计算的连 15% 都不到，剩下 60%+ 都耗在 MPI 通信/自旋等待上.

* CPU的硬件计数器文件中也可以管窥热点（`results/perf_cpu_baseline/perf_stat.txt`）：

    ```text
          1,325,354.33 msec task-clock:u                     #   27.809 CPUs utilized             
                     0      context-switches:u               #    0.000 /sec                      
                     0      cpu-migrations:u                 #    0.000 /sec                      
             2,134,941      page-faults:u                    #    1.611 K/sec                     
     3,761,369,558,311      cycles:u                         #    2.838 GHz                       
     7,173,110,848,608      instructions:u                   #    1.91  insn per cycle            
     1,036,512,680,199      branches:u                       #  782.065 M/sec                     
         8,548,328,888      branch-misses:u                  #    0.82% of all branches           
     3,005,760,598,612      L1-dcache-loads:u                #    2.268 G/sec                     
        11,228,452,875      L1-dcache-load-misses:u          #    0.37% of all L1-dcache accesses 
        15,847,323,125      LLC-loads:u                      #   11.957 M/sec                     
         7,895,422,838      LLC-load-misses:u                #   49.82% of all LL-cache accesses  
    
          47.658499836 seconds time elapsed
    
        1302.984115000 seconds user
          26.259599000 seconds sys
    ```

    可以看出，LLC-load-misses 高达 49.82%，末级缓存命中率很差，一半的 LLC load 都要去内存拿数据. 这既可能是 stencil 计算本身访存局部性差，也很可能是 opal/mpi 那些高频轮询共享内存标志位/队列，产生的cache line bouncing 和 false sharing造成的，因此也不是 stencil 内核开销.



> 2.在 CPU 平台上，MPI rank 数和 OpenMP thread 数如何权衡？描述你的最佳配置并解释选择这个配置的原因. MPI 和 OMP 同样作为并行化工具，虽然有自己的同步、通信方法，但是都可以达到并行的目的，可不可以只采用 MPI 或者 OMP 进行呢？有必要同时使用两者进行优化吗？

* 一部分实验结果：

    | 日志        | MPI processes | OMP Threads | 单次evolve运行时间/s |
    | ----------- | ------------- | ----------- | -------------------- |
    | 4_95698.log | 15            | 2           | ~51                  |
    | 4_95632.log | 10            | 3           | ~55                  |
    | baseline    | 30            | 1           | ~37                  |

    我也感觉奇怪，优化实在是做不到，问了AI得到的结果是：

    - 修改的块级 OpenMP：粒度错了，`Parallel::distribute` 里 `split_size = block_size/nodes`，块数随 rank 数同比例缩放 → 每 rank 每层只有 **~1 个块**。对块做 `parallel for` 无块可并.
    - 已有的细粒度 OpenMP（`fderivs/fdderivs/kodis/lopsided` 里的 `!$omp parallel do`）：每次 stencil 调用都 fork/join 一次线程组，一次 RHS 里有几十次调用，开销被放大几十倍.
    -  perf 显示 ~55% 时间在 `libopen-pal` 自旋等待（MPI 同步），真正 compute 只占小头.



> 3.AMSS-NCKU 程序中从高到低有非常多的并行层级，例如最简单的 MPI 分块并行和 OMP 循环并行等；而你在分析源码的过程中或许还发现了其他可以并行的结构. 简述一下你优化后的程序都在哪些并行结构上实现了并行. 

* 



>  4.如果优化前后结果精度出现小幅差异，如何判断它是合理的浮点误差还是程序错误？

嗯，我也不是特别明白，大概讲讲自己的验证思路：

* 在check.sh测试时稳定复现错误出来的基本可以确定是程序错误
* 



> 5.对于只分配一个 MIG 实例的情况，你是否尝试过让 MPI 进程数（`MPI_processes`）大于 1？如果是，你观察到了什么问题？NVIDIA 是否为多个进程共享同一个 GPU 实例提供了相应方案？

* 



> 6.在本实验的 GPU kernel 优化操作中，模板操作（Stencil，比如三维求导等）是一个广泛需要优化的部分. 一味地使用 Shared Memory 加速是否一定是更好的？引入共享内存本身带来了什么性能问题？如果你在实验过程中有类似现象，也可以举例说明. 

* 不好



> 7.之前我们提到过，我们提供给大家的三张 A100 有 -40GB 和 -80GB 两种配置，虽然实测中本实验的性能没有明显区别，但是理论上是存在性能差异的. 你能否说出有什么差异？请给出参考引用以佐证你的答案. 

* 



> 8.（Bonus）今年是我们首次直接将一个超算竞赛题目修改成实验，也是首次把一个完整的科学计算程序引入到实验中，并且首次在科学计算实验中着眼于 GPU 优化加速. 欢迎你跟我们分享本次实验的体验，也欢迎你给出改进建议（锐评也可以，不会扣分的！）

体验是环境配置的基础要求不是很明确，花了很长时间去试错，导致baseline复现花了很长时间.
