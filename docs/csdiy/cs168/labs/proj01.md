# Project 01: Traceroute

## Guide

### Networking Background

Protocols - Building Blocks.

Internet的layers:

* Layer 1: Physical

* Layer 2: Link

* Layer 3: Internet (Network of Networks)，包括End Hosts, Routers，一条message需要经过多次hop才能到达目标，一个route必须forward这条message以接近final destination.

    The Internet only offers **best-effort** service

* Layer 4: Transport，添加了额外的特性以保证可靠的传递

* Layer 7: Application,

<img src="https://sp25.cs168.io/assets/projects/proj1/06-layers.png" alt="img" style="zoom:67%;" />



## Setup and Debug

下载完zip文件之后，

```bash
$ sudo python3 traceroute.py cmu.edu
```



## Project 1A: Basic Traceroute