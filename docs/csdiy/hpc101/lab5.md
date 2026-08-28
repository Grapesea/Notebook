# Lab 5: Gemma4 端到端推理优化

<center>Grapesea</center>

[TOC]

> 参考资料：
>
> * [实验文档](https://hpc101.zjusct.io/lab/Lab5-Gemma4/)
>
> * [A Visual Guide to Gemma 4 12B - by Maarten Grootendorst](https://newsletter.maartengrootendorst.com/p/a-visual-guide-to-gemma-4-12b)，读了一遍非常通俗易懂.
> * 
>
> 

## GPTQ权重优化

首先学习一下原理：

Gemma 4 12B是一个“没有采用 encoder” 的小模型，实际上这指的是，在多模态情境下不使用encoder也获得了多模态理解和推理的能力.





## 端到端推理性能优化