









<center>
  <font face="黑体" size = 100>
    《计算机网络》实验报告
  </font>
</center> 
<center><font face="黑体" size = 4>
    姓名：
  </font>
</center> 
<center><font face="黑体" size = 4>
    学院：
  </font> 
</center> 
<center><font face="黑体" size = 4>
    系：
  </font> 
</center> 
<center><font face="黑体" size = 4>
    专业：
  </font>
</center> 
<center><font face="黑体" size = 4>
    学号：
  </font>
</center> 
<center><font face="黑体" size = 4>
    指导教师：
  </font>
</center> 







<center><font face="黑体" size = 5>
    报告日期:  年 月 日
  </font>
</center> 



<div STYLE="page-break-after: always;"></div>



# Lab1 <此处替换为实验名称>

> <此处替换为姓名> <此处替换为专业> <此处替换为学号>

## 实验目的和要求

- 初步了解WireShark软件的界面和功能
- 熟悉各类常用网络命令的使用

## 实验内容和原理

- Wireshark是PC上使用最广泛的免费抓包工具，可以分析大多数常见的协议数据包。有Windows版本、Linux版本和Mac版本，可以免费从网上下载  
- 初步掌握网络协议分析软件Wireshark的使用，学会配置过滤器
- 根据要求配置Wireshark，捕获某一类协议的数据包
- 在PC机上熟悉常用网络命令的功能和用法: Ping.exe，Netstat.exe, Telnet.exe, Tracert.exe, Arp.exe, Ipconfig.exe, Net.exe, Route.exe, Nslookup.exe
- 利用WireShark软件捕捉上述部分命令产生的数据包

## 主要仪器设备

- 联网的PC机
- WireShark协议分析软件

## 操作方法与实验步骤

**按照以下的步骤进行实验，你的过程截图和实验结果应放在 [实验结果与分析](#result) 中的相应位置。（实验报告中请去除此段）**

1. 安装网络包捕获软件Wireshark
2. 配置网络包捕获软件，捕获所有类型的数据包
3. 配置网络包捕获软件，只捕获特定类型的包
4. 在Windows命令行方式下，执行适当的命令，完成以下功能(请以管理员身份打开命令行)：
   - 测试到特定地址的联通性、数据包延迟时间
   - 显示本机的网卡物理地址、IP地址 	 	
   - 显示本机的默认网关地址、DNS服务器地址 	 	
   - 显示本机记录的局域网内其它机器IP地址与其物理地址的对照表
   - 显示从本机到达一个特定地址的路由 	 	
   - 显示某一个域名的IP地址
   - 显示已经与本机建立TCP连接的端口、IP地址、连接状态等信息
   - 显示本机的路由表信息，并手工添加一个路由
   - 显示本机的NetBIOS名称	 	
   - 显示局域网内某台机器的共享资源 	 	
   - 使用telnet连接WEB服务器的端口，输入（\<cr\>表示回车）获得该网站的主页内容：
     - GET / HTTP/1.1
     - Host:www.baidu.com

​	5. 利用WireShark实时观察在执行上述命令时，哪些命令会额外产生数据包，并记录这些数据包的种类。

## <span id='result'> 实验结果与分析 </span>

1. **这里应给出详实的实验结果。分析应有条理，要求采用规范的书面语。**

2. **原则上要求使用图片与文字结合的形式说明，因为word和PDF文档不支持视频，所以请不要使用视频文件。**
3. **图片请在垂直方向，不要横向。不要用很大的图片，请先做裁剪操作。**

**（实验报告中请去除以上内容）**

- 运行Wireshark软件，主界面是由哪几个部分构成？各有什么作用？
- 开始捕获网络数据包，你看到了什么？有哪些协议？
- 配置显示过滤器，让界面只显示某一协议类型的数据包。
- 配置捕获过滤器，只捕获某类协议的数据包。
- 利用ping, ipconfig, arp, tracert, nslookup, nbtstat, route, netstat, NET SHARE, telnet命令完成在实验步骤4中列举的11个功能。
- 观察使用ping命令时在WireShark中出现的数据包并捕获。这是什么协议？
- 观察使用tracert命令时在WireShark中出现的数据包并捕获。这是什么协议？
- 观察使用nslookup命令时在WireShark中出现的数据包并捕获。这是什么协议？
- 观察使用telnet命令时在WireShark中出现的数据包并捕获。这是什么协议？

### 思考题

**根据你看到的数据包，分别解答以下协议的问题（实验报告中请去除此段）：**

- WireShark的两种过滤器有什么不同？
- 哪些网络命令会产生在WireShark中产生数据包，为什么？
- ping发送的是什么类型的协议数据包？什么时候会出现ARP消息？ping一个域名和ping一个IP地址出现的数据包有什么不同？

## 讨论、心得

**简要地叙述一下实验过程中的感受，以及其他的问题描述和自己的感想。特别是实验中遇到的困难，最后如何解决的。（实验报告中请去除本段）**