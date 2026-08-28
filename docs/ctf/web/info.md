

## 信息收集

### ZJU bus 42

首先查看前端，尝试curl:

```bash
$ curl -s -i https://sbus-042-bigturtlesjourney.zjusec.net/ | head -60
HTTP/1.1 200 Connection established

HTTP/2 200
server: nginx/1.11.1
date: Wed, 19 Aug 2026 20:44:50 GMT
content-type: text/html; charset=UTF-8
look: MFCEEM2YGNIXOWDXHU6Q====

<!DOCTYPE html>
<html>
<head>
        <title>大乌龟找妈妈</title>
</head>
<body>
        <div id="body" style="border-radius: 5px;background-color: #d0cece;padding: 20px 20px 20px 20px;">
                <h1>大乌龟找妈妈</h1>
                <p>找啊找，找不到，东找找，西找找，都在哪里呀？？？</p>
                <p>hint:flag由多部分组成，几部分？乌龟几部分就是几部分。本题意在考察收集信息的能力。</p>
                <!--Good Job! The first part is AAA{, the next part is also in this page, but maybe it has been encoded? Try to search for it!-->
        </div>
</body>
</html>
```

得到第一部分是`AAA{`，后面的部分是`MFCEEM2YGNIXOWDXHU6Q====`，两次base64解码可以得到`h0w_t0_`.

接下来开始渗透：从 robots.txt 找到线索（robots.txt 本意是告诉搜索引擎“哪些目录不许爬”，但对渗透测试者来说，Disallow 列表等于免费的路标——凡是不让爬的，往往是藏着秘密的地方. 所以信息收集题的惯例就是先看 robots.txt）

```bash
$ curl -s https://sbus-042-bigturtlesjourney.zjusec.net/robots.txt
User-agent: *
Disallow: /turtl3_1s_h3r3.txt
Disallow: /reg1ster.php
```

发现了两个文件，于是尝试获取信息：
```bash
$ curl -s https://sbus-042-bigturtlesjourney.zjusec.net/turtl3_1s_h3r3.txt
..-./.----/-./-../..--.-/--/-.--/..--.-/.../-----/-./..--.-
```

扔进cyberchef中把分隔符设置成slash就可以得到：`F1ND_MY_S0N_`

`register.php`中的cookies是：

```text
haha=7768305f3472335f
```

From Hex处理之后得到`wh0_4r3_`.

选择不跟随跳转，`-i`查看测试失败重定向时的响应头：

```bash
$ curl -s -i https://sbus-042-bigturtlesjourney.zjusec.net/reg1ster.php
HTTP/1.1 200 Connection established

HTTP/2 302
server: nginx/1.11.1
date: Wed, 19 Aug 2026 21:13:32 GMT
content-type: text/html; charset=UTF-8
location: register.php

r3t4rd3d}
```

所以最后一段是：`r3t4rd3d}`

拼起来就是`AAA{h0w_t0_F1ND_MY_S0N_wh0_4r3_r3t4rd3d}`

但是并不对，所以接着尝试.

