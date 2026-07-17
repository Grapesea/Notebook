# Checkpoint 0-Networking Warmup

## Networking by Hand

### **Fetch a Web page**

http://cs144.keithw.org/hello 这个网址似乎没有反应，遂作罢.

```bash
cs144-25fa$ telnet cs144.keithw.org http
Trying 104.196.238.229...
^C
```

* `GET /hello HTTP/1.1`+ENTER：告诉服务器URL的path部分
* `HOST: cs144.keithw.org`+ENTER：告诉服务器URL的host部分.
* `Connection: close`+ENTER：告诉服务器我这边已经完成request，它必须在完成所有reply之后直接关闭.
* 

### Send yourself an email

无stanford账号与环境，无法完成.

### Listening and Connecting

先运行`netcat`指令监听9090端口：

```bash
cs144-25fa$ netcat -v -l -p 9090
Listening on 0.0.0.0 9090
```

新开一个窗口来拨号：

```bash
cs144-25fa$ telnet localhost 9090
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
```

在监听端口可以看到：

```bash
cs144-25fa$ netcat -v -l -p 9090
Listening on 0.0.0.0 9090
Connection received on localhost 43252
```

