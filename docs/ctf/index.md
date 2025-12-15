# 笔记列表

<table>
<thead>
    <tr>
        <th>笔记列表</th>
        <th>内容概要</th>
    </tr>
</thead>
<tbody>
    <tr>
        <td><a href="ctf101">CTF101课程笔记</a></td>
        <td>CTF启蒙课程笔记</td>
    </tr>
    <tr>
        <td><a href="crypto/">crypto笔记</a></td>
        <td>crypto相关</td>
    </tr>
    <tr>
        <td><a href="newstarctf2025/">NewStar CTF2025 Crypto/Misc Writeup</a></td>
        <td></td>
    </tr>
</tbody>
</table>

??? tips "环境准备"

    不知道为什么本地网络经常刷新，有时一下子不能连接上靶机.

    * 如果WSL里面nc失效，报错为`name resolution failure`

        首先确认基本网络连接：

        ```bash
        ping 8.8.8.8
        ping google.com
        ```

        查看当前DNS设置：

        ```bash
        cat /etc/resolv.conf
        ```

        如果DNS服务器不正确或缺失，可以临时修改：

        ```bash
        sudo nano /etc/resolv.conf
        ```

        添加公共DNS服务器：

        ```bash
        nameserver 8.8.8.8
        nameserver 8.8.4.4
        nameserver 1.1.1.1
        ```

        刷新DNS缓存：

        ```bash
        sudo systemctl restart systemd-resolved
        # 或者
        sudo service networking restart
        ```

    * 如果GitHub突然git clone不下来，显示`recv failure: connection was reset`

        修改`C:\Windows\System32\drivers\etc`路径下的hosts文件，添加：

        ```plaintext
        140.82.112.3 github.com
        140.82.112.3 api.github.com
        185.199.108.153 assets-cdn.github.com
        185.199.108.154 github.githubassets.com
        185.199.108.133 raw.githubusercontent.com
        185.199.108.133 gist.githubusercontent.com
        185.199.108.133 cloud.githubusercontent.com
        185.199.108.133 camo.githubusercontent.com
        185.199.108.133 avatars.githubusercontent.com
        185.199.108.133 avatars0.githubusercontent.com
        185.199.108.133 avatars1.githubusercontent.com
        185.199.108.133 avatars2.githubusercontent.com
        185.199.108.133 avatars3.githubusercontent.com
        185.199.108.133 user-images.githubusercontent.com
        ```

        感觉是watt toolkit干的好事，会给我设置一堆回环地址（笑
