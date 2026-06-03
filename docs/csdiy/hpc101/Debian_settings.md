> 本文档记录Debian个人偏好配置.

## 添加sudo用户组

将自己的账户添加到sudo组中：

```bash
su -
usermod -aG sudo grapesea
exit
reboot # 重启
```

## 添加底部应用栏

GNOME 默认没有底部任务栏，需要安装扩展来实现.

````bash
sudo apt install gnome-shell-extensions gnome-tweaks -y
sudo apt install gnome-shell-extension-dash-to-panel -y
sudo apt install gnome-shell-extension-manager -y
````

需要注销重新登录，然后：

```bash
extension-manager
```

在里面找到 Dash to Panel 并开启，开启后点击齿轮图标 → Position → **Bottom**，即可出现底部应用栏. 

