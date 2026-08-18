# Git

## 生成ssh密钥

```bash
ssh-keygen -t ed25519 -C "chaseraurora5@gmail.com"
chmod 600 ~/.ssh/id_ed25519
cat ~/.ssh/id_ed25519.pub
```

以 ssh-ed25519 开头的内容，复制粘贴到 GitLab 的 SSH Key 输入框即可.