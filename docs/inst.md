## 自动同步导航

安装依赖后直接运行：

```bash
mkdocs serve
```

MkDocs 启动开发服务器时会自动启用导航同步；此后每次在 `docs/` 中保存、新建、删除或重命名 Markdown 文件，都会在热重载前自动更新 `mkdocs.yml`。已有导航顺序和人工标题保持不变；新文档会追加到对应的最末级目录末尾。自动创建的条目会带有 `# mkdocs-nav-sync` 标记，并跟随文档的 front matter `title` 或一级标题更新名称；如需固定一个自动条目的名称，删除该标记即可。

不应出现在导航中的文档写入 `.mkdocsignore`，每行一个相对于 `docs/` 的路径，也支持 gitignore 风格的目录与通配符，例如：

```gitignore
story.md
drafts/
private/*.md
```

不启动 MkDocs、只想独立监听时，仍可运行 `python scripts/sync_mkdocs_nav.py --watch`。只需同步一次时，运行 `python scripts/sync_mkdocs_nav.py`；检查配置是否已同步但不修改文件时，运行 `python scripts/sync_mkdocs_nav.py --check`