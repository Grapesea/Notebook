# Grapesea' Notebook

> 本站点放置的是学习笔记，已经与[原先的博客](https://github.com/Grapesea/MyBlog)分离。

## 图片自动优化

安装依赖后，正常构建或启动预览即可自动将本地图片转换为 WebP：

```bash
pip install -r requirements.txt
mkdocs build
# 或 mkdocs serve
```

`scripts/optimize_images.py` 通过 MkDocs hook 处理 JPG/JPEG、PNG、GIF、BMP、TIFF，
保留 `docs/` 中的原图和 Markdown，输出站点使用 `原文件名.webp`（例如 `photo.jpg.webp`）。
Markdown 图片、HTML 图片/链接、主题 logo/favicon 和 CSS 图片地址会自动更新。
SVG、ICO、已有 WebP 和外链图片保留原样；无法转换的图片会保留原图并输出警告。

照片使用质量 85 的有损压缩；PNG/GIF/BMP 使用无损压缩，保留透明度和动画，
不缩小图片尺寸。转换结果缓存于 `.cache/webp/`，后续构建仅转换新增或修改的图片。
GitHub Pages 部署工作流也会复用这份缓存。
首次转换会增加构建时间，网页加载提速取决于图片压缩后的大小；构建日志会显示转换数量和体积。
调整脚本中的 `QUALITY` 可修改照片质量，缓存会自动失效。
首次启用或改变转换设置后请运行 `mkdocs build` 完整构建，避免旧的增量构建产物残留。


