Marp是一款将markdown转换成slides的插件.

基础配置：

```markdown
---
marp: true
theme: gaia
paginate: true
_footer: "" 
headingDivider: [1, 4]
style: |
  /* 全局字号调整 */
  section {
    font-size: 25px;
    font-family: "Times New Roman", "Simsun", serif;
    padding: 40px;
    justify-content: flex-start !important; /* 顶部对齐 */
    align-items: flex-start !important;    /* 左对齐 */
    text-align: left;           /* 文本左对齐 */
    padding: 50px;
  }
  section::after {
    display: none;
  }
  /* 让列表更紧凑 */
  li {
    margin-bottom: 5px;
  }
  img {
    max-width: 100%;
    max-height: 70%; /* 留出 30% 给文字空间 */
    object-fit: contain; /* 保持比例 */
    display: block;
    margin: 0 auto;
  }
---
```