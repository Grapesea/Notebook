## 语法

### re模块（正则表达式）

可以使用正则表达式，用于处理字符串。

`re.match()` 从字符串的起始位置匹配正则表达式

`match.group()`返回的是

```python
import re

pattern = r"world"
text = "hello world"

match = re.search(pattern, text)
if match:
    print("Right", match.group())
else:
    print("Wrong")
```

## 文档与图片处理

### 提取pdf首页的图片

??? tips "python处理代码"

    ```bash
    pip install PyMuPDF Pillow
    ```

    ```python
    import fitz  # PyMuPDF
    from pathlib import Path

    def extract_first_pages(input_folder, output_folder, dpi=300):
        """
        提取文件夹中所有PDF的第一页为高清图片
        
        参数:
        - input_folder: 包含PDF文件的文件夹路径
        - output_folder: 输出图片的文件夹路径
        - dpi: 分辨率，默认300（越高越清晰，文件越大）
        """
        input_path = Path(input_folder)
        output_path = Path(output_folder)
        
        # 调试信息
        print(f"当前工作目录: {Path.cwd()}")
        print(f"输入文件夹路径: {input_path.absolute()}")
        print(f"输入文件夹是否存在: {input_path.exists()}")
        
        if not input_path.exists():
            print(f"错误：输入文件夹 '{input_folder}' 不存在！")
            return
        
        # 列出所有PDF文件
        pdf_files = list(input_path.glob("*.pdf"))
        print(f"找到 {len(pdf_files)} 个PDF文件")
        
        if len(pdf_files) == 0:
            print("没有找到PDF文件！")
            # 显示文件夹中的所有文件
            all_files = list(input_path.iterdir())
            print(f"文件夹中的所有文件: {[f.name for f in all_files]}")
            return
        
        # 创建输出文件夹
        output_path.mkdir(exist_ok=True)
        print(f"输出文件夹: {output_path.absolute()}\n")
        
        # 遍历所有PDF文件
        for pdf_file in pdf_files:
            try:
                print(f"正在处理: {pdf_file.name}")
                
                # 打开PDF
                doc = fitz.open(pdf_file)
                
                # 检查PDF是否有页面
                if len(doc) == 0:
                    print(f"  警告: {pdf_file.name} 没有页面")
                    doc.close()
                    continue
                
                page = doc[0]
                
                zoom = dpi / 72  # 72是PDF的默认DPI
                mat = fitz.Matrix(zoom, zoom)
                
                pix = page.get_pixmap(matrix=mat)
                
                output_file = output_path / f"{pdf_file.stem}.png"
                pix.save(output_file)
                print(f"  ✓ 成功保存: {output_file.name}")
                
                doc.close()
                
            except Exception as e:
                print(f"  ✗ 处理 {pdf_file.name} 时出错: {e}")
        print(f"\n处理完成！")

    extract_first_pages("path1", "path2", dpi=150)  

    # path1 : pdf的路径
    # path2 : 图片输出的路径

    # 可以调整dpi参数以获得不同清晰度的图片
    # dpi = 300 # 高清
    # dpi = 150 # 中等清晰度
    # dpi = 72  # 普通清晰度
    # dpi = 50  # 低清晰度 
    ```
