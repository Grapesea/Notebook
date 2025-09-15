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





