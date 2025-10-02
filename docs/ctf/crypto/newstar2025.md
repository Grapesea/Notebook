## Crypto

### 唯一表示

题干如下：

```python
from sympy.ntheory.modular import crt
from Crypto.Util.number import bytes_to_long
from sympy import primerange
import uuid

# 生成素数列表
primes = list(primerange(2, 114514))

# 生成随机 flag，并转换为整数
flag = "flag{" + str(uuid.uuid4()) + "}"
message_int = bytes_to_long(flag.encode())

def fun(n: int):
    """
    给定整数 n，返回它对若干个素数模的余数列表，
    直到用这些余数和模数 CRT 重建出的值恰好等于 n。
    """
    used_primes = [2]          # 当前使用的素数列表，先用 2 开始
    prime_index = 1            # primes[0] 已用，从 primes[1] 开始
    while True:
        # 计算 n 对当前所有模数的余数
        remainders = [n % p for p in used_primes]

        # 用 CRT 尝试重建 n
        reconstructed, _ = crt(used_primes, remainders)

        # 如果重建成功，返回余数列表
        if reconstructed == n:
            return remainders

        # 否则继续添加新的素数，扩大模数集合
        used_primes.append(primes[prime_index])
        prime_index += 1

# 计算 message_int 的余数表示
c = fun(message_int)

print(c)


"""
[1, 2, 2, 4, 0, 2, 11, 11, 8, 23, 1, 30, 35, 0, 18, 30, 55, 60, 29, 42, 8, 13, 49, 11, 69, 26, 8, 73, 84, 67, 100, 9, 77, 72, 127, 49, 57, 74, 70, 129, 146, 45, 35, 180, 196, 101, 100, 146, 100, 194, 2, 161, 35, 155]
"""
```

## Misc
