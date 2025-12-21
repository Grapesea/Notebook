## cryptohack-aes_starter

> [Writeup](https://lianjinlll.cn/2025/02/18/Cryptohack-SymmetricCiphers-wp-%E6%8C%81%E7%BB%AD%E6%9B%B4%E6%96%B0/)

AES是一种块加密算法，大致流程如下图所示（图源CTFwiki）：

<center><img src="../photos/cryptohack/aes_details.jpg" alt="rr" style="zoom: 50%;" /></center>

其主要过程如下：

1. KeyExpansion or Key Schedule

    From the 128 bit key, 11 separate 128 bit "round keys" are derived: one to be used in each AddRoundKey step.

2. Initial key addition

    AddRoundKey - the bytes of the first round key are XOR'd with the bytes of the state.

3. Round - this phase is looped 10 times, for 9 main rounds plus one "final round"

* SubBytes - each byte of the state is substituted for a different byte according to a lookup table ("S-box").

* ShiftRows - the last three rows of the state matrix are transposed—shifted over a column or two or three.

* MixColumns - matrix multiplication is performed on the columns of the state, combining the four bytes in each column. This is skipped in the final round.

* AddRoundKey - the bytes of the current round key are XOR'd with the bytes of the state.

Included is a `bytes2matrix` function for converting our initial plaintext block into a state matrix. Write a `matrix2bytes` function to turn that matrix back into bytes, and submit the resulting plaintext as the flag.

??? tips "bytes2matrix 以及 [matrix2byte](https://cryptohack.org/courses/symmetric/aes2/) 函数"

    ```python
    def bytes2matrix(text):
        """ Converts a 16-byte array into a 4x4 matrix.  """
        return [list(text[i:i+4]) for i in range(0, len(text), 4)]

    def matrix2bytes(matrix):
        """ Converts a 4x4 matrix into a 16-byte array.  """
        return bytes([byte for row in matrix for byte in row])  # 只需要补上这句话就行了

    matrix = [
        [99, 114, 121, 112],
        [116, 111, 123, 105],
        [110, 109, 97, 116],
        [114, 105, 120, 125],
    ]

    print(matrix2bytes(matrix))
    ```

SubBytes是AES每一轮的第一步，将状态矩阵的每个元素通过一个查找表subbox映射生成下一个状态矩阵.

这里的查找表运用了非常逼近非线性函数的构造，即Galois Field 取模数$2^{8}$下的高次多项式函数：

\[f(x) = 05x^{fe} + 09x^{fd} + f9 x^{fb} + 25x^{f7} + f4x^{ef} + 01x^{df} + b5x^{bf} + 8fx^{7f} + 63\]

制作完成S-Box之后，如果能求出S_Box_invert，则可以反向破译，但正如这个算法本身所保证的那样，破解难度是极其大的.

??? tips "subbox"

    ```python
    s_box = (
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    )

    inv_s_box = (
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
    )

    state = [
        [251, 64, 182, 81],
        [146, 168, 33, 80],
        [199, 159, 195, 24],
        [64, 80, 182, 255],
    ]

    def matrix2bytes(matrix):
        """ Converts a 4x4 matrix into a 16-byte array.  """
        return bytes([byte for row in matrix for byte in row])

    def add_round_key(s, k):
        res = [[] for i in range(4)]
        for i in range(4):
            for j in range(4):
                res[i].append(s[i][j] ^ k[i][j])
        return matrix2bytes(res)

    def sub_bytes(s, sbox=s_box):
        res = [[] for i in range(4)]
        for i in range(4):
            for j in range(4):
                res[i].append(sbox[s[i][j]])
        return matrix2bytes(res)

    print(sub_bytes(state, sbox=inv_s_box))
    ```

??? tips "diffusion"

    ```python
    def shift_rows(s):
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]

    def inv_shift_rows(s):
        '''Wrong:因为这样会导致前面的赋值影响后面的结果，写成了跟原函数一样的效果，所以要慎用原地交换
        s[1][0], s[1][1], s[1][2], s[1][3] = s[1][3], s[1][0], s[1][1], s[1][2]
        s[2][0], s[2][1], s[2][2], s[2][3] = s[2][2], s[2][3], s[2][0], s[2][1]
        s[3][0], s[3][1], s[3][2], s[3][3] = s[3][1], s[3][2], s[3][3], s[3][0]
        '''
        s[1][1], s[2][1], s[3][1], s[0][1] = s[0][1], s[1][1], s[2][1], s[3][1]
        s[2][2], s[3][2], s[0][2], s[1][2] = s[0][2], s[1][2], s[2][2], s[3][2]
        s[3][3], s[0][3], s[1][3], s[2][3] = s[0][3], s[1][3], s[2][3], s[3][3]

    # learned from http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
    xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)
    # GF(2^8) 上的乘2运算（即多项式乘法后模一个不可约多项式）

    def mix_single_column(a):
        # see Sec 4.1.2 in The Design of Rijndael
        t = a[0] ^ a[1] ^ a[2] ^ a[3]
        u = a[0]
        a[0] ^= t ^ xtime(a[0] ^ a[1])
        a[1] ^= t ^ xtime(a[1] ^ a[2])
        a[2] ^= t ^ xtime(a[2] ^ a[3])
        a[3] ^= t ^ xtime(a[3] ^ u)

    def mix_columns(s):
        for i in range(4):
            mix_single_column(s[i])


    def inv_mix_columns(s):
        # see Sec 4.1.3 in The Design of Rijndael
        for i in range(4):
            u = xtime(xtime(s[i][0] ^ s[i][2]))
            v = xtime(xtime(s[i][1] ^ s[i][3]))
            s[i][0] ^= u
            s[i][1] ^= v
            s[i][2] ^= u
            s[i][3] ^= v

        mix_columns(s)

    state = [
        [108, 106, 71, 86],
        [96, 62, 38, 72],
        [42, 184, 92, 209],
        [94, 79, 8, 54],
    ]

    def matrix2bytes(matrix):
        """ Converts a 4x4 matrix into a 16-byte array.  """
        return bytes([byte for row in matrix for byte in row])

    inv_mix_columns(state)
    inv_shift_rows(state)

    print(matrix2bytes(state))
    ```

??? tips "Bring all Together"

    代码量看起来很宏伟，实际上只是把先前的模块拼在了一起.

    需要注意的一点是类型转换，如果在先前的代码里面，`add_round_key`和`inv_sub_bytes`已经调用过matrix2bytes，则类型冲突会报错.

    ```python
    N_ROUNDS = 10

    s_box = (
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    )
    inv_s_box = (
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
    )

    key        = b'\xc3,\\\xa6\xb5\x80^\x0c\xdb\x8d\xa5z*\xb6\xfe\\'
    ciphertext = b'\xd1O\x14j\xa4+O\xb6\xa1\xc4\x08B)\x8f\x12\xdd'

    def bytes2matrix(text):
        """ Converts a 16-byte array into a 4x4 matrix.  """
        return [list(text[i:i+4]) for i in range(0, len(text), 4)]

    def matrix2bytes(matrix):
        """ Converts a 4x4 matrix into a 16-byte array.  """
        return bytes([byte for row in matrix for byte in row])

    def expand_key(master_key):
        """
        Expands and returns a list of key matrices for the given master_key.
        """

        # Round constants https://en.wikipedia.org/wiki/AES_key_schedule#Round_constants
        r_con = (
            0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
            0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
            0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
            0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
        )

        # Initialize round keys with raw key material.
        key_columns = bytes2matrix(master_key)
        iteration_size = len(master_key) // 4

        # Each iteration has exactly as many columns as the key material.
        i = 1
        while len(key_columns) < (N_ROUNDS + 1) * 4:
            # Copy previous word.
            word = list(key_columns[-1])

            # Perform schedule_core once every "row".
            if len(key_columns) % iteration_size == 0:
                # Circular shift.
                word.append(word.pop(0))
                # Map to S-BOX.
                word = [s_box[b] for b in word]
                # XOR with first byte of R-CON, since the others bytes of R-CON are 0.
                word[0] ^= r_con[i]
                i += 1
            elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
                # Run word through S-box in the fourth iteration when using a
                # 256-bit key.
                word = [s_box[b] for b in word]

            # XOR with equivalent word from previous iteration.
            word = bytes(i^j for i, j in zip(word, key_columns[-iteration_size]))
            key_columns.append(word)

        # Group key words in 4x4 byte matrices.
        return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]

    def add_round_key(s, k):
        res = [[] for i in range(4)]
        for i in range(4):
            for j in range(4):
                res[i].append(s[i][j] ^ k[i][j])
        return res

    def sub_bytes(s, sbox=s_box):
        res = [[] for i in range(4)]
        for i in range(4):
            for j in range(4):
                res[i].append(sbox[s[i][j]])
        return matrix2bytes(res)

    def inv_sub_bytes(s, inv_sbox=inv_s_box):
        res = [[] for i in range(4)]
        for i in range(4):
            for j in range(4):
                res[i].append(inv_sbox[s[i][j]])
        return res

    def shift_rows(s):
        s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
        s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
        s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]

    def inv_shift_rows(s):
        s[1][1], s[2][1], s[3][1], s[0][1] = s[0][1], s[1][1], s[2][1], s[3][1]
        s[2][2], s[3][2], s[0][2], s[1][2] = s[0][2], s[1][2], s[2][2], s[3][2]
        s[3][3], s[0][3], s[1][3], s[2][3] = s[0][3], s[1][3], s[2][3], s[3][3]

    xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

    def mix_single_column(a):
        # see Sec 4.1.2 in The Design of Rijndael
        t = a[0] ^ a[1] ^ a[2] ^ a[3]
        u = a[0]
        a[0] ^= t ^ xtime(a[0] ^ a[1])
        a[1] ^= t ^ xtime(a[1] ^ a[2])
        a[2] ^= t ^ xtime(a[2] ^ a[3])
        a[3] ^= t ^ xtime(a[3] ^ u)

    def mix_columns(s):
        for i in range(4):
            mix_single_column(s[i])

    def inv_mix_columns(s):
        # see Sec 4.1.3 in The Design of Rijndael
        for i in range(4):
            u = xtime(xtime(s[i][0] ^ s[i][2]))
            v = xtime(xtime(s[i][1] ^ s[i][3]))
            s[i][0] ^= u
            s[i][1] ^= v
            s[i][2] ^= u
            s[i][3] ^= v

        mix_columns(s)

    def decrypt(key, ciphertext):
        round_keys = expand_key(key) # Remember to start from the last round key and work backwards through them when decrypting

        # Convert ciphertext to state matrix
        state = bytes2matrix(ciphertext)
        # Initial add round key step
        state = add_round_key(state, round_keys[N_ROUNDS])

        for i in range(N_ROUNDS - 1, 0, -1):
            inv_shift_rows(state)
            state = inv_sub_bytes(state)
            round_key = round_keys[i]
            state = add_round_key(state, round_key)
            inv_mix_columns(state)
            
        # Run final round (skips the InvMixColumns step)
        inv_shift_rows(state)
        state = inv_sub_bytes(state)
        round_key = round_keys[0]
        state = add_round_key(state, round_key)
        
        # Convert state matrix to plaintext
        plaintext = matrix2bytes(state)

        return plaintext

    print(decrypt(key, ciphertext))

    ```

## cryptohack-block_cipher

??? tips "题干"

    ```python
    from Crypto.Cipher import AES
    plaintext = '63727970746f7b626c30636b5f633170683372355f3472335f663435375f217'
    ciphertext = 'c11949a4a2ecf929dfce48b39daedd9e6d90c67d2f550b79259bdda835348a48'

    KEY = ?
    FLAG = ?

    @chal.route('/block_cipher_starter/decrypt/<ciphertext>/')
    def decrypt(ciphertext):
        ciphertext = bytes.fromhex(ciphertext)

        cipher = AES.new(KEY, AES.MODE_ECB)
        try:
            decrypted = cipher.decrypt(ciphertext)
        except ValueError as e:
            return {"error": str(e)}

        return {"plaintext": decrypted.hex()}


    @chal.route('/block_cipher_starter/encrypt_flag/')
    def encrypt_flag():
        cipher = AES.new(KEY, AES.MODE_ECB)
        encrypted = cipher.encrypt(FLAG.encode())

        return {"ciphertext": encrypted.hex()}
    ```

[第一关](https://aes.cryptohack.org/block_cipher_starter/)实际上只要先encrypt一下，然后把得到的ciphertext输给decrypt函数就能得到plaintext. 喂给cyberchef可得解.

[第二关](https://aes.cryptohack.org/passwords_as_keys/)需要学一点交互知识和AES调库了：

??? tips "writeup"

    ```python
    from Crypto.Cipher import AES
    import requests
    import hashlib

    url='https://aes.cryptohack.org/passwords_as_keys/'

    response1 = requests.get(url+'encrypt_flag/')
    enc = response1.json()['ciphertext']
    print(enc)
    response1.close()

    response2 = requests.get("https://gist.githubusercontent.com/wchargin/8927565/raw/d9783627c731268fb2935a731a618aa8e95cf465/words")
    date = response2.text.split("\n")

    response2.close()

    for pwd in date:
        KEY = hashlib.md5(pwd.encode()).digest()
        print(KEY)
        ''' 比较慢的方法, json传递key去枚举
        response = requests.get(url+'decrypt/'+enc+'/'+KEY.hex())
        dec=response.json()['plaintext']
        response.close()
        下面是本地解密的方法
        '''
        aes = AES.new(KEY, AES.MODE_ECB)
        decrypt = aes.decrypt(bytes.fromhex(enc))
        if b'crypto' in decrypt:
            print(decrypt)
            break
    ```

[ECB_oracle](https://cryptohack.org/courses/symmetric/ecb_oracle/)

这个题目根本没想到是逐byte爆破，看了题解才知道是怎么回事.当然，看的题解其实是需要一点修正的，不能完全复现出来情况.

??? tips "[题解1](https://lianjinlll.cn/2025/02/18/Cryptohack-SymmetricCiphers-wp-%E6%8C%81%E7%BB%AD%E6%9B%B4%E6%96%B0/)的修改版"
    
    ```python
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Util.number import *
    import requests
    import hashlib

    '''
    url='https://aes.cryptohack.org/ecb_oracle/'
    def encrypt(plaintext):
        response = requests.get(url+'encrypt/'+plaintext+'/') # 这里plaintext不可转成hex，不然看不出位数
        enc=response.json()['ciphertext']
        response.close()
        return enc
    
    @chal.route('/ecb_oracle/encrypt/<plaintext>/')
    def encrypt(plaintext):
        plaintext = bytes.fromhex(plaintext)
        padded = pad(plaintext + FLAG.encode(), 16) # pad后面的16是指填充成16的整数倍长度.
        cipher = AES.new(KEY, AES.MODE_ECB)
        try:
            encrypted = cipher.encrypt(padded)
        except ValueError as e:
            return {"error": str(e)}
        return {"ciphertext": encrypted.hex()}
    '''
    
    # padded = pad(plaintext + FLAG.encode(), 16)
    # 把输入的 plaintext 和服务器上的秘密 FLAG 拼在了一起（plaintext在前，FLAG 在后）.
    # 填充 (Padding)：AES 是分组加密，要求数据长度必须是 16 字节的倍数。pad 函数负责把拼接后的数据填满到 16 的倍数（通常使用 PKCS#7 填充）
    # 所以这个函数可以通过上面的枚举猜出flag长度：
    # {"ciphertext":"f1fc01b6f5261ab2791273d409e982bc926b6882b9cd8bc87e1d7af1b6e869748399707d033badaa41663890fe57858e"}
    # 这是个96位hex, 32bytes的ciphertext，在输入了14位hex之后得到
    # {"ciphertext":"077bc05478564779802bf824e42b8af071223c29278234f552e8149d5f2f9954"}
    # 这是个64位hex, 32bytes的ciphertext，在输入了12位hex之后得到
    # 所以有理由相信flag长度是26bytes

    charset = "etoanihsrdlucgwyfmpbkvjxqz{}_01234567890ETOANIHSRDLUCGWYFMPBKVJXQZ"

    flag = b'crypto{' # 使用b''
    for i in range (19): # 19 = 26 - 7('crypto{'的长度)
        base = '00' * (24-i) # 填充物的长度
        enc1 = encrypt(base)
        for j in charset:
            enc2 = encrypt(base + hex(bytes_to_long(flag+j.encode()))[2:]) 
            # enc2相当于“占用掉”flag的前面位置，做到了逐byte进行pad，
            # 与不占用flag只拼接的enc进行对比，如果结果相同就采用
            if (enc1[32:64] == enc2[32:64]): # 取第二个块，因为第一个块一定是相同的，不需要对比
                flag += j.encode()
                print(flag)
                break
    # 不知道是不是访问有频率限制，测试了好几次，刚开始到b'crypto{p3n6u1n'的输出之后就会报错误：
    # requests.exceptions.ConnectionError: ('Connection aborted.', ConnectionResetError(10054, '远程主机强迫关闭了一个现有的连接。', None, 10054, None))

    # 所以一种方法是，不断修改前面的flag和函数循环参数直到flag完整.
    ```

??? tips "题解2:retroid，有修改"

    ```python
    import requests

    """
    Solves in only 41 HTTP requests, with 0 assumptions about flag format etc.
    I achieve this by stuffing multiple trial plaintexts into each HTTP request,
    and exiting early as soon as a matching block is found.
    This code is over-optimised, sacrificing readability and thus educational value.
    $ time python3 solve.py
    ...
    solved in 41 HTTP requests!
    real	0m0.587s
    user	0m0.203s
    sys	0m0.022s
    FUTURE OPTIMISATIONS:
    This script solves the plaintext left-to-right. It is also possible to solve
    right-to-left. We could do both in parallel and "meet in the middle", to ~halve
    the execution time.
    https://gist.github.com/DavidBuchanan314/beb4b4998f4131806ba466cbdff9a83e
    """

    s = requests.session()
    rcount = 0
    def encrypt(data):
        global rcount
        rcount += 1 # track HTTP request count, just for fun
        r = s.get(f"http://aes.cryptohack.org/ecb_oracle/encrypt/{data.hex()}/")
        return(bytes.fromhex(r.json()["ciphertext"]))


    # split data across multiple requests, to deal with URL length restrictions
    # returns a generator so the caller can early-exit
    def encrypt_big(data):
        MAX_SIZE = 0x10*56
        for i in range((len(data)-1)//MAX_SIZE+1):
            block = data[i*MAX_SIZE:(i+1)*MAX_SIZE]
            ct = encrypt(block)[:len(block)]
            for j in range(len(ct)//0x10):
                yield ct[j*0x10:(j+1)*0x10]


    # put most common byte values first, so we can early-exit sooner on average
    charset = list(b"etoanihsrdlucgwyfmpbkvjxqz{}_01234567890ETOANIHSRDLUCGWYFMPBKVJXQZ")
    for i in range(0x100): # include all the other byte values in the charset too
        if i not in charset:
            charset.append(i)

    # cache ciphertexts at all 16 possible offsets
    targets = [encrypt(b"A"*(0x10-i)) for i in range(0x10)]

    # we can work out the length of the flag based on when the padded length "steps up"
    lengths = list(map(len, targets))
    flag_len = lengths[-1] - 0x11 + lengths.index(lengths[-1])

    flag = b"crypto{"
    for _ in range(flag_len-7):
        # XXX: there are multiple off-by-one bugs here, that all cancel out. Trust me.
        b, i = divmod(len(flag) + 1, 0x10)
        target = targets[i][b*0x10:(b+1)*0x10] # get the ciphertext of that block

        attempts = b""
        for c in charset:
            attempts += (b"A"*0x10+flag+bytes([c]))[-0x10:]

        for c, ct in zip(charset, encrypt_big(attempts)):
            if ct == target:
                flag += bytes([c])
                print(flag)
                break
        else:
            exit("oof")

    print(f"solved in {rcount} HTTP requests!")
    ```

[ECBCBCWTF](https://cryptohack.org/courses/symmetric/ecbcbcwtf/)

<center><img src="../photos/cryptohack/cbc.png" style="zoom: 50%;" /></center>

??? tips "题解"

    ```python
    from Crypto.Util.number import *
    import requests

    url='https://aes.cryptohack.org/ecbcbcwtf/'

    response = requests.get(url+'encrypt_flag/') 
    enc=response.json()['ciphertext']
    print(enc)
    response.close()

    iv = enc[:32]
    enc1 = enc[32:64]
    enc2 = enc[64:]
    # a4303894154416d146138cdb19c1edbd2c1ce7df2b73b84bd146c142faeb0fff524490dee726973472a1f8faca75cc49

    response = requests.get(url+'decrypt/'+enc[32:])
    dec=response.json()['plaintext']
    print(dec)
    response.close()

    dec1 = dec[:32]
    dec2 = dec[32:]

    print(long_to_bytes(int(iv,16)^int(dec1,16))+long_to_bytes(int(enc1,16)^int(dec2,16)))
    ```

[Flipping Cookie](https://cryptohack.org/courses/symmetric/flipping_cookie/)

也是一个数学推导的题目，我们已经知道了cookie的返回值是由16bytes的iv和一段P1构成.

现在只需要构造一个可以骗过系统的iv，使得admin权限被获得就可以了，所以：

$$\begin{cases}
    m_{\text{old}} = \text{decrypt}(C) \oplus iv_{\text{old}} \\
    m_{\text{new}} = \text{decrypt}(C) \oplus iv_{\text{new}}
    \end{cases} \Longrightarrow 
    iv_{\text{old}} \oplus m_{\text{old}} = iv_{\text{new}} \oplus m_{\text{new}}
    \Longrightarrow 
    iv_{\text{new}} = iv_{\text{old}} \oplus m_{\text{old}} \oplus m_{\text{new}}$$

??? tips "题解"

    ```python
    import requests
    from Crypto.Cipher import AES
    from Crypto.Util.number import *

    url = 'https://aes.cryptohack.org/flipping_cookie/'
    request = requests.get(url + 'get_cookie')
    cookie = request.json()["cookie"]
    iv = cookie[:32]
    P1 = cookie[32:] # 64个hex
    print(cookie) # 3414be61ceb8b3a4b69a86221d02795d0b92d1938afa83f234b5d141162bb5f2e8ca23d9a3108e30f7d3b6d9bbd8e16a

    #构造虚假的iv，选了一个block
    m   =b'admin=False;expi'
    invm=b'admin=True;expir'

    new_iv=hex(bytes_to_long(m)^bytes_to_long(invm)^int(iv,16))

    request = requests.get(url+'check_admin/'+P1+'/'+new_iv[2:])
    flag=request.json()['flag']
    print(flag)
    ```

[Symmetry](https://cryptohack.org/courses/symmetric/symmetry/)

<center><img src="../photos/cryptohack/cbc.png" style="zoom: 50%;" /></center>

??? tips "题解"

    实际上极其简单，需要注意到最后一步plaintext和ciphertext是可以换位的，则把cipher当作plaintext输入，可以轻松获得flag.

    ```python
    import requests
    from Crypto.Cipher import AES
    from Crypto.Util.number import *

    url = 'https://aes.cryptohack.org/symmetry/'
    request = requests.get(url + 'encrypt_flag/')
    C = request.json()["ciphertext"]
    print(C)

    iv = C[:32]  # 16Bytes
    enc = C[32:] # 32Bytes
    print(iv,enc)

    response = requests.get(url+'encrypt/'+enc+'/'+iv)
    flag=response.json()['ciphertext']
    print(flag)
    response.close()

    print(bytes.fromhex(flag))
    ```

[Bean_counter](https://cryptohack.org/courses/symmetric/bean_counter/)

<center><img src="../photos/cryptohack/ctr.png" style="zoom: 50%;" /></center>

??? tips "题解"

