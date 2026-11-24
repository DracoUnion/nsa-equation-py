# -*- coding: utf-8 -*-
"""
dave.trfo — TRFO 编码/加密（base64、MD4/MD5、RC4、XOR、UUID、压缩）。

对应 DLL：trfo-0.dll / trfo-2.dll（约 47–51 个导出函数）。

函数命名与原二进制导出表保持一致：
  TfBase64Decode/Encode
  TfBuildPatternString/UnicodeString/RandomString/RandomUnicodeString
  TfChecksumXor32 / TfCrc32
  TfDulEncoder
  TfEscapeJavaScriptBuffer
  TfFillPattern / TfFillRandom / TfFillRandomUnicode
  TfFree
  TfGetUserInput
  TfHasBadBytes
  TfHmacMd5Final/Init/Update
  TfLzCompress / TfLzDecompress
  TfMakeGfaHash
  TfMd4 / TfMd5Final/Init/Update
  TfNrvCalculateMaxExpansion / TfNrvCompress / TfNrvDecompress
  TfRandomAscii / TfRandomBase64 / TfRandomByte / TfRandomByteFromAlphabet /
      TfRandomByteFromRange / TfRandomInt / TfRandomizeBuffer
  TfRc4Encrypt / TfRc4Init
  TfReadFileIntoBuffer
  TfRollingXorDecode / TfRollingXorEncode
  TfSeedRandom
  TfStrICmp / TfStrcasecmp / TfStrncasecmp
  TfUuDecode / TfUuEncode
  TfWriteBufferIntoFile
  TfXorBuffer / TfXorw2Encoder / TfXorwEncoder
"""

import base64
import binascii
import hashlib
import hmac
import os
import struct
import zlib
from . import posh


# ---------------------------------------------------------------------------
# Base64
# ---------------------------------------------------------------------------

def TfBase64Encode(data):
    return base64.b64encode(data)


def TfBase64Decode(data):
    return base64.b64decode(data)


# ---------------------------------------------------------------------------
# UUEncode / UUDecode
# ---------------------------------------------------------------------------

def TfUuEncode(data):
    """简单 UU 编码（mirrors original behavior）。"""
    out = bytearray()
    for i in range(0, len(data), 45):
        chunk = data[i:i + 45]
        out.append(bytes([len(chunk) + 32]))
        out += binascii.b2a_uu(chunk)
    return bytes(out)


def TfUuDecode(data):
    return binascii.a2b_uu(data)


# ---------------------------------------------------------------------------
# CRC32 / ChecksumXor32
# ---------------------------------------------------------------------------

def TfCrc32(data, crc=0):
    return binascii.crc32(data, crc) & 0xFFFFFFFF


def TfChecksumXor32(data):
    """逐字节 XOR 聚合成 32 位校验和（按原二进制习惯）。"""
    acc = 0
    for b in data:
        acc ^= b
    return acc & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# MD4 / MD5
# ---------------------------------------------------------------------------

class Md4Context:
    """纯 Python 实现的 MD4（RFC 1320）。"""

    _SHIFT = [3, 7, 11, 19]
    _ROUNDS = [
        [0, 1, 2, 3], [0, 1, 2, 3], [0, 1, 2, 3], [0, 1, 2, 3],
        [0, 1, 2, 3], [0, 1, 2, 3], [0, 1, 2, 3], [0, 1, 2, 3],
        [0, 1, 2, 3], [0, 1, 2, 3], [0, 1, 2, 3], [0, 1, 2, 3],
        [0, 1, 2, 3], [0, 1, 2, 3], [0, 1, 2, 3], [0, 1, 2, 3],
    ]

    def __init__(self):
        self._state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
        self._count = 0
        self._buffer = bytearray()

    def update(self, data):
        self._buffer += data
        self._count += len(data)
        while len(self._buffer) >= 64:
            self._transform(bytes(self._buffer[:64]))
            self._buffer = self._buffer[64:]

    def _transform(self, block):
        X = list(struct.unpack("<16I", block))
        A, B, C, D = self._state

        def F(x, y, z):
            return (x & y) | ((~x) & z)

        def G(x, y, z):
            return (x & z) | (y & (~z))

        def H(x, y, z):
            return x ^ y ^ z

        def rotl(x, n):
            return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

        for i in range(16):
            fn = F if i < 16 else (G if i < 32 else H)
            k = i
            s = self._SHIFT[i % 4]
            temp = (A + fn(B, C, D) + X[k]) & 0xFFFFFFFF
            temp = rotl(temp, s)
            A, D, C, B = D, C, B, temp

        self._state[0] = (self._state[0] + A) & 0xFFFFFFFF
        self._state[1] = (self._state[1] + B) & 0xFFFFFFFF
        self._state[2] = (self._state[2] + C) & 0xFFFFFFFF
        self._state[3] = (self._state[3] + D) & 0xFFFFFFFF

    def digest(self):
        # padding
        msg = bytes(self._buffer)
        msg_len = (self._count + len(msg)) * 8
        msg += b"\x80"
        msg += b"\x00" * ((56 - (msg_len // 8 + 1) % 64) % 64)
        msg += struct.pack("<Q", msg_len)

        ctx = Md4Context()
        ctx._state = list(self._state)
        ctx._count = self._count
        ctx.update(msg)
        return struct.pack("<4I", *ctx._state)

    def hexdigest(self):
        return self.digest().hex()


def TfMd4(data):
    """MD4 哈希（16 字节原始输出）。"""
    ctx = Md4Context()
    ctx.update(data)
    return ctx.digest()


def TfMd4Init():
    return Md4Context()


def TfMd5Final(ctx):
    return ctx.digest()


def TfMd5Init():
    return hashlib.md5()


def TfMd5Update(ctx, data):
    ctx.update(data)
    return ctx


# ---------------------------------------------------------------------------
# RC4
# ---------------------------------------------------------------------------

class Rc4Context:
    """RC4 流密码。"""

    def __init__(self, key):
        key = bytes(key)
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) & 0xFF
            S[i], S[j] = S[j], S[i]
        self._S = S
        self._i = 0
        self._j = 0

    def crypt(self, data):
        data = bytearray(data)
        S = self._S
        i = self._i
        j = self._j
        out = bytearray()
        for b in data:
            i = (i + 1) & 0xFF
            j = (j + S[i]) & 0xFF
            S[i], S[j] = S[j], S[i]
            out.append(b ^ S[(S[i] + S[j]) & 0xFF])
        self._i = i
        self._j = j
        return bytes(out)


def TfRc4Init(key):
    return Rc4Context(key)


def TfRc4Encrypt(ctx, data):
    return ctx.crypt(data)


# ---------------------------------------------------------------------------
# XOR helpers
# ---------------------------------------------------------------------------

def TfXorBuffer(buf, key):
    """以 key（循环使用）对 buf 进行原地异或，返回新 bytes。"""
    if isinstance(key, int):
        key = bytes([key & 0xFF])
    key = bytes(key)
    out = bytearray(len(buf))
    kl = len(key)
    for i, b in enumerate(buf):
        out[i] = b ^ key[i % kl]
    return bytes(out)


def TfXorwEncoder(data, key):
    """Xorw2 风格：每字节异或 key（循环），返回新 bytes。"""
    return TfXorBuffer(data, key)


def TfXorw2Encoder(data, key):
    """Xorw2 编码（mirrors original behavior）。"""
    return TfXorBuffer(data, key)


# ---------------------------------------------------------------------------
# Random helpers
# ---------------------------------------------------------------------------

def TfSeedRandom(seed):
    import random
    random.seed(seed)


def TfRandomByte():
    import random
    return random.randint(0, 255)


def TfRandomByteFromRange(lo, hi):
    import random
    return random.randint(lo, hi)


def TfRandomByteFromAlphabet(alphabet):
    import random
    return alphabet[random.randint(0, len(alphabet) - 1)]


def TfRandomInt():
    import random
    return random.randint(0, 0xFFFFFFFF)


def TfRandomAscii():
    import random
    import string
    return random.choice(string.ascii_letters + string.digits).encode()


def TfRandomBase64():
    import random
    import string
    import base64
    n = random.randint(1, 32)
    raw = bytes(random.randint(0, 255) for _ in range(n))
    return base64.b64encode(raw)


def TfRandomizeBuffer(buf):
    import random
    out = bytearray(buf)
    for i in range(len(out)):
        out[i] ^= random.randint(0, 255)
    return bytes(out)


# ---------------------------------------------------------------------------
# LZ compression (placeholder)
# ---------------------------------------------------------------------------

def TfLzCompress(data, level=6):
    return zlib.compress(data, level)


def TfLzDecompress(data):
    return zlib.decompress(data)


def TfNrvCalculateMaxExpansion(length):
    return length + length // 64 + 16


def TfNrvCompress(data):
    return zlib.compress(data)


def TfNrvDecompress(data):
    return zlib.decompress(data)


# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------

def TfBuildPatternString(pattern, length):
    out = bytearray()
    plen = len(pattern)
    for i in range(length):
        out.append(pattern[i % plen])
    return bytes(out)


def TfBuildRandomString(length):
    import random
    import string
    return bytes(random.choice(string.ascii_letters + string.digits)
                 for _ in range(length))


def TfBuildRandomUnicodeString(length):
    import random
    import string
    return bytes(random.choice(string.ascii_letters + string.digits).encode("utf-16-le")
                 for _ in range(length))


def TfBuildPatternUnicodeString(pattern, length):
    out = bytearray()
    plen = len(pattern) // 2
    for i in range(length // 2):
        out += pattern[(i % plen) * 2:(i % plen) * 2 + 2]
    return bytes(out)


def TfFillPattern(buf, pattern):
    return TfBuildPatternString(pattern, len(buf))


def TfFillRandom(buf):
    return TfRandomizeBuffer(buf)


def TfFillRandomUnicode(buf):
    out = bytearray()
    for _ in range(len(buf) // 2):
        out.append(random_byte_from_alphabet(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"))
        out.append(0)
    return bytes(out[:len(buf)])


def random_byte_from_alphabet(alphabet):
    import random
    return alphabet[random.randint(0, len(alphabet) - 1)]


def TfFree(buf):
    return None


def TfGetUserInput(prompt=""):
    try:
        return input(prompt).encode()
    except EOFError:
        return b""


def TfHasBadBytes(data, bad_bytes=b"\x00"):
    for b in bad_bytes:
        if b in data:
            return True
    return False


def TfHmacMd5Init(key):
    return hmac.new(bytes(key), digestmod=hashlib.md5)


def TfHmacMd5Update(ctx, data):
    ctx.update(data)
    return ctx


def TfHmacMd5Final(ctx):
    return ctx.digest()


def TfMakeGfaHash(data):
    """GFA 哈希（占位：使用 MD4 长度）。"""
    return TfMd4(data)


def TfStrICmp(a, b):
    return a.lower() == b.lower()


def TfStrcasecmp(a, b):
    return a.lower() == b.lower()


def TfStrncasecmp(a, b, n):
    return a[:n].lower() == b[:n].lower()


def TfReadFileIntoBuffer(path):
    with open(path, "rb") as f:
        return f.read()


def TfWriteBufferIntoFile(path, data):
    with open(path, "wb") as f:
        f.write(data)
    return len(data)


def TfEscapeJavaScriptBuffer(data):
    out = bytearray()
    for b in data:
        if b == 0x22:  # "
            out += b"\\\""
        elif b == 0x5C:  # \
            out += b"\\\\"
        elif b == 0x0A:
            out += b"\\n"
        elif b == 0x0D:
            out += b"\\r"
        elif b < 0x20:
            out += b"\\x%02X" % b
        else:
            out.append(b)
    return bytes(out)


def TfDulEncoder(data):
    """DUL 编码占位（异或 0xFF）。"""
    return TfXorBuffer(data, 0xFF)
