#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parsecapture — DSky 抓包文件解析 / 解密工具。

Python 重写自 `ParseCapture.exe` (C++, MSVCRT 窄/宽 CRT)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/DSky/Tools/i386-winnt/ParseCapture.exe`。

该工具读取 DSky / Darkskyline 采集落盘的 ``capture`` 文件（内部格式含多种
“日志类型”头），把其中的各个抓包段提取出来，逐段写成独立的
``capture_%02u.pcap`` 文件。支持三种头部类型（plain / XOR-0xE3 / AES-ECB
加密），key 位 16 字节十六进制（空格分隔）。

CLI:

  parsecapture <capture_file> <results_dir> [encryption_key]

  encryption_key  - 可选，空格分隔的 16 字节十六进制
                    e.g. "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff"
"""

import os
import sys
import struct

try:
    from Crypto.Cipher import AES
except ImportError:  # pragma: no cover
    AES = None


# ---------------------------------------------------------------------------
# 常量（从二进制 .rdata 提取，经 x32dbg 校验）
# ---------------------------------------------------------------------------

# 24 字节 “日志类型” 模板。类型 0 = 明文 pcap 头；类型 1 = 头 XOR 0xE3 混淆；
# 类型 2 = pcap 头 with magic 0x72E35AF7 XOR 0xE3（记录体 AES-ECB 加密）。
HDR_TEMPLATE = struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 0xFFFF, 1)
HDR_TEMPLATES = (
    HDR_TEMPLATE,                                    # type 0: plain pcap hdr
    bytes(b ^ 0xE3 for b in HDR_TEMPLATE),           # type 1: XOR-0xE3 hdr
    struct.pack('<IHHIIII', 0x72E35AF7, 2, 4, 0, 0,  # type 2: encrypted hdr
                0xFFFF, 1),
)
# type 2 模板也 XOR 0xE3（与 type 1 相同混淆），注意第三个元素本身带 0x72E35AF7。
HDR_TEMPLATES = (
    HDR_TEMPLATE,
    bytes(b ^ 0xE3 for b in HDR_TEMPLATE),
    bytes(b ^ 0xE3 for b in HDR_TEMPLATES[2]),
)

SEPARATOR = "-" * 82 + "\n"

MSG_CHECKING = "Checking for log type %d\n"
MSG_HDR_NOT_FOUND = "* Capture header not found at start of buffer\n"
MSG_TOO_SMALL = "* Size (%u) of remaining capture file is too small to contain a valid header\n"
MSG_CAPTURE = "* Capture.%u : %u bytes\n"
MSG_TOO_SHORT_KEY = "* Invalid encryption key given (too short)\n"
MSG_TOO_LONG_KEY = "* Invalid encryption key given (too long)\n"
MSG_BAD_KEY = "* Invalid encryption key given (invalid value)\n"
MSG_KEY_EXAMPLE = '    encryptionkey = e.g., "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff"\n'
MSG_USAGE = "Usage: %s <capture_file> <results_dir> [encryption_key]\n"
MSG_OPEN_FAIL = "* Unable to open input file %ls: %u\n"
MSG_ZERO_SIZE = "* Capture file is zero size -- unable to parse\n"
MSG_SIZE_FAIL = "* Unable to get capture file size: %u\n"
MSG_MAP_FAIL = "* Unable to map capture file: %u\n"
MSG_DECRYPTING = "Decrypting with key '%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x'\n"
MSG_DRYPT_FAIL = "* Decryption failed: 0x%08x\n"
MSG_BAD_LEN = "* Included length (%u) doesn't make sense -- Bad decrypt key?\n"
MSG_NOT_ENOUGH = "* Not enough bytes left to decrypt\n"
MSG_CREATE_FAIL = "* Failed to create %ls: %u\n"
MSG_WRITE_FAIL = "* Failed to write %u bytes to %ls: %u\n"
MSG_NEXT_FAIL = "* Unable to find next capture location\n"
MSG_ENCRYPTED = "* Encrypted log found.  An encryption key must be provided\n"


# ---------------------------------------------------------------------------
# 核心逻辑
# ---------------------------------------------------------------------------

def _find_capture_location(data, pos):
    """在 data[pos:] 中定位下一段抓包。

    返回 (log_type, capture_size)；未找到返回 (None, 0)。

    语义（来自子程序 0x401005，经原程序实测）：
      * 依次尝试 type 0/1/2 的 24 字节头部模板，打印 "Checking for log type %d"；
      * 仅接受位于当前缓冲区起始处的头（不扫描字节）；
      * 若匹配，则向后扫描同一 type 模板的下一个出现位置，作为本段结束边界
        （找不到则取到缓冲区末尾）。
    """
    size = len(data) - pos
    buf = data[pos:]
    if size < 24:
        print(MSG_TOO_SMALL % size, end="")
        return None, 0

    found_type = None
    for t in (0, 1, 2):
        print(MSG_CHECKING % t, end="")
        if buf[:24] == HDR_TEMPLATES[t]:
            found_type = t
            break
    if found_type is None:
        print(MSG_HDR_NOT_FOUND, end="")
        return None, 0

    # 向后扫描同 type 模板的下一个出现位置作为本段结束
    idx = 24
    end = 24
    nxt = 24
    tpl = HDR_TEMPLATES[found_type]
    while idx + 24 <= size:
        if buf[idx:idx + 24] == tpl:
            end = idx
            break
        idx += 1
    else:
        end = size
    return found_type, end


def _parse_key(text):
    """解析命令行加密密钥：空格分隔的十六进制，最多 16 字节。

    与二进制的 wcstoul(…,16) 循环逐字节对齐：
      * 每次从当前位置做一次十六进制解析（可跳过前导空格）；
      * 一个非十六进制 token 解析为 0 且“不前进”，会被反复消费，
        直到填满 16 字节（→ too long）；
      * 解析值 > 0xFF                -> ("invalid value")
      * 解析满 16 字节后仍有内容      -> ("too long")
      * 字符串结束但不足 16 字节       -> ("too short")
    返回 (key, err)；成功时 err 为 None。
    """
    import re

    key = bytearray()
    i = 0
    n = len(text)
    while len(key) < 16:
        # 跳过空格
        while i < n and text[i] in " \t":
            i += 1
        if i >= n:
            break
        # wcstoul(p, &end, 16)：解析十六进制前缀；无有效数字则值为 0 且不前进
        m = re.match(r"[0-9a-fA-F]+", text[i:])
        if m and m.end() > 0:
            v = int(m.group(), 16)
            i += m.end()
        else:
            v = 0
        if v > 0xFF:
            return bytes(key), "invalid value"
        key.append(v & 0xFF)
        if len(key) >= 16:
            # 填满 16 字节后仍有剩余内容 -> 二进制在循环顶部走 too-long 分支
            j = i
            while j < n and text[j] in " \t":
                j += 1
            if j < n:
                return bytes(key), "too long"
    if len(key) < 16:
        return bytes(key), "too short"
    return bytes(key), None


def _decrypt_type2(block):
    """AES-128-ECB 解密一个 16 字节块（type-2 记录体）。

    实测确认：MSVCRT 侧 key 为 16 字节，块大小 16，ECB 模式（无链式）。
    """
    if AES is None:
        raise SystemExit("parsecapture: pycryptodome required for encrypted layers (pip install pycryptodome)")
    return AES.new(block_key(), AES.MODE_ECB).decrypt(block)


_block_key_global = b"\x00" * 16


def block_key():
    return _block_key_global


def _write_capture(out_path, data, log_type, key):
    """写出一段抓包（对应二进制 sub_40117B）。

    type 0: 原样拷贝
    type 1: 全体 XOR 0xE3
    type 2: 24B 头 XOR 0xE3 + magic 归一化为 A1B2C3D4；其后每 16B 块 AES-ECB 解密
    """
    global _block_key_global

    if log_type == 2:
        if key is None:
            print(MSG_ENCRYPTED, end="")
            return False
        print(MSG_DECRYPTING % tuple(b for b in key), end="")
        _block_key_global = key
    else:
        _block_key_global = b"\x00" * 16

    if log_type == 0:
        body = bytes(data)
    elif log_type == 1:
        body = bytes(b ^ 0xE3 for b in data)
    else:
        # type 2：头 24B XOR-E3，magic 改为 0xA1B2C3D4（LE）
        hdr = bytes(b ^ 0xE3 for b in data[:24])
        hdr = struct.pack('<I', 0xA1B2C3D4) + hdr[4:]
        body = bytearray(hdr)
        remaining = len(data) - 24
        pos = 24
        included_remain = 0
        if remaining % 16:
            print(MSG_NOT_ENOUGH, end="")
            return False
        while remaining >= 16:
            ct = bytes(data[pos:pos + 16])
            pt = AES.new(key, AES.MODE_ECB).decrypt(ct)
            if included_remain == 0:
                ln = struct.unpack('<I', pt[8:12])[0]
                if ln > 0xFFFF:
                    print(MSG_BAD_LEN % ln, end="")
                    return False
                included_remain = ln + 0x10
            towrite = min(16, included_remain)
            body += pt[:towrite]
            included_remain -= towrite
            pos += 16
            remaining -= 16
        data = bytes(body)

    try:
        with open(out_path, "wb") as f:
            f.write(body)
    except OSError:
        print(MSG_WRITE_FAIL % (len(body), out_path, 0), end="")
        return False
    return True


def run_function(capture_file, results_dir, encryption_key=None):
    """核心入口。"""
    if not os.path.exists(results_dir):
        os.makedirs(results_dir, exist_ok=True)

    if not os.path.exists(capture_file):
        print(MSG_OPEN_FAIL % (capture_file, 0), end="")
        return 1

    with open(capture_file, "rb") as f:
        buf = f.read()
    if not buf:
        print(MSG_ZERO_SIZE, end="")
        return 1

    key = None
    if encryption_key:
        key, kerr = _parse_key(encryption_key)
        if kerr is not None:
            if kerr == "too short":
                print(MSG_TOO_SHORT_KEY, end="")
            elif kerr == "too long":
                print(MSG_TOO_LONG_KEY, end="")
            else:
                print(MSG_BAD_KEY, end="")
            print(MSG_KEY_EXAMPLE, end="")
            return 1

    pos = 0
    counter = 1
    while True:
        log_type, size = _find_capture_location(buf, pos)
        if log_type is None:
            print(MSG_NEXT_FAIL, end="")
            return 1
        print(SEPARATOR, end="")
        print(MSG_CAPTURE % (counter, size), end="")
        out_path = os.path.join(results_dir, "capture_%02u.pcap" % counter)
        if not _write_capture(out_path, buf[pos:pos + size], log_type, key):
            return 1
        pos += size
        counter += 1
        if pos >= len(buf):
            break
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if len(argv) < 2 or len(argv) > 3:
        print(MSG_USAGE % os.path.basename(sys.argv[0] or "parsecapture"), end="")
        return 1
    capture_file = argv[0]
    results_dir = argv[1]
    encryption_key = argv[2] if len(argv) > 2 else None
    return run_function(capture_file, results_dir, encryption_key)