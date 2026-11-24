#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ds_parselogs — DSky/Darkskyline 抓包文件分片工具。

Python 重写自 `DS_ParseLogs.exe` (C++/MSVCRT)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/Darkskyline/DS_ParseLogs.exe`。

该工具按“捕获文件”格式拆分输入文件：每段以标准 pcap 24 字节头部
(`D4C3 B2A1` / v2.4 / snaplen 0xFFFF / net 1) 开始，向后扫描下一个相同头部
作为本段边界，逐段原样写出为 `<results_prefix>_%02d.pcap`。

注意：该工具**不**做 XOR-0xE3 混淆也不做 AES 解密（那是 `ParseCapture.exe` 的职责），
只处理明文 pcap 头；遇到非明文头部会报错并退出。

CLI:

  ds_parselogs <capture_file> <results_prefix>

  例如：ds_parselogs capture.bin out   -> out_01.pcap, out_02.pcap, ...
"""

import os
import sys

# 标准 pcap 文件头（24 字节）：magic / v2.4 / thiszone / sigfigs / snaplen / network
PCAP_HEADER = (
    b"\xd4\xc3\xb2\xa1"   # magic (little-endian 0xA1B2C3D4)
    b"\x02\x00\x04\x00"   # version major/minor
    b"\x00\x00\x00\x00"   # thiszone
    b"\x00\x00\x00\x00"   # sigfigs
    b"\xff\xff\x00\x00"   # snaplen = 0xFFFF
    b"\x01\x00\x00\x00"   # network = 1
)

MSG_USAGE = "Usage: %s <capture_file> <results_prefix>\r\n"
MSG_OPEN_FAIL = "* Unable to open input file %s: %d\r\n"
MSG_ZERO_SIZE = "* Capture file is zero size -- unable to parse"
MSG_MAP_FAIL = "* Unable to map capture file\r\n"
MSG_TOO_SMALL = "* Size (%d) of remaining capture file is too small to contain a valid header\r\n"
MSG_HDR_NOT_FOUND = "* Capture header not found at start of buffer\r\n"
MSG_NEXT_FAIL = "* Unable to find next capture location\r\n"
MSG_CAPTURE = "* Capture.%d : %d bytes\r\n"
MSG_CREATE_FAIL = "* Failed to create %s: %d\r\n"
MSG_WRITE_FAIL = "* Failed to write %d bytes to %s: %d\r\n"


def _find_next_header(buf, start, size):
    """在 buf[start:size] 中查找下一个完整 pcap 头部模板，返回其绝对偏移；
    未找到返回 size（取到缓冲区末尾）。"""
    end = size - len(PCAP_HEADER)
    i = start
    while i <= end:
        if buf[i:i + len(PCAP_HEADER)] == PCAP_HEADER:
            return i
        i += 1
    return size


def run_function(capture_file, results_prefix):
    """核心入口。"""
    try:
        with open(capture_file, "rb") as f:
            buf = f.read()
    except OSError as e:
        winerr = getattr(e, "winerror", 0) or 0
        print(MSG_OPEN_FAIL % (capture_file, winerr), end="")
        return 1

    file_size = len(buf)
    if file_size == 0:
        print(MSG_ZERO_SIZE, end="")
        return 1

    pos = 0
    counter = 1
    remaining = file_size
    while True:
        # 段起始必须是标准 pcap 头部
        if remaining < len(PCAP_HEADER):
            print(MSG_TOO_SMALL % remaining, end="")
            print(MSG_NEXT_FAIL, end="")
            return 1

        if buf[pos:pos + len(PCAP_HEADER)] != PCAP_HEADER:
            print(MSG_HDR_NOT_FOUND, end="")
            print(MSG_NEXT_FAIL, end="")
            return 1

        # 向后扫描下一个 pcap 头部作为本段结束边界；未找到则取到缓冲区末尾
        consumed = _find_next_header(buf, pos + len(PCAP_HEADER), file_size) - pos

        print(MSG_CAPTURE % (counter, consumed), end="")

        out_path = "%s_%02d.pcap" % (results_prefix, counter)
        try:
            with open(out_path, "wb") as f:
                f.write(buf[pos:pos + consumed])
        except OSError:
            print(MSG_WRITE_FAIL % (consumed, out_path, 0), end="")
            return 1

        pos += consumed
        remaining -= consumed
        counter += 1

        if pos >= file_size:
            break

    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if len(argv) != 2:
        print(MSG_USAGE % os.path.basename(sys.argv[0] or "ds_parselogs"), end="")
        return 1
    capture_file = argv[0]
    results_prefix = argv[1]
    return run_function(capture_file, results_prefix)


if __name__ == "__main__":
    sys.exit(main())