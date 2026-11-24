#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nameprobe — 名称/端点探测工具。

Python 重写自 `NameProbe.exe` (C++/MSVCRT，Winsock)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/Resources/Tools/NameProbe.exe`。

向目标主机的指定端口发起 TCP 连接，并发送一个探测缓冲区，用于探测
目标是否开放该端点并响应。

CLI:

  nameprobe <target> [port]

  target  - 目标主机名或 IP 地址
  port    - 可选，目标端口（默认 137，NetBIOS 名称服务）

示例:

  nameprobe 192.168.1.5 137
"""

import os
import socket
import sys


# 探测缓冲区（与原程序中的填充模式保持一致）
PROBE_BUFFER = (
    b"CKA" + b"A" * 31 + b"\x00"  # "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)
SECOND_BUFFER = (
    b"C" + b"ACA" * 10 + b"D"  # "CACACACACACACACACACACACACACACAAD"
)


def run_function(target, port):
    """核心入口。"""
    print("Probing %s:%d" % (target, port))

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
    except OSError as e:
        print("Unable to connect to %s:%d (%s)" % (target, port, e))
        return 1

    try:
        sock.sendall(PROBE_BUFFER)
        try:
            resp = sock.recv(4096)
        except socket.timeout:
            resp = b""
        if resp:
            print("Received %d bytes" % len(resp))
            print(resp[:64].hex(" "))
        else:
            print("No response")
    except OSError as e:
        print("Probe failed: %s" % e)
    finally:
        sock.close()

    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if len(argv) < 1 or len(argv) > 2:
        prog = os.path.basename(sys.argv[0] or "nameprobe")
        print('Usage: %s <target> [port]' % prog)
        return 1
    target = argv[0]
    port = int(argv[1]) if len(argv) > 1 and argv[1].isdigit() else 137
    return run_function(target, port)


if __name__ == "__main__":
    sys.exit(main())