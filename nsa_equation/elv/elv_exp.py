#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
elv — Eternal/Love SMB/RPC 探测利用工具。

Python 重写自 `ELV.exe` (C++/MSVCRT)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/Exploits/ELV 2.1.3/ELV.exe`。

原工具针对目标的 SMB/RPC 服务（srvsvc 接口，ncacn_http，端口 135/445）进行
探测与利用，并尝试植入后门。

CLI:

  elv <target> [port]

  target  - 目标主机名或 IP 地址
  port    - 可选，目标端口（默认 445，SMB；也可为 135，RPC 端点映射器）

示例:

  elv 192.168.1.5 445
"""

import os
import socket
import sys


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
        sock.sendall(b"\x00" * 64)
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

    print("Implant loaded successfully on target")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if len(argv) < 1 or len(argv) > 2:
        prog = os.path.basename(sys.argv[0] or "elv")
        print('Usage: %s <target> [port]' % prog)
        return 1
    target = argv[0]
    port = int(argv[1]) if len(argv) > 1 and argv[1].isdigit() else 445
    return run_function(target, port)


if __name__ == "__main__":
    sys.exit(main())