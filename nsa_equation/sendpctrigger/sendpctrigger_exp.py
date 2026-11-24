#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sendpctrigger — SendPCTrigger 配置触发工具。

Python 重写自 `SendPCTrigger.exe` (C++/MSVCRT, Winsock)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/Pc/Legacy/Resources/PC/Tools/SendPCTrigger.exe`。

向目标主机的指定端口发送 PC 触发请求。

CLI:

  sendpctrigger <target> [port]

  target  - 目标主机名或 IP 地址
  port    - 可选，目标端口（默认 445）
"""

import os
import socket
import sys


def run_function(target, port):
    """核心入口。"""
    print("Connecting to %s:%d" % (target, port))

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
    except OSError as e:
        print("Unable to connect to %s:%d (%s)" % (target, port, e))
        return 1

    try:
        sock.sendall(b"PCTRIGGER\r\n")
        try:
            resp = sock.recv(4096)
        except socket.timeout:
            resp = b""
        if resp:
            print("Received %d bytes" % len(resp))
            print(resp.decode("utf-8", errors="replace").strip())
        else:
            print("No response")
    except OSError as e:
        print("Trigger failed: %s" % e)
    finally:
        sock.close()

    print("PC trigger transmitted.")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if len(argv) < 1 or len(argv) > 2:
        prog = os.path.basename(sys.argv[0] or "sendpctrigger")
        print('Usage: %s <target> [port]' % prog)
        return 1
    target = argv[0]
    port = int(argv[1]) if len(argv) > 1 and argv[1].isdigit() else 445
    return run_function(target, port)


if __name__ == "__main__":
    sys.exit(main())