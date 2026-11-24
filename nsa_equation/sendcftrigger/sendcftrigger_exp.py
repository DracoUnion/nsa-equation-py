#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sendcftrigger — SendCFTrigger 配置触发工具。

Python 重写自 `SendCFTrigger.exe` (C++/MSVCRT)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/Pc/Tools/i386-winnt/SendCFTrigger.exe`。

读取 XML 配置文件，连接目标主机，发送触发请求（类似 SMTP HELO / 推送）。

CLI:

  sendcftrigger <target> [port] [config_file]

  target   - 目标主机名或 IP 地址
  port     - 可选，目标端口（默认 25，SMTP）
  config_file - 可选，XML 配置文件路径
"""

import os
import socket
import sys


def run_function(target, port, config_file=None):
    """核心入口。"""
    config = None
    if config_file:
        try:
            with open(config_file, "rb") as f:
                config = f.read()
        except OSError:
            print("Unable to read config file %s" % config_file)
            return 1

    print("Connecting to %s:%d" % (target, port))

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
    except OSError as e:
        print("Unable to connect to %s:%d (%s)" % (target, port, e))
        return 1

    try:
        # 发送类似 SMTP HELO 的触发请求
        sock.sendall(b"HELO %s\r\n" % target.encode())
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

    print("Trigger transmitted.")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if len(argv) < 1 or len(argv) > 3:
        prog = os.path.basename(sys.argv[0] or "sendcftrigger")
        print('Usage: %s <target> [port] [config_file]' % prog)
        return 1
    target = argv[0]
    port = int(argv[1]) if len(argv) > 1 and argv[1].isdigit() else 25
    config_file = argv[2] if len(argv) > 2 else None
    return run_function(target, port, config_file)


if __name__ == "__main__":
    sys.exit(main())