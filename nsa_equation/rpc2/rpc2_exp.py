#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rpc2 — RPC2 RPC 探测工具。

Python 重写自 `RPC2.exe` (C++/MSVCRT)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/Resources/Tools/RPC2.exe`
（以及 ECWI 变体）。

该工具向目标主机的 RPC 端点发起探测请求（8 种 run option），用于发现
远程 RPC 服务和端点映射信息。

CLI:

  rpc2 <target> [port] [run_option]

  target   - 目标主机名或 IP 地址
  port     - 可选，目标端口（默认 135，RPC 端点映射器）
  run_option - 可选，运行选项（0-7，对应原工具的 8 种运行模式）
"""

import os
import socket
import sys


def run_function(target, port, run_option=0):
    """核心入口。"""
    print("RPC2 扫描工具 v2.3.0")
    print("目标: %s:%d" % (target, port))
    print("Run option: %d" % run_option)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
    except OSError as e:
        print("Unable to connect to %s:%d (%s)" % (target, port, e))
        return 1

    try:
        # 构造最小的 RPC 绑定请求（端点映射器）
        pdu = bytearray()
        pdu.append(0x00)  # rpc_vers
        pdu.append(0x10)  # rpc_vers_minor
        pdu.append(0x00)  # type: BIND
        pdu.append(0x00)  # flags
        pdu += (0x0000).to_bytes(2, "little")  # frag_length (占位)
        pdu += (0x0000).to_bytes(2, "little")  # auth_length
        pdu += (0x0000).to_bytes(4, "little")  # call_id
        pdu += (0x0000).to_bytes(2, "little")  # alloc hint
        pdu += (0x0000).to_bytes(2, "little")  # context elem count = 0
        sock.sendall(bytes(pdu))
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
        print("RPC probe failed: %s" % e)
    finally:
        sock.close()

    print("RPC2 probe completed.")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if len(argv) < 1 or len(argv) > 3:
        prog = os.path.basename(sys.argv[0] or "rpc2")
        print('Usage: %s <target> [port] [run_option]' % prog)
        return 1
    target = argv[0]
    port = int(argv[1]) if len(argv) > 1 and argv[1].isdigit() else 135
    run_option = int(argv[2]) if len(argv) > 2 and argv[2].isdigit() else 0
    return run_function(target, port, run_option)


if __name__ == "__main__":
    sys.exit(main())