#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
regprobe — RPC 端点映射器 (EPMapper) 探测 / 指纹识别工具。

Python 重写自 `regprobe.exe` (C++/MSVCRT)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/Resources/Tools/regprobe.exe`。

原工具连接目标主机的 RPC 端点映射器（默认 TCP 135 / `\\pipe\epmapper`），通过
RPC 绑定与调用探测目标操作系统版本，并打印 `RpcProxy=<ip>:<port>` 设置。

CLI:

  regprobe <target> [port]

  target  - 目标主机名或 IP 地址
  port    - 可选，RPC 端点映射器端口（默认 135）

示例输出:

  Looks like Windows 2000
  RpcProxy=1.2.3.4:135
"""

import os
import socket
import sys


# 端点映射器 (EPMapper) 接口 UUID (00000178-0000-0000-0000-000000000000)
EPMAPPER_UUID = "00000178-0000-0000-0000-000000000000"
EPMAPPER_VERSION = "1.0"


def _build_rpc_bind_pdu():
    """构建最小的 RPC 绑定 (bind) PDU，目标为端点映射器接口。"""
    # RPC 通用头 (常见于 NDR64 / NDR 绑定请求)
    pdu = bytearray()
    pdu.append(0x00)  # rpc_vers
    pdu.append(0x10)  # rpc_vers_minor
    pdu.append(0x00)  # type: BIND
    pdu.append(0x00)  # flags
    pdu.append(0x22)  # drep: NDR little-endian
    pdu.append(0x00)  # drep2
    pdu.append(0x00)  # drep3
    pdu.append(0x00)  # drep4
    pdu += (0x0000).to_bytes(2, "little")  # frag_length (占位)
    pdu += (0x0000).to_bytes(2, "little")  # auth_length
    pdu.append(0x00)  # call_id (低)
    pdu.append(0x00)
    pdu.append(0x00)
    pdu.append(0x00)
    # 分配 hint
    pdu += (0x0000).to_bytes(2, "little")
    pdu += (0x0000).to_bytes(2, "little")
    # context elem count = 1
    pdu.append(0x01)
    # reserve
    pdu.append(0x00)
    # 接口 UUID
    pdu += bytes.fromhex(EPMAPPER_UUID.replace("-", ""))
    # 接口版本 (major=1, minor=0)
    pdu.append(0x01)
    pdu.append(0x00)
    pdu.append(0x00)
    pdu.append(0x00)
    # 传输语义 (0x00 = 发送/接收)
    pdu.append(0x00)
    return bytes(pdu)


def run_function(target, port):
    """核心入口。"""
    print("Looks like probing %s:%d" % (target, port))

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
    except OSError as e:
        print("Unable to connect to %s:%d (%s)" % (target, port, e))
        return 1

    try:
        bind_pdu = _build_rpc_bind_pdu()
        # 修正片段长度
        pdu = bytearray(bind_pdu)
        pdu[6:8] = (len(pdu)).to_bytes(2, "little")
        sock.sendall(bytes(pdu))
        try:
            resp = sock.recv(4096)
        except socket.timeout:
            resp = b""
        if resp:
            print("Received %d bytes from endpoint mapper" % len(resp))
            # 尝试从响应中推断操作系统
            if b"Windows" in resp or b"NT" in resp:
                print("Looks like Windows (RPC response)")
            else:
                print("Looks like unknown Windows version")
        else:
            print("No response from endpoint mapper")
    except OSError as e:
        print("RPC exchange failed: %s" % e)
    finally:
        sock.close()

    print("RpcProxy=%s:%d" % (target, port))
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if len(argv) < 1 or len(argv) > 2:
        prog = os.path.basename(sys.argv[0] or "regprobe")
        print('Usage: %s <target> [port]' % prog)
        return 1
    target = argv[0]
    port = int(argv[1]) if len(argv) > 1 and argv[1].isdigit() else 135
    return run_function(target, port)


if __name__ == "__main__":
    sys.exit(main())