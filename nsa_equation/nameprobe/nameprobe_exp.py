#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nameprobe_exp.py — NameProbe 名称/端点探测工具，DAVE 框架重写。

原二进制 `NameProbe.exe` (C++/MSVCRT)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/Resources/Tools/NameProbe.exe`。

向目标主机发起网络连接，探测目标的网络服务状态和响应行为。

CLI:

  nameprobe <target_ip> [target_port]

  target_ip          目标主机 IP
  target_port        目标端口（默认 445）

输出示例：

  [*] NameProbe - Python port (DAVE 库)
  [*] Target: 192.168.1.5:445
  [*] Connecting...
  [*] Connection established
  [*] Response received: <bytes>
  [*] Connection closed
"""

import os
import socket
import sys


DEFAULT_PORT = 445


def run_function(target_ip, target_port=DEFAULT_PORT):
    """核心入口。"""
    print(f"[*] NameProbe - Python port (DAVE 库)")
    print(f"[*] Target: {target_ip}:{target_port}")
    print("[*] Connecting...")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target_ip, target_port))
        print("[+] Connected")

        # 发送一个探测请求
        probe_data = b"\x00\x00\x00\x00"
        try:
            sock.sendall(probe_data)
            resp = sock.recv(4096)
            if resp:
                print(f"[*] Response received ({len(resp)} bytes):")
                print(resp.hex(' '))
            else:
                print("[*] No response received")
        except socket.timeout:
            print("[*] Connection timed out waiting for response")
        except OSError as e:
            print(f"[-] Communication error: {e}")
        finally:
            sock.close()
            print("[*] Connection closed")

        return 0
    except OSError as e:
        print(f"[-] Unable to connect to {target_ip}:{target_port}: {e}")
        return 1


def main(argv=None):
    import argparse
    if argv is None:
        argv = sys.argv[1:]
    if len(argv) < 1 or len(argv) > 2:
        prog = os.path.basename(sys.argv[0] or "nameprobe")
        print(f'Usage: {prog} <target_ip> [target_port]')
        return 1
    target_ip = argv[0]
    target_port = int(argv[1]) if len(argv) > 1 else DEFAULT_PORT
    return run_function(target_ip, target_port)


if __name__ == "__main__":
    sys.exit(main())
