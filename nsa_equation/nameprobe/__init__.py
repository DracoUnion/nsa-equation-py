#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nameprobe — NameProbe 名称/端点探测工具。

Python 重写自 `NameProbe.exe` (C++/MSVCRT)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/Resources/Tools/NameProbe.exe`。

向目标主机发起 TCP 连接，探测目标主机的网络服务状态和响应行为。

CLI:

  nameprobe <target_ip> [target_port]

  target_ip          目标主机 IP
  target_port        目标端口（默认 445）

输出示例：

  [*] NameProbe - Python port (DAVE 库)
  [*] Target: 192.168.1.5:445
  [*] Connecting...
  [+] Connected
  [*] Response received (4 bytes): 00 00 00 00
  [*] Connection closed
"""

from . import nameprobe_exp


def nameprobe_handle(args):
    """Run the nameprobe tool."""
    return nameprobe_exp.run_function(
        target_ip=args.target_ip,
        target_port=args.target_port,
    )


def reg_subparser(subparsers):
    """Register the `nameprobe` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "nameprobe",
        help="NameProbe 名称/端点探测工具",
        description="nameprobe — 向目标主机发起 TCP 连接，探测目标主机的网络服务状态和响应行为。",
    )
    p.add_argument("target_ip", help="目标主机 IP")
    p.add_argument("target_port", metavar="PORT", type=int, default=445,
                   help="目标端口（默认 445）")
    p.set_defaults(func=nameprobe_handle)
