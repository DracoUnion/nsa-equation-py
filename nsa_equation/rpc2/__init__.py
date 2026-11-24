#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rpc2 — RPC2 RPC 探测工具。

Python 重写自 `RPC2.exe` (C++/MSVCRT)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/Resources/Tools/RPC2.exe`。

向目标主机的 RPC 端点映射器 (EPMapper, TCP 135) 发起探测请求，
检测目标 RPC 服务状态、操作系统版本以及 RPC DCOM 漏洞补丁状态
(CVE-2003-0031 / CrystalIce，KB824146 / KB823980)。

支持两种模式：
- telnet：标准 Telnet 风格探测
- hprpc：基于 HPRPC 的探测

CLI:

  rpc2 <target_ip> [target_port] [mode]

  target_ip          目标主机 IP
  target_port        目标端口（默认 135，RPC 端点映射器）
  mode               探测模式：telnet 或 hprpc（默认 telnet）

输出示例：

  [*] RPC2 (RPC Probe) - Python port (DAVE 库)
  [*] Target: 192.168.1.5:135
  [*] Mode: telnet
  [*] Checking RPC endpoint mapper...
  [*] OS Version: Windows XP Service Pack 1
  [*] KB824146: Not installed (VULNERABLE to CrystalIce)
  [*] KB823980: Not installed (VULNERABLE to CrystalIce)
  [*] RPC DCOM exploitability: VULNERABLE
"""

from . import rpc2_exp


def rpc2_handle(args):
    """Run the RPC2 tool."""
    return rpc2_exp.run_function(
        target_ip=args.target_ip,
        port=args.target_port,
        mode=args.mode,
    )


def reg_subparser(subparsers):
    """Register the `rpc2` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "rpc2",
        help="RPC2 RPC 探测工具",
        description="rpc2 — 向目标主机的 RPC 端点映射器 (EPMapper, TCP 135) 发起探测请求，"
                    "检测目标 RPC 服务状态、操作系统版本以及 RPC DCOM 漏洞补丁状态。",
    )
    p.add_argument("target_ip", help="目标主机 IP")
    p.add_argument("target_port", metavar="PORT", type=int, default=135,
                   help="目标端口（默认 135，RPC 端点映射器）")
    p.add_argument("mode", metavar="MODE", nargs="?", default="telnet",
                   help="探测模式：telnet 或 hprpc（默认 telnet）")
    p.set_defaults(func=rpc2_handle)
