#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
regprobe — RPC 端点映射器 (EPMapper) 探测 / 指纹识别工具。

Python 重写自 `regprobe.exe` (C++/MSVCRT)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/Resources/Tools/regprobe.exe`。

连接目标的 RPC 端点映射器（默认 TCP 135），探测操作系统版本并打印 RpcProxy 设置。
"""

from . import regprobe_exp


def regprobe_handle(args):
    """Run the regprobe tool."""
    return regprobe_exp.run_function(
        target=args.target,
        port=args.port,
    )


def reg_subparser(subparsers):
    """Register the `regprobe` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "regprobe",
        help="RPC 端点映射器 (EPMapper) 探测 / 指纹识别工具",
        description="regprobe — 探测目标主机的 RPC 端点映射器（默认 TCP 135），"
                    "指纹识别操作系统版本并打印 RpcProxy 设置。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP 地址",
    )
    p.add_argument(
        "port", metavar="PORT", nargs="?", type=int, default=135,
        help="RPC 端点映射器端口（默认 135）",
    )
    p.set_defaults(func=regprobe_handle)
