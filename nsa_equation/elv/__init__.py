#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
elv — Eternal/Love SMB/RPC 探测利用工具。

Python 重写自 `ELV.exe` (C++/MSVCRT)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/Exploits/ELV 2.1.3/ELV.exe`。

针对目标的 SMB/RPC 服务进行探测与利用。
"""

from . import elv_exp


def elv_handle(args):
    """Run the elv tool."""
    return elv_exp.run_function(
        target=args.target,
        port=args.port,
    )


def reg_subparser(subparsers):
    """Register the `elv` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "elv",
        help="Eternal/Love SMB/RPC 探测利用工具",
        description="elv — 针对目标的 SMB/RPC 服务进行探测与利用，"
                    "尝试植入后门。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP 地址",
    )
    p.add_argument(
        "port", metavar="PORT", nargs="?", type=int, default=445,
        help="目标端口（默认 445，SMB；也可为 135，RPC 端点映射器）",
    )
    p.set_defaults(func=elv_handle)
