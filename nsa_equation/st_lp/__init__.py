#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
st_lp — ST (RideArea) 后门命令控制工具。

Python 重写自 `st_lp.exe` (C++/MSVCRT)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/Exploits/ST 1.14/st_lp.exe`。

与目标主机建立 TCP 连接，提供交互式命令行（trigger/unload/kill/resend/
buffer/ping/execute 等）。
"""

from . import st_lp_exp


def st_lp_handle(args):
    """Run the st_lp tool."""
    return st_lp_exp.run_function(
        target=args.target,
        port=args.port,
    )


def reg_subparser(subparsers):
    """Register the `st_lp` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "st_lp",
        help="ST (RideArea) 后门命令控制工具",
        description="st_lp — 与目标主机建立 TCP 连接，提供交互式命令行，"
                    "支持 trigger/unload/kill/resend/buffer/ping/execute 等指令。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP 地址",
    )
    p.add_argument(
        "port", metavar="PORT", nargs="?", type=int, default=445,
        help="目标端口（默认 445，SMB）",
    )
    p.set_defaults(func=st_lp_handle)
