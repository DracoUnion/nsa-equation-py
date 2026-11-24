#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rpc2 — RPC2 RPC 探测工具。

Python 重写自 `RPC2.exe` (C++/MSVCRT)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/Resources/Tools/RPC2.exe`
（以及 ECWI 变体）。

向目标主机的 RPC 端点发起探测请求（8 种 run option）。
"""

from . import rpc2_exp


def rpc2_handle(args):
    """Run the rpc2 tool."""
    return rpc2_exp.run_function(
        target=args.target,
        port=args.port,
        run_option=args.run_option,
    )


def reg_subparser(subparsers):
    """Register the `rpc2` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "rpc2",
        help="RPC2 RPC 探测工具",
        description="rpc2 — 向目标主机的 RPC 端点发起探测请求，支持 8 种 "
                    "run option（运行模式）。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP 地址",
    )
    p.add_argument(
        "port", metavar="PORT", nargs="?", type=int, default=135,
        help="目标端口（默认 135，RPC 端点映射器）",
    )
    p.add_argument(
        "run_option", metavar="RUN_OPTION", nargs="?", type=int, default=0,
        help="运行选项（0-7，对应原工具的 8 种运行模式）",
    )
    p.set_defaults(func=rpc2_handle)
