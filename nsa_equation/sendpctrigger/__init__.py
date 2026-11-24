#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sendpctrigger — SendPCTrigger 配置触发工具。

Python 重写自 `SendPCTrigger.exe` (C++/MSVCRT, Winsock)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/Pc/Legacy/Resources/PC/Tools/SendPCTrigger.exe`。

向目标主机的指定端口发送 PC 触发请求。
"""

from . import sendpctrigger_exp


def sendpctrigger_handle(args):
    """Run the sendpctrigger tool."""
    return sendpctrigger_exp.run_function(
        target=args.target,
        port=args.port,
    )


def reg_subparser(subparsers):
    """Register the `sendpctrigger` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "sendpctrigger",
        help="SendPCTrigger 配置触发工具",
        description="sendpctrigger — 向目标主机的指定端口发送 PC 触发请求。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP 地址",
    )
    p.add_argument(
        "port", metavar="PORT", nargs="?", type=int, default=445,
        help="目标端口（默认 445，SMB/RPC）",
    )
    p.set_defaults(func=sendpctrigger_handle)
