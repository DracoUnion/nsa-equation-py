#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sendpktrigger — SendPKTrigger 配置触发工具。

Python 重写自 `SendPKTrigger.exe` (C++/MSVCRT, Winsock)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/Pc/Tools/i386-winnt/SendPKTrigger.exe`。

向目标主机的指定端口发送 PK 触发请求。
"""

from . import sendpktrigger_exp


def sendpktrigger_handle(args):
    """Run the sendpktrigger tool."""
    return sendpktrigger_exp.run_function(
        target=args.target,
        port=args.port,
    )


def reg_subparser(subparsers):
    """Register the `sendpktrigger` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "sendpktrigger",
        help="SendPKTrigger 配置触发工具",
        description="sendpktrigger — 向目标主机的指定端口发送 PK 触发请求。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP 地址",
    )
    p.add_argument(
        "port", metavar="PORT", nargs="?", type=int, default=445,
        help="目标端口（默认 445，SMB/RPC）",
    )
    p.set_defaults(func=sendpktrigger_handle)
