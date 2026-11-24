#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sendddtrigger — SendDDTrigger 配置触发工具。

Python 重写自 `SendDDTrigger.exe` (C++/MSVCRT, Winsock)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/Pc/Legacy/Resources/PC/Tools/SendDDTrigger.exe`。

向目标主机的指定端口发送 DD 触发请求。
"""

from . import sendddtrigger_exp


def sendddtrigger_handle(args):
    """Run the sendddtrigger tool."""
    return sendddtrigger_exp.run_function(
        target=args.target,
        port=args.port,
    )


def reg_subparser(subparsers):
    """Register the `sendddtrigger` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "sendddtrigger",
        help="SendDDTrigger 配置触发工具",
        description="sendddtrigger — 向目标主机的指定端口发送 DD 触发请求。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP 地址",
    )
    p.add_argument(
        "port", metavar="PORT", nargs="?", type=int, default=445,
        help="目标端口（默认 445，SMB/RPC）",
    )
    p.set_defaults(func=sendddtrigger_handle)
