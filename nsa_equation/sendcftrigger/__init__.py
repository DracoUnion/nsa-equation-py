#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sendcftrigger — SendCFTrigger 配置触发工具。

Python 重写自 `SendCFTrigger.exe` (C++/MSVCRT)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/Pc/Tools/i386-winnt/SendCFTrigger.exe`。

读取 XML 配置文件，连接目标主机，发送触发请求。
"""

from . import sendcftrigger_exp


def sendcftrigger_handle(args):
    """Run the sendcftrigger tool."""
    return sendcftrigger_exp.run_function(
        target=args.target,
        port=args.port,
        config_file=args.config_file,
    )


def reg_subparser(subparsers):
    """Register the `sendcftrigger` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "sendcftrigger",
        help="SendCFTrigger 配置触发工具",
        description="sendcftrigger — 读取 XML 配置文件，连接目标主机，发送触发请求。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP 地址",
    )
    p.add_argument(
        "port", metavar="PORT", nargs="?", type=int, default=25,
        help="目标端口（默认 25，SMTP）",
    )
    p.add_argument(
        "config_file", metavar="CONFIG_FILE", nargs="?", default=None,
        help="可选 XML 配置文件路径",
    )
    p.set_defaults(func=sendcftrigger_handle)
