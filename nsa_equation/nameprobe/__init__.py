#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nameprobe — 名称/端点探测工具。

Python 重写自 `NameProbe.exe` (C++/MSVCRT，Winsock)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/Resources/Tools/NameProbe.exe`。

向目标主机的指定端口发起 TCP 连接并发送探测缓冲区。
"""

from . import nameprobe_exp


def nameprobe_handle(args):
    """Run the nameprobe tool."""
    return nameprobe_exp.run_function(
        target=args.target,
        port=args.port,
    )


def reg_subparser(subparsers):
    """Register the `nameprobe` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "nameprobe",
        help="名称/端点探测工具",
        description="nameprobe — 向目标主机的指定端口发起 TCP 连接并发送探测缓冲区，"
                    "用于探测端点是否开放并响应。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP 地址",
    )
    p.add_argument(
        "port", metavar="PORT", nargs="?", type=int, default=137,
        help="目标端口（默认 137，NetBIOS 名称服务）",
    )
    p.set_defaults(func=nameprobe_handle)
