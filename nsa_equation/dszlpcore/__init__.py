#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dszlpcore — DszLpCore 后门核心工具。

Python 重写自 `DszLpCore.exe` (C++/MSVCRT)，位于
`EQGRP_Lost_in_Translation-master/windows/.../DszLpCore.exe`。

DszLp.exe 是轻量级启动壳；DszLpCore.exe 才是主体。本移植实现 TCP
监听/代理核心逻辑。
"""

from . import dszlpcore_exp


def dszlpcore_handle(args):
    """Run the dszlpcore tool."""
    return dszlpcore_exp.run_function(
        listen_port=args.listen_port,
        connect_target=args.connect_target,
        connect_port=args.connect_port,
    )


def reg_subparser(subparsers):
    """Register the `dszlpcore` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "dszlpcore",
        help="DszLpCore 后门核心工具",
        description="dszlpcore — DszLpCore 后门核心工具，实现 TCP "
                    "监听/代理核心逻辑。",
    )
    p.add_argument(
        "listen_port", metavar="LISTEN_PORT", type=int,
        help="本地监听端口",
    )
    p.add_argument(
        "connect_target", metavar="CONNECT_TARGET", nargs="?", default=None,
        help="可选，反向连接目标主机",
    )
    p.add_argument(
        "connect_port", metavar="CONNECT_PORT", nargs="?", type=int, default=None,
        help="可选，反向连接目标端口",
    )
    p.set_defaults(func=dszlpcore_handle)
