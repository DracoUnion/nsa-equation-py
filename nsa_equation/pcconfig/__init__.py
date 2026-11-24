#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pcconfig — PCConfig 配置工具。

Python 重写自 `PCConfig.exe` (C++/MSVCRT)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/Pc/Tools/i386-winnt/PCConfig.exe`。

读取/配置 PC 套件相关配置。
"""

from . import pcconfig_exp


def pcconfig_handle(args):
    """Run the pcconfig tool."""
    return pcconfig_exp.run_function(
        config_file=args.config_file,
    )


def reg_subparser(subparsers):
    """Register the `pcconfig` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "pcconfig",
        help="PCConfig 配置工具",
        description="pcconfig — 读取/配置 PC 套件相关配置。",
    )
    p.add_argument(
        "config_file", metavar="CONFIG_FILE", nargs="?", default=None,
        help="可选配置文件路径",
    )
    p.set_defaults(func=pcconfig_handle)
