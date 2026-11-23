#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pccfg — PCConfig 配置工具。

Python 重写的 `PCConfig.exe` (C++，MSVCR90/xerces-c)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/Pc/Tools/i386-winnt/PCConfig.exe`。

该工具用于读取和修改 XML 配置文件，支持网络配置和文件操作。
通过静态 PE 分析恢复，其导入的关键函数包括：
  - xerces-c_2_7: XML 解析库 (DOM 解析器)
  - WS2_32: inet_addr, inet_ntoa, WSASetLastError (网络地址转换)
  - MSVCR90/MSVCP90: 标准 C++ 运行时
  - KERNEL32: 文件操作 (CreateFileW, ReadFile, WriteFile, etc.),
              时间转换 (FileTimeToSystemTime, SystemTimeToFileTime),
              内存映射文件 (CreateFileMappingW, MapViewOfFile, etc.)

CLI:

  pccfg <config_file> [--get <key>] [--set <key> <value>] [--list]

Options:
  --get <key>    获取指定键的配置值
  --set <key> <value>  设置指定键的配置值
  --list         列出所有配置项
"""

from . import pccfg_exp


def pccfg_handle(args):
    """Run the PCConfig tool."""
    return pccfg_exp.run_function(
        config_file=args.config_file,
        get_key=args.get,
        set_key=args.set_key,
        set_value=args.set_value,
        list_all=args.list,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `pccfg` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "pccfg",
        help="PCConfig 配置工具",
        description="PCConfig — 配置工具。使用 XML 配置文件（xerces-c 库）"
                    "读取和修改配置项，支持网络配置和文件操作。",
    )
    p.add_argument(
        "config_file", metavar="CONFIG_FILE",
        help="配置文件路径",
    )
    p.add_argument(
        "--get", metavar="KEY",
        help="获取指定键的配置值",
    )
    p.add_argument(
        "--set", metavar="KEY",
        help="设置指定键的配置值",
    )
    p.add_argument(
        "set_value", metavar="VALUE", nargs="?",
        help="设置的值（与 --set 一起使用）",
    )
    p.add_argument(
        "-l", "--list", action="store_true",
        help="列出所有配置项",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="启用详细输出",
    )
    p.set_defaults(func=pccfg_handle)
