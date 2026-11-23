#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
papercut — PaperCut 配置工具。

Python 重写的 `papercut_2.1.0.5_Win32.exe` (C++)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/PaCu/Uploads/i386/winnt/
papercut_2.1.0.5_Win32.exe`。

该工具用于配置和管理系统设置，支持 Boost program_options 命令行解析、
KERNEL32 文件/服务/注册表操作、ADVAPI32 服务和注册表操作。
通过静态 PE 分析恢复，其导入的关键函数包括：
  - KERNEL32: 大量文件、内存、服务、注册表操作
  - ADVAPI32: OpenProcessToken, LookupPrivilegeValueA, AdjustTokenPrivileges,
              RegOpenKeyExA, RegQueryValueExA, RegCloseKey, RegEnumKeyExA
  - USER32:   MessageBoxA, wsprintfW
  - PSAPI:    GetMappedFileNameA
  - MSVCR71/MSVCP71: 标准 C++ 运行时
  - Boost: program_options, exception 处理

CLI:

  papercut <config_file> [--get <key>] [--set <key> <value>] [--list]

Options:
  --get <key>    获取指定键的配置值
  --set <key> <value>  设置指定键的配置值
  --list         列出所有配置项
"""

from . import papercut_exp


def papercut_handle(args):
    """Run the papercut tool."""
    return papercut_exp.run_function(
        config_file=args.config_file,
        get_key=args.get,
        set_key=args.set_key,
        set_value=args.set_value,
        list_all=args.list,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `papercut` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "papercut",
        help="PaperCut 配置工具",
        description="PaperCut — 配置工具。使用 XML 配置文件读取和修改配置"
                    "项，使用 KERNEL32 文件/服务/注册表操作、ADVAPI32 服务和"
                    "注册表操作、USER32 消息框。",
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
    p.set_defaults(func=papercut_handle)
