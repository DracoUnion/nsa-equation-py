#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
setports — SetPorts 端口设置工具。

Python 重写的 `SetPorts.exe` (C++)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/Pc/Tools/legacy/SetPorts.exe`。

该工具用于在目标文件中设置端口（1-5个）。
通过静态 PE 分析恢复，其导入的关键函数包括 KERNEL32 文件操作
(CreateFileW, ReadFile, WriteFile, CloseHandle, SetFilePointer, GetFileSize,
VirtualAlloc, VirtualFree, etc.) 和 USER32 (MessageBoxA)。

CLI:

  setports <input_file> <output_file> <version> <port1> [port2] [port3] [port4] [port5]

Arguments:
  input_file    输入文件路径
  output_file   输出文件路径
  version       版本：1 = PC 1.2, 2 = PC 1.2 (24 hour), 3 = PC 1.3, 4 = PC 1.3 (24 hour)
  port1-5       端口（1-5个，至少1个）
"""

from . import setports_exp


def setports_handle(args):
    """Run the SetPorts tool."""
    return setports_exp.run_function(
        input_file=args.input_file,
        output_file=args.output_file,
        version=args.version,
        ports=args.ports,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `setports` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "setports",
        help="SetPorts 端口设置工具",
        description="SetPorts — 端口设置工具。在目标文件中设置端口（1-5个），"
                    "使用 KERNEL32 文件操作。",
    )
    p.add_argument(
        "input_file", metavar="INPUT_FILE",
        help="输入文件路径",
    )
    p.add_argument(
        "output_file", metavar="OUTPUT_FILE",
        help="输出文件路径",
    )
    p.add_argument(
        "version", metavar="VERSION", type=int, choices=[1, 2, 3, 4],
        help="版本：1 = PC 1.2, 2 = PC 1.2 (24 hour), 3 = PC 1.3, 4 = PC 1.3 (24 hour)",
    )
    p.add_argument(
        "ports", metavar="PORT", type=int, nargs="+",
        help="端口（1-5个，至少1个）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="启用详细输出",
    )
    p.set_defaults(func=setports_handle)
