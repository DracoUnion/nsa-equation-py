#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
setcallbackports — SetCallbackPorts 回调端口设置工具。

Python 重写的 `SetCallbackPorts.exe` (C++)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/Pc/Tools/legacy/
SetCallbackPorts.exe`。

该工具用于在目标文件中设置回调端口（1-6个）。
通过静态 PE 分析恢复，其导入的关键函数包括 KERNEL32 文件操作
(CreateFileW, ReadFile, WriteFile, CloseHandle, SetFilePointer, GetFileSize,
VirtualAlloc, VirtualFree, etc.) 和 USER32 (MessageBoxA)。

CLI:

  setcallbackports <input_file> <output_file> <port1> [port2] [port3] [port4] [port5] [port6]

Arguments:
  input_file    输入文件路径
  output_file   输出文件路径
  port1-6       回调端口（1-6个，至少1个）
"""

from . import setcallbackports_exp


def setcallbackports_handle(args):
    """Run the SetCallbackPorts tool."""
    return setcallbackports_exp.run_function(
        input_file=args.input_file,
        output_file=args.output_file,
        ports=args.ports,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `setcallbackports` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "setcallbackports",
        help="SetCallbackPorts 回调端口设置工具",
        description="SetCallbackPorts — 回调端口设置工具。在目标文件中设置"
                    "回调端口（1-6个），使用 KERNEL32 文件操作。",
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
        "ports", metavar="PORT", type=int, nargs="+",
        help="回调端口（1-6个，至少1个）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="启用详细输出",
    )
    p.set_defaults(func=setcallbackports_handle)
