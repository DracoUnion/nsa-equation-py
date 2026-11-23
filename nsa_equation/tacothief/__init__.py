#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tacothief — Tacothief 文件处理工具。

Python 重写的 `tacothief.exe` (C++)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/Ops/Tools/i386-winnt/
tacothief.exe`。

该工具用于处理文件数据，读取输入文件，处理数据，写入输出文件。
通过静态 PE 分析恢复，其导入的关键函数包括 KERNEL32 文件操作
(CreateFileA, ReadFile, WriteFile, CloseHandle, SetFilePointer, GetFileSize,
VirtualAlloc, VirtualFree, SetFileAttributesA, CopyFileA, etc.) 和
USER32 (MessageBoxA)。

CLI:

  tacothief <input_file> <output_file> <target_file>

Arguments:
  input_file    输入文件路径
  output_file   输出文件路径
  target_file   目标文件路径（用于引用）
"""

from . import tacothief_exp


def tacothief_handle(args):
    """Run the tacothief tool."""
    return tacothief_exp.run_function(
        input_file=args.input_file,
        output_file=args.output_file,
        target_file=args.target_file,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `tacothief` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "tacothief",
        help="Tacothief 文件处理工具",
        description="Tacothief — 文件处理工具。读取输入文件，处理数据，"
                    "写入输出文件，使用 KERNEL32 文件操作。",
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
        "target_file", metavar="TARGET_FILE",
        help="目标文件路径",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="启用详细输出",
    )
    p.set_defaults(func=tacothief_handle)
