#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
oj_deleter — OJ_Deleter_2.4 Oddjob 删除工具。

Python 重写的 `OJ_Deleter_2.4.exe` (C++)，位于
`EQGRP_Lost_in_Translation-master/oddjob/Binaries/Payloads/OJ_Deleter_2.4.exe`。

该工具用于卸载/删除目标系统上的 Oddjob 植入相关文件。通过静态 PE 分析
恢复，其导入的关键函数包括：
  - KERNEL32: DeleteFileW (删除文件), Sleep, SetErrorMode,
              OutputDebugStringW, GetModuleHandleW, GetStartupInfoW
  - OLE32:    CoInitializeEx, CoCreateInstance, CoUninitialize, CoTaskMemFree (COM 初始化)
  - MSVCRT:   标准 C 运行时

CLI:

  oj_deleter <target_path> [--delay <ms>] [--debug]

target_path: 要删除的文件路径 (宽字符 UTF-16)
delay:       删除前等待的毫秒数 (默认 0)
debug:       启用调试输出 (OutputDebugStringW)
"""

from . import oj_deleter_exp


def oj_deleter_handle(args):
    """运行 OJ_Deleter 删除指定路径的文件。"""
    return oj_deleter_exp.run_function(
        target=args.target,
        delay=args.delay,
        debug=args.debug,
    )


def reg_subparser(subparsers):
    """Register the `oj_deleter` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "oj_deleter",
        help="OJ_Deleter_2.4 Oddjob 删除工具",
        description="OJ_Deleter_2.4 — Equation Group Oddjob 植入删除工具。"
                    "删除目标路径指定的文件，使用 COM 初始化和 DeleteFileW。",
    )
    p.add_argument(
        "target", metavar="TARGET_PATH",
        help="要删除的文件路径",
    )
    p.add_argument(
        "-d", "--delay", type=int, default=0, metavar="MS",
        help="删除前等待的毫秒数 (默认 0)",
    )
    p.add_argument(
        "--debug", action="store_true",
        help="启用调试输出",
    )
    p.set_defaults(func=oj_deleter_handle)
