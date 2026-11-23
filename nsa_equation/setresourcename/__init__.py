#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
setresourcename — SetResourceName 资源名称设置工具。

Python 重写的 `SetResourceName.exe` (C++)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/Pc/Tools/legacy/
SetResourceName.exe`。

该工具用于在目标文件中替换资源名称（OriginalFilename 或 InternalName）。
通过静态 PE 分析恢复，其导入的关键函数包括 KERNEL32 文件操作
(CreateFileW, ReadFile, WriteFile, CloseHandle, SetFilePointer, GetFileSize,
VirtualAlloc, VirtualFree, etc.) 和 USER32 (MessageBoxA, wsprintfA)。

CLI:

  setresourcename <input_file> <output_file> <old_resource> <new_resource_name>

Arguments:
  input_file       输入文件路径
  output_file      输出文件路径
  old_resource     旧资源索引：1=spcss32.exe, 2=appinit.dll, 3=memss.exe, 4=msvcp57.exe
  new_resource_name 新资源名称
"""

from . import setresourcename_exp


def setresourcename_handle(args):
    """Run the SetResourceName tool."""
    return setresourcename_exp.run_function(
        input_file=args.input_file,
        output_file=args.output_file,
        old_resource=args.old_resource,
        new_resource_name=args.new_resource_name,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `setresourcename` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "setresourcename",
        help="SetResourceName 资源名称设置工具",
        description="SetResourceName — 资源名称设置工具。在目标文件中替换"
                    "资源名称（OriginalFilename 或 InternalName），使用"
                    "KERNEL32 文件操作。",
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
        "old_resource", metavar="OLD_RESOURCE", type=int, choices=[1, 2, 3, 4],
        help="旧资源索引：1=spcss32.exe, 2=appinit.dll, 3=memss.exe, 4=msvcp57.exe",
    )
    p.add_argument(
        "new_resource_name", metavar="NEW_NAME",
        help="新资源名称",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="启用详细输出",
    )
    p.set_defaults(func=setresourcename_handle)
