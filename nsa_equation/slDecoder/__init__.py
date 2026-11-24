#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
slDecoder — SlDecoder 二进制到 XML 解码工具。

Python 重写的 `SlDecoder.exe` (C++)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/StLa/Tools/i386-winnt/
SlDecoder.exe`。

该工具用于将二进制数据解码为 XML 格式，使用 MSVCRT/MSVCP60 (C++ 运行时)、
Xml4_0u.dll (XML 解析)、ole32 (CoInitialize)、OLEAUT32 (SysAllocString,
SysFreeString)、KERNEL32 (文件操作)、USER32 (MessageBoxW)。

CLI:

  slDecoder <input_file> [output_file]

Arguments:
  input_file    输入二进制文件路径
  output_file   输出 XML 文件路径（可选）
"""

from . import slDecoder_exp


def slDecoder_handle(args):
    """Run the SlDecoder tool."""
    return slDecoder_exp.run_function(
        input_file=args.input_file,
        output_file=args.output_file,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `slDecoder` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "slDecoder",
        help="SlDecoder 二进制到 XML 解码工具",
        description="SlDecoder — 二进制到 XML 解码工具。使用 KERNEL32 文件操作、"
                    "MSVCRT/MSVCP60 (C++ 标准库)、Xml4_0u (XML 解析)、ole32"
                    "(CoInitialize)、OLEAUT32 (SysAllocString, SysFreeString)、"
                    "USER32 (MessageBoxW) 将二进制数据解码为 XML 格式。",
    )
    p.add_argument(
        "input_file", metavar="INPUT_FILE",
        help="输入二进制文件路径",
    )
    p.add_argument(
        "output_file", metavar="OUTPUT_FILE", nargs="?",
        help="输出 XML 文件路径（可选）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="启用详细输出",
    )
    p.set_defaults(func=slDecoder_handle)
