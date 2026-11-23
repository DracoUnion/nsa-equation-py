#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vlad — Vlad XML 验证工具。

Python 重写的 `Vlad.exe` (C++)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/Ep/Commands/Vlad.exe`。

该工具用于验证 XML 文件，使用 OLE32 (CoCreateInstance, OleRun, CoInitialize)、
OLEAUT32 (SetErrorInfo, VariantClear, SysFreeString, SysAllocStringByteLen,
SysAllocString, VariantChangeType, CreateErrorInfo, VariantInit, GetErrorInfo)、
KERNEL32 (文件和内存操作)、USER32 (wsprintfA, MessageBoxA)。

CLI:

  vlad <xml_file> [schema_file]

Arguments:
  xml_file      XML 文件路径
  schema_file   XML 架构文件路径（可选）
"""

from . import vlad_exp


def vlad_handle(args):
    """Run the Vlad tool."""
    return vlad_exp.run_function(
        xml_file=args.xml_file,
        schema_file=args.schema_file,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `vlad` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "vlad",
        help="Vlad XML 验证工具",
        description="Vlad — XML 验证工具。使用 OLE32 (CoCreateInstance, OleRun, CoInitialize)、"
                    "OLEAUT32 (VariantClear, SysFreeString, SysAllocStringByteLen, SysAllocString,"
                    "VariantChangeType, CreateErrorInfo, VariantInit, GetErrorInfo)、KERNEL32"
                    "文件/内存操作、USER32 (wsprintfA, MessageBoxA) 验证 XML 文件。",
    )
    p.add_argument(
        "xml_file", metavar="XML_FILE",
        help="XML 文件路径",
    )
    p.add_argument(
        "schema_file", metavar="SCHEMA_FILE", nargs="?",
        help="XML 架构文件路径（可选）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="启用详细输出",
    )
    p.set_defaults(func=vlad_handle)
