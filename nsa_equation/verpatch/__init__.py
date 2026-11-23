#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verpatch — VerPatch PE 版本修补工具。

Python 重写的 `verpatch.exe` (C++)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/Pc/Tools/i386-winnt/verpatch.exe`。

该工具用于修改 PE 文件的版本资源信息。
通过静态 PE 分析恢复，其导入的关键函数包括：
  - KERNEL32: CreateFileW, ReadFile, WriteFile, CloseHandle,
              BeginUpdateResourceW, UpdateResourceW, EndUpdateResourceW,
              SetFilePointer, GetFileSize, etc.
  - imagehlp.dll: MapAndLoad, UnMapAndLoad, CheckSumMappedFile (PE 校验和)
  - VERSION.dll: GetFileVersionInfoW (版本信息)

CLI:

  verpatch <pe_file> [--version <ver>] [--company <name>] [--product <name>]
             [--file-desc <desc>] [--internal-name <name>]
             [--legal-copyright <text>] [--checksum]

Options:
  --version <ver>      文件版本 (如 1.0.0.0)
  --company <name>     公司名称
  --product <name>     产品名称
  --file-desc <desc>   文件描述
  --internal-name <name> 内部名称
  --legal-copyright <text> 法律版权
  --checksum           重算 PE 校验和
"""

from . import verpatch_exp


def verpatch_handle(args):
    """Run the verpatch tool."""
    return verpatch_exp.run_function(
        pe_file=args.pe_file,
        version=args.version,
        company=args.company,
        product=args.product,
        file_desc=args.file_desc,
        internal_name=args.internal_name,
        legal_copyright=args.legal_copyright,
        checksum=args.checksum,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `verpatch` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "verpatch",
        help="VerPatch PE 版本修补工具",
        description="VerPatch — PE 版本修补工具。使用 imagehlp (MapAndLoad,"
                    "CheckSumMappedFile) 和 VERSION.dll (GetFileVersionInfoW)"
                    "修改 PE 文件的版本资源信息。",
    )
    p.add_argument(
        "pe_file", metavar="PE_FILE",
        help="PE 文件路径",
    )
    p.add_argument(
        "--version", metavar="VER",
        help="文件版本 (如 1.0.0.0)",
    )
    p.add_argument(
        "--company", metavar="NAME",
        help="公司名称",
    )
    p.add_argument(
        "--product", metavar="NAME",
        help="产品名称",
    )
    p.add_argument(
        "--file-desc", metavar="DESC",
        help="文件描述",
    )
    p.add_argument(
        "--internal-name", metavar="NAME",
        help="内部名称",
    )
    p.add_argument(
        "--legal-copyright", metavar="TEXT",
        help="法律版权",
    )
    p.add_argument(
        "--checksum", action="store_true",
        help="重算 PE 校验和",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="启用详细输出",
    )
    p.set_defaults(func=verpatch_handle)
