#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
expa — EXPA 1.0.0.2 PE resource tool.

Python rewrite of `EXPA.exe` recovered from
`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/
Exploits/EXPA 1.0.0.2/EXPA.exe`.

EXPA is a PE resource extraction/injection tool.  It:

  1. Opens a target PE file,
  2. Maps it into memory,
  3. Enumerates resources (FindResourceA / LoadResource / LockResource /
     SizeofResource),
  4. Optionally extracts a resource to an output file,
  5. Optionally injects/replaces a resource in the PE.

The original binary is a small Win32 console tool (~20 KB) importing only
KERNEL32 and MSVCRT, driving raw file/PE manipulation directly.

CLI:

  expa <pe_file> [--list]
  expa <pe_file> --extract <type> <name> <out_file>
  expa <pe_file> --inject <type> <name> <in_file>

type and name can be numeric IDs or string names.
"""

from . import expa_exp


def expa_handle(args):
    """Run the EXPA resource tool against the supplied PE file."""
    return expa_exp.run_function(
        pe_path=args.pe_file,
        extract=args.extract,
        inject=args.inject,
        list_res=args.list,
    )


def reg_subparser(subparsers):
    """Register the `expa` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "expa",
        help="EXPA 1.0.0.2 PE 资源提取/注入工具",
        description="EXPA 1.0.0.2 — Equation Group PE 资源操作工具。"
                    "从 PE 文件中枚举、提取或注入资源，"
                    "镜像原始工具的 FindResourceA/LoadResource/LockResource/"
                    "SizeofResource 流程。",
    )
    p.add_argument(
        "pe_file", metavar="PE_FILE",
        help="目标 PE 文件路径",
    )
    p.add_argument(
        "--list", action="store_true",
        help="列出 PE 文件中的所有资源",
    )
    p.add_argument(
        "--extract", metavar=("TYPE", "NAME", "OUT_FILE"), nargs=3,
        help="提取资源：<类型ID/名> <名称ID/名> <输出文件>",
    )
    p.add_argument(
        "--inject", metavar=("TYPE", "NAME", "IN_FILE"), nargs=3,
        help="注入资源：<类型ID/名> <名称ID/名> <输入文件>",
    )
    p.set_defaults(func=expa_handle)
