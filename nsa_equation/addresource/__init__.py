#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
addresource — 将资源注入目标 PE 文件的工具。

Python 重写自 `AddResource.exe` (C++/MSVCRT)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/Df/Tools/i386-winnt/AddResource.exe`。

从源 PE/DLL 中按类型/名称提取资源，可选 zlib 压缩或 LCG 异或混淆，再将其
作为资源写入目标 PE。
"""

from . import addresource_exp


def addresource_handle(args):
    """Run the addresource tool."""
    flags = 0
    for ch in (args.flags or "").upper():
        if ch == "C":
            flags |= 1
        elif ch == "F":
            flags |= 8
        elif ch == "M":
            flags |= 2
        elif ch == "P":
            flags |= 4
    rtype = int(args.rtype) if str(args.rtype).isdigit() else args.rtype
    rname = int(args.rname) if str(args.rname).isdigit() else args.rname
    return addresource_exp.run_function(
        flags=flags,
        rtype=rtype,
        rname=rname,
        pe_path=args.pe_path,
        resource_path=args.resource_path,
    )


def reg_subparser(subparsers):
    """Register the `addresource` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "addresource",
        help="将资源注入目标 PE 文件",
        description="addresource — 将资源从源 PE/DLL 提取并注入目标 PE 文件，"
                    "支持 zlib 压缩与 LCG 异或混淆。",
    )
    p.add_argument(
        "flags", metavar="FLAGS", nargs="?", default="",
        help="可选标志，任意顺序/组合：c=zlib 压缩，m=LCG 异或混淆，"
             "p=proprietary 目录，f=最终化 proprietary 目录",
    )
    p.add_argument(
        "rtype", metavar="TYPE",
        help="资源类型：十进制整数 ID 或字符串名",
    )
    p.add_argument(
        "rname", metavar="NAME",
        help="资源名称：十进制整数 ID 或字符串名",
    )
    p.add_argument(
        "pe_path", metavar="PE_PATH",
        help="目标 PE 文件路径",
    )
    p.add_argument(
        "resource_path", metavar="RESOURCE_PATH",
        help="源 PE/DLL 文件路径（从其中提取资源）",
    )
    p.set_defaults(func=addresource_handle)
