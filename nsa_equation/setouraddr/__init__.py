#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
setouraddr — SetOurAddr 地址设置工具。

Python 重写的 `SetOurAddr.exe` (C++)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/Pc/Tools/legacy/SetOurAddr.exe`。

该工具用于在文件中替换默认 IP/IPX 地址。
通过静态 PE 分析恢复，其导入的关键函数包括：
  - WS2_32: WSAStartup, gethostbyname, inet_addr, gethostname (网络地址)
  - KERNEL32: 文件操作 (CreateFileW, ReadFile, WriteFile, CloseHandle,
              SetFilePointer, GetFileSize, VirtualAlloc, etc.)
  - USER32:   wsprintfA, MessageBoxA

CLI:

  setouraddr <input_file> <output_file> <protocol> [IP/IPX_address]

Arguments:
  input_file    输入文件路径
  output_file   输出文件路径
  protocol      协议：1 = IP，2 = IPX
  IP/IPX_address 地址（可选；IP 模式下默认使用本地主机地址）

Examples:
  setouraddr input.dat output.dat 1          # Use local IP address
  setouraddr input.dat output.dat 1 192.168.1.100  # Use specific IP
  setouraddr input.dat output.dat 2 00000000.000000000000  # Use IPX address
"""

from . import setouraddr_exp


def setouraddr_handle(args):
    """Run the SetOurAddr tool."""
    return setouraddr_exp.run_function(
        input_file=args.input_file,
        output_file=args.output_file,
        protocol=args.protocol,
        address=args.address,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `setouraddr` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "setouraddr",
        help="SetOurAddr 地址设置工具",
        description="SetOurAddr — 地址设置工具。在文件中替换默认 IP/IPX"
                    "地址，使用 WS2_32 网络功能和 KERNEL32 文件操作。",
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
        "protocol", metavar="PROTOCOL", type=int, choices=[1, 2],
        help="协议：1 = IP，2 = IPX",
    )
    p.add_argument(
        "address", metavar="ADDRESS", nargs="?",
        help="IP/IPX 地址（IP 模式下可选，默认使用本地主机地址）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="启用详细输出",
    )
    p.set_defaults(func=setouraddr_handle)
