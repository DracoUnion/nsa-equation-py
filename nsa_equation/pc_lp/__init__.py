#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pc_lp — PC_LP 监听/代理工具。

Python 重写的 `PC_LP.exe` (C++，MSVCR71/MSVCP71)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/Pc/Legacy/Bin/PC_LP.exe`。

该工具用于监听和代理网络连接，支持 socket 监听、文件操作、进程创建等。
通过静态 PE 分析恢复，其导入的关键函数包括：
  - WS2_32: socket, bind, listen, accept, send, recv, closesocket,
            WSAStartup, WSACleanup, gethostbyname, inet_addr, htons,
            ntohs, getpeername, getsockname, ioctlsocket
  - KERNEL32: CreateFileW, ReadFile, WriteFile, CloseHandle,
              SetFilePointer, GetFileSize, VirtualAlloc, VirtualFree,
              CreateProcessW, GetModuleFileNameW, SetCurrentDirectoryW,
              CreateDirectoryW, etc.
  - MSVCR71/MSVCP71: 标准 C++ 运行时 (_beginthreadex, _endthreadex,
                     malloc, free, sprintf, fprintf, etc.)

CLI:

  pc_lp <listen_port> [target_host] [target_port]

Arguments:
  listen_port   本地监听端口
  target_host   目标主机（可选，用于代理模式）
  target_port   目标端口（可选，用于代理模式）
"""

from . import pc_lp_exp


def pc_lp_handle(args):
    """Run the PC_LP tool."""
    return pc_lp_exp.run_function(
        listen_port=args.listen_port,
        target_host=args.target_host,
        target_port=args.target_port,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `pc_lp` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "pc_lp",
        help="PC_LP 监听/代理工具",
        description="PC_LP — 监听/代理工具。使用 WS2_32 socket 监听和代理"
                    "网络连接，使用 KERNEL32 进行文件和进程操作。",
    )
    p.add_argument(
        "listen_port", metavar="LISTEN_PORT", type=int,
        help="本地监听端口",
    )
    p.add_argument(
        "target_host", metavar="TARGET_HOST", nargs="?",
        help="目标主机（可选，用于代理模式）",
    )
    p.add_argument(
        "target_port", metavar="TARGET_PORT", type=int, nargs="?",
        help="目标端口（可选，用于代理模式）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="启用详细输出",
    )
    p.set_defaults(func=pc_lp_handle)
