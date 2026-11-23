#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
simrpc — SIM RPC 信息查询工具。

Python 重写的 `simrpc.exe` (C++)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/
Resources/Tools/simrpc.exe`。

该工具用于查询目标主机上的 RPC 服务信息，类似于 Unix 的 rpcinfo。
通过静态 PE 分析恢复，其导入的关键函数包括：
  - WSOCK32: WSAStartup, socket, connect, sendto, recv, select,
             gethostbyname, htons, inet_addr, __WSAFDIsSet
  - KERNEL32: ExitProcess, SetUnhandledExceptionFilter
  - CRTDLL: 标准 C 运行时 (__GetMainArgs, _cexit, atoi, fprintf,
            printf, memcpy, memset, signal, sprintf, sscanf, strncmp,
            strncpy, strtol, _close, _getpid, _environ_dll, _fmode_dll,
            _fpreset, _iob, _setmode, atexit)

CLI:

  simrpc <host> [-t | -u | -l] [-m] [-r <num>] [-q <num>] [-v] [-s]
             [<prog_number> [<version>]]

Options:
  -t      Use TCP packets for request
  -u      Use UDP packets for request (default)
  -l      Use UDP packets for request (same as -u)
  -m      Use Alternate UDP port (does not work on all systems)
  -r num  Retry after num seconds
  -q num  Stop retrying after num seconds
  -v      Print a couple extras
  -s      Long printout
"""

from . import simrpc_exp


def simrpc_handle(args):
    """Run the simrpc tool against the supplied host."""
    return simrpc_exp.run_function(
        host=args.host,
        use_tcp=args.use_tcp,
        use_udp=args.use_udp,
        alt_udp=args.alt_udp,
        retry=args.retry,
        total_timeout=args.total_timeout,
        verbose=args.verbose,
        long_output=args.long_output,
        prog_number=args.prog_number,
        version=args.version,
    )


def reg_subparser(subparsers):
    """Register the `simrpc` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "simrpc",
        help="SIM RPC 信息查询工具",
        description="simrpc — SIM RPC 信息查询工具，类似于 Unix 的 rpcinfo。"
                    "通过 Winsock 查询目标主机上的 RPC 服务信息。",
    )
    p.add_argument(
        "host", metavar="HOST",
        help="目标主机名或 IP 地址",
    )
    p.add_argument(
        "-t", "--tcp", action="store_true",
        help="使用 TCP 包进行请求",
    )
    p.add_argument(
        "-u", "--udp", action="store_true",
        help="使用 UDP 包进行请求 (默认)",
    )
    p.add_argument(
        "-l", "--udp-alt", action="store_true",
        help="使用 UDP 包进行请求 (与 -u 相同)",
    )
    p.add_argument(
        "-m", "--alt-port", action="store_true",
        help="使用替代 UDP 端口 (在所有系统上可能不工作)",
    )
    p.add_argument(
        "-r", "--retry", type=int, metavar="NUM",
        help="重试间隔秒数",
    )
    p.add_argument(
        "-q", "--total-timeout", type=int, metavar="NUM",
        help="停止重试的总秒数",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="打印额外信息",
    )
    p.add_argument(
        "-s", "--long", action="store_true",
        help="长输出格式",
    )
    p.add_argument(
        "prog_number", metavar="PROG", nargs="?", type=int,
        help="RPC 程序号",
    )
    p.add_argument(
        "version", metavar="VER", nargs="?", type=int,
        help="RPC 程序版本号",
    )
    p.set_defaults(func=simrpc_handle)
