#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
makedmgd — Oddjob ZiPo DMG 包打包工具。

Python 重写的 `makedmgd.exe` (C++)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/Ops/Tools/ZiPo/makedmgd.exe`。

该工具用于打包 Oddjob ZiPo DMG 文件，使用 UCL 数据压缩库。
通过静态 PE 分析恢复，其导入的关键函数包括：
  - KERNEL32: GetVersion, GetCurrentProcessId, GetCurrentThreadId,
              GetTickCount, QueryPerformanceCounter, GetModuleHandleA,
              SetUnhandledExceptionFilter, UnhandledExceptionFilter,
              GetCurrentProcess, TerminateProcess, InterlockedCompareExchange,
              Sleep, InterlockedExchange, RtlUnwind, GetSystemTimeAsFileTime
  - MSVCRT:   标准 C 运行时 (_iob, calloc, free, fprintf, memcpy, strlen,
              _snscanf, strcmp, memset, malloc, __getmainargs, _exit,
              _XcptFilter, exit, _initterm, _amsg_exit, __setusermatherr,
              _adjust_fdiv, __p__commode, __p__fmode, __set_app_type,
              ?terminate@@YAXXZ, _controlfp, realloc, fread, ftell, fclose,
              fseek, fopen, fwrite, srand, floor, rand, _ftime)

CLI:

  makedmgd <package_type> <directory> [options]

Package types (from the binary's .data section):
  envoy_verifytorpid      - VerifyTorpid package
  finkdifferent           - FinkDifferent package
  finkdifferent_nothread  - FinkDifferent no-thread package
  finkdifferent_ghostlyhammer - FinkDifferent ghostlyhammer package
  peddlecheap             - PeddleCheap package
  veto                    - VETO package
"""

from . import makedmgd_exp


def makedmgd_handle(args):
    """Run the makedmgd tool."""
    return makedmgd_exp.run_function(
        package_type=args.package_type,
        directory=args.directory,
        output=args.output,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `makedmgd` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "makedmgd",
        help="Oddjob ZiPo DMG 包打包工具",
        description="makedmgd — Oddjob ZiPo DMG 包打包工具。使用 UCL 数据"
                    "压缩库打包 DMG 文件，支持多种包类型。",
    )
    p.add_argument(
        "package_type", metavar="TYPE",
        help="包类型: envoy_verifytorpid, finkdifferent, finkdifferent_nothread, "
             "finkdifferent_ghostlyhammer, peddlecheap, veto",
    )
    p.add_argument(
        "directory", metavar="DIR",
        help="要打包的目录路径",
    )
    p.add_argument(
        "-o", "--output", metavar="FILE",
        help="输出 DMG 文件路径",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="启用详细输出",
    )
    p.set_defaults(func=makedmgd_handle)
