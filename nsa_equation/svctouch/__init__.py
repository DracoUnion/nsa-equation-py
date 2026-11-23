#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
svctouch — SvcTouch 服务触摸/探测工具。

Python 重写的 `svctouch.exe` (C++)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/
Resources/Tools/svctouch.exe`。

该工具用于检测目标机器上的 DCOM 服务/应用程序是否存在。
通过静态 PE 分析恢复，其导入的关键函数包括：
  - KERNEL32: MultiByteToWideChar (ANSI 到宽字符转换)
  - OLE32:    CoInitialize, CoGetClassObject, CLSIDFromString, CoUninitialize (COM)
  - MSVCRT:   标准 C 运行时 (__getmainargs, _initterm, memset, printf,
              _exit, _XcptFilter, exit, _adjust_fdiv, _controlfp,
              __setusermatherr, __p__commode, __p__fmode, __set_app_type,
              _except_handler3)

CLI:

  svctouch <\\machinename> <CLSID>

Arguments:
  \\machinename  目标机器名称 (UNC 路径格式，如 \\\\TARGET)
  CLSID          要检测的 COM 类标识符 (GUID 字符串)

The tool reports whether the target machine has the specified service or
application, and whether it is running.
"""

from . import svctouch_exp


def svctouch_handle(args):
    """Run the svctouch tool against the supplied target."""
    return svctouch_exp.run_function(
        machine=args.machine,
        clsid=args.clsid,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `svctouch` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "svctouch",
        help="SvcTouch 服务触摸/探测工具",
        description="SvcTouch — 服务触摸/探测工具。使用 COM (CoInitialize/"
        "CoGetClassObject/CLSIDFromString) 检测目标机器上的 DCOM 服务或"
        "应用程序是否存在。",
    )
    p.add_argument(
        "machine", metavar="MACHINE",
        help="目标机器名称 (UNC 路径，如 \\\\TARGET)",
    )
    p.add_argument(
        "clsid", metavar="CLSID",
        help="要检测的 COM 类标识符 (GUID 字符串)",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="启用详细输出",
    )
    p.set_defaults(func=svctouch_handle)
