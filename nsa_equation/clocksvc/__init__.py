#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
clocksvc — ClockSvc 监听/代理工具。

Python 重写的 `clocksvc.exe` (C++)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/Ep/clocksvc.exe`。

该工具用于监听和代理网络连接，支持 mailslot、socket 监听、服务管理等。
通过静态 PE 分析恢复，其导入的关键函数包括：
  - KERNEL32: 大量文件/内存/服务/进程/线程操作
  - USER32: CreateWindowEx, DestroyWindow, GetCursorPos, GetWindowLongA,
            GetActiveWindow, SetPropA
  - ADVAPI32: OpenProcessToken, LookupPrivilegeValueA, AdjustTokenPrivileges,
              RegOpenKeyExA, RegQueryValueExA, RegCloseKey, RegEnumKeyExA,
              RegSetValueExA, RegCreateKeyA, RegDeleteKeyA,
              InitializeSecurityDescriptor, SetSecurityDescriptorDacl,
              GetAce, AddAce, AddAccessAllowedAce, InitializeAcl,
              GetSecurityInfo, GetLengthSid, LookupAccountNameA
  - MSVCRT: 标准 C 运行时
  - WSOCK32: listen, setsockopt, gethostname, shutdown

CLI:

  clocksvc [options]

Options:
  --listen <port>   监听端口
  --mailslot <name> 监听邮件槽名称
  --service <name>  服务名称
  --registry <key>  注册表键名
  -v, --verbose     启用详细输出
"""

from . import clocksvc_exp


def clocksvc_handle(args):
    """Run the clocksvc tool."""
    return clocksvc_exp.run_function(
        listen_port=args.listen_port,
        mailslot=args.mailslot,
        service=args.service,
        registry=args.registry,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `clocksvc` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "clocksvc",
        help="ClockSvc 监听/代理工具",
        description="ClockSvc — 监听/代理工具。使用 KERNEL32 文件/服务/"
                    "注册表操作、USER32 窗口操作、ADVAPI32 服务和注册表操作、"
                    "MSVCRT 标准 C 运行时、WSOCK32 socket 监听。",
    )
    p.add_argument(
        "--listen", metavar="PORT", type=int,
        help="监听端口",
    )
    p.add_argument(
        "--mailslot", metavar="NAME",
        help="监听邮件槽名称",
    )
    p.add_argument(
        "--service", metavar="NAME",
        help="服务名称",
    )
    p.add_argument(
        "--registry", metavar="KEY",
        help="注册表键名",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="启用详细输出",
    )
    p.set_defaults(func=clocksvc_handle)
