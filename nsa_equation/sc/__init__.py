#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sc — Windows 服务控制工具 (Service Control)。

Python 重写的 `sc.exe` (C++)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/
Resources/Tools/sc.exe`。

该工具通过 ADVAPI32 服务管理 API 管理 Windows 服务。通过静态 PE 分析
恢复，其导入的关键函数包括：
  - ADVAPI32: OpenSCManagerW, CreateServiceW, DeleteService, StartServiceW,
              OpenServiceW, ControlService, QueryServiceStatus,
              QueryServiceConfigW, ChangeServiceConfigW, EnumServicesStatusW,
              CloseServiceHandle, ChangeServiceConfig2W,
              QueryServiceObjectSecurity, SetServiceObjectSecurity,
              EnumDependentServicesW, GetServiceKeyNameW,
              GetServiceDisplayNameW, LockServiceDatabase,
              UnlockServiceDatabase, QueryServiceLockStatusW,
              ConvertSecurityDescriptorToStringSecurityDescriptorW,
              ConvertStringSecurityDescriptorToSecurityDescriptorW,
              NotifyBootConfigStatus
  - KERNEL32: ExitProcess, LocalAlloc, GetLastError, FormatMessageW,
              GetCommandLineA, GetVersion, LocalFree, WideCharToMultiByte,
              ReadConsoleInputA, SetConsoleMode, GetConsoleMode,
              TerminateProcess, GetCurrentProcess, UnhandledExceptionFilter,
              GetModuleFileNameA, FreeEnvironmentStringsA,
              MultiByteToWideChar, FreeEnvironmentStringsW,
              GetEnvironmentStrings, GetEnvironmentStringsW, GetCPInfo,
              GetACP, GetOEMCP, SetHandleCount, GetStdHandle, GetFileType,
              GetStartupInfoA, HeapDestroy, HeapCreate, VirtualFree,
              RtlUnwind, WriteFile, CreateFileA, CloseHandle,
              WriteConsoleA, HeapFree, HeapAlloc, LCMapStringA,
              LCMapStringW, GetStringTypeA, GetStringTypeW, VirtualAlloc,
              GetProcAddress, LoadLibraryA, FlushFileBuffers,
              SetFilePointer, SetStdHandle
  - ntdll:    RtlAnsiStringToUnicodeString, RtlInitAnsiString,
              RtlAdjustPrivilege

CLI:

  sc <server> <command> <service name> [options]

Supported commands:
  query       Query service status
  create      Create a service entry
  delete      Delete a service entry
  start       Start a service
  stop        Stop a service
  config      Change service configuration
  qc          Query service configuration information
  control     Send a control code to a service
  contin      Send a CONTINUE control request
  sdshow      Display a service's security descriptor
  boot        Indicates whether the last boot should be saved
"""

from . import sc_exp


def sc_handle(args):
    """Run the sc tool against the supplied server/service."""
    return sc_exp.run_function(
        server=args.server,
        command=args.command,
        service=args.service,
        args=args.extra_args,
        display_name=args.display_name,
        bin_path=args.bin_path,
        start_type=args.start_type,
        error_control=args.error_control,
        load_order_group=args.load_order_group,
        tag=args.tag,
        deps=args.deps,
        service_obj_name=args.service_obj_name,
        password=args.password,
        description=args.description,
        failure_actions=args.failure_actions,
        buffer_size=args.buffer_size,
        sd=args.sd,
        timeout=args.timeout,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `sc` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "sc",
        help="Windows 服务控制工具 (Service Control)",
        description="sc — Windows 服务控制工具。通过 ADVAPI32 服务管理 API"
                    "管理 Windows 服务，支持查询、创建、删除、启动、停止、"
                    "配置等操作。",
    )
    p.add_argument(
        "server", metavar="SERVER",
        help="目标服务器名称 (或本机使用 . 或空字符串)",
    )
    p.add_argument(
        "command", metavar="COMMAND",
        help="操作命令: query, create, delete, start, stop, config, qc, "
             "control, contin, sdshow, boot",
    )
    p.add_argument(
        "service", metavar="SERVICE",
        help="服务名称",
    )
    p.add_argument(
        "extra_args", metavar="ARG", nargs="*",
        help="额外参数",
    )
    p.add_argument(
        "--display-name", metavar="NAME",
        help="显示名称 (用于 create/config)",
    )
    p.add_argument(
        "--bin-path", metavar="PATH",
        help="二进制文件路径 (用于 create/config)",
    )
    p.add_argument(
        "--start-type", metavar="TYPE",
        choices=["boot", "system", "auto", "demand", "disabled"],
        help="启动类型 (用于 create/config)",
    )
    p.add_argument(
        "--error-control", metavar="LEVEL",
        choices=["normal", "severe", "critical", "ignore"],
        help="错误控制级别 (用于 create/config)",
    )
    p.add_argument(
        "--description", metavar="TEXT",
        help="服务描述 (用于 description/config)",
    )
    p.add_argument(
        "--timeout", type=int, default=30, metavar="SEC",
        help="等待超时秒数 (默认 30)",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="启用详细输出",
    )
    p.set_defaults(func=sc_handle)
