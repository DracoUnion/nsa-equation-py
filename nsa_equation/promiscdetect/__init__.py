#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
promiscdetect — PromiscDetect 网卡混杂模式检测工具。

Python 重写的 `promiscdetect.exe` (C++)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/Ops/Uploads/i386/winnt/
promiscdetect.exe`。

该工具用于检测目标机器网络适配器是否处于混杂模式（Promiscuous Mode）。
通过静态 PE 分析恢复，其导入的关键函数包括：
  - KERNEL32: CreateFileA, DeviceIoControl, ReadFile, WriteFile, CloseHandle,
              SetFilePointer, GetFileSize, VirtualAlloc, VirtualFree,
              SetFileAttributesA, CopyFileA, GetLastError, GetCommandLineA,
              GetVersion, ExitProcess, TerminateProcess, GetCurrentProcess,
              UnhandledExceptionFilter, GetModuleFileNameA,
              FreeEnvironmentStringsA/W, WideCharToMultiByte,
              GetEnvironmentStrings, GetEnvironmentStringsW,
              SetHandleCount, GetStdHandle, GetFileType, GetStartupInfoA,
              GetModuleHandleA, GetEnvironmentVariableA, GetVersionExA,
              HeapDestroy, HeapCreate, VirtualFree, HeapFree, RtlUnwind,
              HeapAlloc, GetCPInfo, GetACP, GetOEMCP, HeapReAlloc,
              GetProcAddress, LoadLibraryA, FlushFileBuffers,
              MultiByteToWideChar, LCMapStringA, LCMapStringW,
              GetStringTypeA, GetStringTypeW, CloseHandle
  - ADVAPI32: RegOpenKeyExA, RegQueryValueExA, RegCloseKey, RegEnumKeyExA
  - USER32:   MessageBoxA, GetLastActivePopup, GetActiveWindow

CLI:

  promiscdetect [adapter_name]

Arguments:
  adapter_name   网络适配器名称（可选，默认检测所有适配器）
"""

from . import promiscdetect_exp


def promiscdetect_handle(args):
    """Run the promiscdetect tool."""
    return promiscdetect_exp.run_function(
        adapter_name=args.adapter,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `promiscdetect` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "promiscdetect",
        help="PromiscDetect 网卡混杂模式检测工具",
        description="PromiscDetect — 网卡混杂模式检测工具。使用 KERNEL32"
                    "设备操作 (CreateFileA, DeviceIoControl) 和 ADVAPI32"
                    "注册表操作检测目标机器网络适配器是否处于混杂模式。",
    )
    p.add_argument(
        "adapter", metavar="ADAPTER", nargs="?",
        help="网络适配器名称（可选，默认检测所有适配器）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="启用详细输出",
    )
    p.set_defaults(func=promiscdetect_handle)
