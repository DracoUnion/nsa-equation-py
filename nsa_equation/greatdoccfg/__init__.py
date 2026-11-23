#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vtuner — Vtuner 配置工具。

Python 重写的 `vtuner.exe` (C++)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/GRDO/Uploads/i386/winnt/
vtuner.exe`。

该工具用于配置系统设置，使用 KERNEL32 (大量文件/内存/服务/进程操作)、
WS2_32 (网络)、imagehlp (MapAndLoad, UnMapAndLoad)、sfc (SfcIsFileProtected)、
VERSION (GetFileVersionInfoSizeW, VerQueryValueW, GetFileVersionInfoW)、
CRYPT32 (多种加密函数)、USER32 (EnumWindows, GetClipboardFormatNameW,
IsWindow, IsWindowVisible, GetWindowThreadProcessId, wsprintfW)、
ADVAPI32 (多种加密和注册表操作)、ole32 (CoUninitialize, CoSetProxyBlanket,
CoCreateInstance, CoInitializeSecurity, CoInitializeEx)、
OLEAUT32 (SysAllocString, SysFreeString)。

CLI:

  greatdoccfg <config_file> [--get <key>] [--set <key> <value>] [--list]

Options:
  --get <key>    获取指定键的配置值
  --set <key> <value>  设置指定键的配置值
  --list         列出所有配置项
"""

from . import greatdoccfg_exp


def greatdoccfg_handle(args):
    """Run the greatdoccfg tool."""
    return greatdoccfg_exp.run_function(
        config_file=args.config_file,
        get_key=args.get,
        set_key=args.set_key,
        set_value=args.set_value,
        list_all=args.list,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `greatdoccfg` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "greatdoccfg",
        help="GreatDoc DLL 配置工具",
        description="GreatDoc DLL 配置工具。使用 KERNEL32 文件/资源操作"
                    "(EndUpdateResourceW, GetLastError, BeginUpdateResourceW,"
                    "UpdateResourceW, HeapFree, TerminateProcess,"
                    "GetCurrentProcess, UnhandledExceptionFilter,"
                    "SetUnhandledExceptionFilter, IsDebuggerPresent,"
                    "HeapCreate, VirtualFree, DeleteCriticalSection,"
                    "LeaveCriticalSection, EnterCriticalSection, HeapAlloc,"
                    "VirtualAlloc, HeapReAlloc, GetModuleHandleW, Sleep,"
                    "GetProcAddress, ExitProcess, WriteFile, GetStdHandle,"
                    "GetModuleFileNameW, FreeEnvironmentStringsW,"
                    "GetEnvironmentStringsW, GetCommandLineW, SetHandleCount,"
                    "GetFileType, GetStartupInfoA, TlsGetValue, TlsAlloc,"
                    "TlsSetValue, TlsFree, InterlockedIncrement, SetLastError,"
                    "GetCurrentThreadId, InterlockedDecrement,"
                    "QueryPerformanceCounter, GetTickCount, GetCurrentProcessId,"
                    "GetSystemTimeAsFileTime, SetFilePointer,"
                    "WideCharToMultiByte, GetConsoleCP, GetConsoleMode,"
                    "GetCPInfo, GetACP, GetOEMCP, IsValidCodePage,"
                    "MultiByteToWideChar, InitializeCriticalSectionAndSpinCount,"
                    "RtlUnwind, LoadLibraryA, SetStdHandle, WriteConsoleW,"
                    "GetConsoleOutputCP, WriteConsoleW, LCMapStringA,"
                    "LCMapStringW, GetStringTypeA, GetStringTypeW,"
                    "GetLocaleInfoA, FlushFileBuffers, HeapSize, CreateFileA,"
                    "CloseHandle)。",
    )
    p.add_argument(
        "input_file", metavar="INPUT_FILE",
        help="输入文件路径",
    )
    p.add_argument(
        "output_file", metavar="OUTPUT_FILE", nargs="?",
        help="输出文件路径（可选）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="启用详细输出",
    )
    p.set_defaults(func=greatdoccfg_handle)
