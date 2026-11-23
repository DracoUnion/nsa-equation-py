#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
greatdoccfg — GreatDoc DLL 配置工具。

Python 重写的 `greatdoc-dll-config.exe` (C++)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/GRDO/Tools/i386/
greatdoc-dll-config.exe`。

该工具用于配置 GREATERDOCTOR DLL 资源，使用 KERNEL32 文件/资源操作
(EndUpdateResourceW, GetLastError, BeginUpdateResourceW, UpdateResourceW,
HeapFree, TerminateProcess, GetCurrentProcess, UnhandledExceptionFilter,
SetUnhandledExceptionFilter, IsDebuggerPresent, HeapCreate, VirtualFree,
DeleteCriticalSection, LeaveCriticalSection, EnterCriticalSection, HeapAlloc,
VirtualAlloc, HeapReAlloc, GetModuleHandleW, Sleep, GetProcAddress, ExitProcess,
WriteFile, GetStdHandle, GetModuleFileNameW, FreeEnvironmentStringsW,
GetEnvironmentStringsW, GetCommandLineW, SetHandleCount, GetFileType,
GetStartupInfoA, TlsGetValue, TlsAlloc, TlsSetValue, TlsFree,
InterlockedIncrement, SetLastError, GetCurrentThreadId,
InterlockedDecrement, QueryPerformanceCounter, GetTickCount,
GetCurrentProcessId, GetSystemTimeAsFileTime, SetFilePointer,
WideCharToMultiByte, GetConsoleCP, GetConsoleMode, GetCPInfo, GetACP,
GetOEMCP, IsValidCodePage, MultiByteToWideChar,
InitializeCriticalSectionAndSpinCount, RtlUnwind, LoadLibraryA,
SetStdHandle, WriteConsoleW, GetConsoleOutputCP, WriteConsoleW,
LCMapStringA, LCMapStringW, GetStringTypeA, GetStringTypeW,
GetLocaleInfoA, FlushFileBuffers, HeapSize, CreateFileA, CloseHandle)。

CLI:

  greatdoccfg <input_file> [output_file]

Arguments:
  input_file    输入文件路径
  output_file   输出文件路径（可选）
"""

from . import greatdoccfg_exp


def greatdoccfg_handle(args):
    """Run the greatdoccfg tool."""
    return greatdoccfg_exp.run_function(
        input_file=args.input_file,
        output_file=args.output_file,
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
                    "GetModuleFileNameW, FreeEnvironmentStringsA/W,"
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
