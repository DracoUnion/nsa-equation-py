#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
setcallback — SetCallback 回调标志设置工具。

Python 重写的 `SetCallback.exe` (C++)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/Pc/Tools/legacy/SetCallback.exe`。

该工具用于设置目标文件中的回调标志（Callback Flag）。
通过静态 PE 分析恢复，其导入的关键函数包括：
  - KERNEL32: CreateFileW, ReadFile, WriteFile, CloseHandle,
              SetFilePointer, GetFileSize, SetFileAttributesA,
              CopyFileA, GetLastError, GetCommandLineA, GetVersion,
              ExitProcess, TerminateProcess, GetCurrentProcess,
              UnhandledExceptionFilter, GetModuleFileNameA,
              FreeEnvironmentStringsA/W, WideCharToMultiByte,
              MultiByteToWideChar, GetEnvironmentStringsA/W,
              SetHandleCount, GetStdHandle, WriteFile, GetStartupInfoA,
              GetModuleHandleA, GetEnvironmentVariableA, GetVersionExA,
              HeapDestroy, HeapCreate, VirtualFree, HeapFree, RtlUnwind,
              HeapAlloc, GetCPInfo, GetACP, GetOEMCP, HeapReAlloc,
              GetProcAddress, LoadLibraryA, FlushFileBuffers,
              MultiByteToWideChar, LCMapStringA/W, GetStringTypeA/W,
              SetStdHandle
  - USER32:   MessageBoxA, GetLastActivePopup, GetActiveWindow

CLI:

  setcallback <input_file> <output_file>

The tool reads an input file, sets the callback flag in it, and writes
the result to the output file. It turns the callback flag on.
"""

from . import setcallback_exp


def setcallback_handle(args):
    """Run the SetCallback tool."""
    return setcallback_exp.run_function(
        input_file=args.input_file,
        output_file=args.output_file,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `setcallback` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "setcallback",
        help="SetCallback 回调标志设置工具",
        description="SetCallback — 回调标志设置工具。读取输入文件，设置"
                    "回调标志（Callback Flag），写入输出文件。",
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
        "-v", "--verbose", action="store_true",
        help="启用详细输出",
    )
    p.set_defaults(func=setcallback_handle)
