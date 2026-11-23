#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
renamer — Renamer 文件重命名工具。

Python 重写的 `renamer.exe` (C++)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/Ops/Tools/renamer.exe`。

该工具用于重命名文件，读取目录中的文件，应用重命名规则，写入结果。
通过静态 PE 分析恢复，其导入的关键函数包括：
  - KERNEL32: FindFirstFileW, FindNextFileW, MoveFileW, CreateFileW,
              ReadFile, WriteFile, CloseHandle, SetFilePointer, GetFileSize,
              VirtualAlloc, VirtualFree, SetFileAttributesA, CopyFileA,
              GetLastError, GetCommandLineA, GetVersion, ExitProcess,
              TerminateProcess, GetCurrentProcess, UnhandledExceptionFilter,
              GetModuleFileNameA, FreeEnvironmentStringsA,
              FreeEnvironmentStringsW, WideCharToMultiByte,
              GetEnvironmentStrings, GetEnvironmentStringsW,
              SetHandleCount, GetStdHandle, GetFileType, GetStartupInfoA,
              GetModuleHandleA, GetEnvironmentVariableA, GetVersionExA,
              HeapDestroy, HeapCreate, VirtualFree, HeapFree, RtlUnwind,
              HeapAlloc, GetCPInfo, GetACP, GetOEMCP, HeapReAlloc,
              GetProcAddress, LoadLibraryA, FlushFileBuffers,
              LCMapStringA, LCMapStringW, SetFilePointer
  - USER32:   wsprintfW, MessageBoxA

CLI:

  renamer <input_dir> <output_dir> <pattern> [replacement]

Arguments:
  input_file       输入文件或目录路径
  output_file      输出文件或目录路径
  pattern          重命名模式
  replacement      替换名称（可选）
"""

from . import renamer_exp


def renamer_handle(args):
    """Run the renamer tool."""
    return renamer_exp.run_function(
        input_file=args.input_file,
        output_file=args.output_file,
        pattern=args.pattern,
        replacement=args.replacement,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `renamer` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "renamer",
        help="Renamer 文件重命名工具",
        description="Renamer — 文件重命名工具。读取目录中的文件，应用重命名"
                    "规则，写入结果，使用 KERNEL32 文件操作。",
    )
    p.add_argument(
        "input_file", metavar="INPUT_FILE",
        help="输入文件或目录路径",
    )
    p.add_argument(
        "output_file", metavar="OUTPUT_FILE",
        help="输出文件或目录路径",
    )
    p.add_argument(
        "pattern", metavar="PATTERN",
        help="重命名模式",
    )
    p.add_argument(
        "replacement", metavar="REPLACEMENT", nargs="?",
        help="替换名称（可选）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="启用详细输出",
    )
    p.set_defaults(func=renamer_handle)
