#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ridearea2 — RideArea2 植入包装/加载器工具。

Python 重写的 `RideArea2.exe` (C++)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/
Resources/Tools/RideArea2.exe`。

该工具用于加载和执行植入负载（DLL/EXE），支持从内存或磁盘加载、
指定函数序数、IP 地址/端口、线程选项等。
通过静态 PE 分析恢复，其导入的关键函数包括：
  - WS2_32: inet_ntoa, inet_addr, htons (网络地址转换)
  - KERNEL32: GetModuleHandleA, LoadLibraryA, GetProcAddress, FreeLibrary,
              VirtualAlloc, VirtualFree, CreateFileA, CreateThread,
              ExitThread, DeleteFileA, GetTempPathA, GetTempFileNameA,
              GetSystemDirectoryA, lstrcpyA, lstrcatA, lstrlenA, etc.
  - MSVCR71: 标准 C 运行时 (exit, fopen, fclose, fread, fwrite, fseek,
             ftell, calloc, malloc, free, sprintf, vfprintf, fflush, etc.)
  - ntdll: LdrQueryImageFileExecutionOptions, RtlAllocateHeap,
           RtlFreeHeap, RtlEnterCriticalSection, RtlLeaveCriticalSection,
           RtlFreeUnicodeString, RtlImageDirectoryEntryToData,
           RtlImageNtHeader, RtlNtStatusToDosError, NtCreateSection,
           NtMapViewOfSection

CLI:

  ridearea2 -i InputFile -o OutputFile [-x FileType [-d DropFileName [-D]]]
            [-t ThreadOption] [-f FunctionOrdinal [-I IpAddress -P Port]]
            [-a FunctionArgument] [-l LoadOption]

Options:
  -i InputFile         输入文件路径
  -o OutputFile        输出负载文件路径
  -x FileType          文件类型：DLL (默认) 或 EXE
  -d DropFileName      目标上放置的文件名 (仅 EXE 类型有效)
  -D                   DropOnly 模式：仅放置，不启动植入
  -t ThreadOption      线程选项：Multi (默认) 或 Single
  -f FunctionOrdinal   函数序数 (默认 13)
  -I IpAddress         IP 地址 (仅 ordinal 15 有效)
  -P Port              端口 (仅 ordinal 15 有效)
  -a FunctionArgument  函数参数 (默认 3)
  -l LoadOption        加载选项：Memory 或 Disk (默认 Disk)
"""

from . import ridearea2_exp


def ridearea2_handle(args):
    """Run the RideArea2 tool."""
    return ridearea2_exp.run_function(
        input_file=args.input_file,
        output_file=args.output_file,
        file_type=args.file_type,
        drop_file=args.drop_file,
        drop_only=args.drop_only,
        thread_option=args.thread_option,
        function_ordinal=args.function_ordinal,
        ip_address=args.ip_address,
        port=args.port,
        function_argument=args.function_argument,
        load_option=args.load_option,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `ridearea2` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "ridearea2",
        help="RideArea2 植入包装/加载器工具",
        description="RideArea2 — 植入包装/加载器工具。支持从内存或磁盘加载"
                    "植入负载，指定函数序数、IP 地址/端口、线程选项等。",
    )
    p.add_argument(
        "-i", "--input-file", metavar="FILE", required=True,
        help="输入文件路径",
    )
    p.add_argument(
        "-o", "--output-file", metavar="FILE", required=True,
        help="输出负载文件路径",
    )
    p.add_argument(
        "-x", "--file-type", metavar="TYPE", choices=["DLL", "EXE"], default="DLL",
        help="文件类型：DLL (默认) 或 EXE",
    )
    p.add_argument(
        "-d", "--drop-file", metavar="NAME",
        help="目标上放置的文件名 (仅 EXE 类型有效)",
    )
    p.add_argument(
        "-D", "--drop-only", action="store_true",
        help="仅放置，不启动植入 (DropOnly)",
    )
    p.add_argument(
        "-t", "--thread-option", metavar="OPT", choices=["Multi", "Single"], default="Multi",
        help="线程选项：Multi (默认) 或 Single",
    )
    p.add_argument(
        "-f", "--function-ordinal", type=int, default=13, metavar="NUM",
        help="函数序数 (默认 13)",
    )
    p.add_argument(
        "-I", "--ip-address", metavar="IP",
        help="IP 地址 (仅函数序数 15 有效)",
    )
    p.add_argument(
        "-P", "--port", type=int, metavar="PORT",
        help="端口 (仅函数序数 15 有效)",
    )
    p.add_argument(
        "-a", "--function-argument", type=int, default=3, metavar="NUM",
        help="函数参数 (默认 3)",
    )
    p.add_argument(
        "-l", "--load-option", metavar="OPT", choices=["Memory", "Disk"], default="Disk",
        help="加载选项：Memory 或 Disk (默认 Disk)",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="启用详细输出",
    )
    p.set_defaults(func=ridearea2_handle)
