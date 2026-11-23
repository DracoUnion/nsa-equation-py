#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
epwrapper — EpWrapper 包装工具。

Python 重写的 `EpWrapper.exe` (C++)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/Ep/EpWrapper.exe`。

该工具用于包装 EP 文件，使用 WS2_32 socket、KERNEL32 文件/目录操作、
MSVCR71 标准 C 运行时。
通过静态 PE 分析恢复，其导入的关键函数包括：
  - WS2_32: WSAStartup, ioctlsocket, getsockname, getpeername, ntohs,
            send, recv, WSAGetLastError, WSASetLastError
  - KERNEL32: GetModuleHandleA, LoadLibraryW, GetProcAddress,
              CreateDirectoryW, SetCurrentDirectoryW, GetLastError,
              ExitProcess, FreeLibrary, Sleep, GetModuleFileNameW,
              WideCharToMultiByte, MultiByteToWideChar, CreateFileA,
              CloseHandle, GetFileType, GetEnvironmentVariableA,
              TerminateThread, ResumeThread, CloseHandle,
              SetCurrentDirectoryW, CreateProcessW, GetModuleFileNameW,
              ExitProcess, GetSystemTimeAsFileTime, SetUnhandledExceptionFilter
  - MSVCR71: 标准 C 运行时 (sprintf, wprintf, vwprintf, wcslen, _wfullpath,
              wcstoul, _except_handler3, _local_unwind2, _c_exit, _exit,
              _XcptFilter, _cexit, exit, __p___winitenv, _amsg_exit,
              __wgetmainargs, _initterm, _initterm_e, _configthreadlocale,
              __setusermatherr, _adjust_fdiv, __p__commode, __p__fmode,
              __set_app_type, ?terminate@@YAXXZ, __dllonexit, _onexit,
              _controlfp, sprintf, wprintf, vwprintf, wcslen, _wfullpath,
              wcstoul, malloc, strlen, free, wcscpy, strcpy, _vsnwprintf,
              malloc, strlen, free, _wtoi, memset, wcsncat, _snwprintf,
              wcslen, wcschr, vwprintf, vfwprintf, fclose, _beginthreadex,
              _iob, fflush, wscanf, swscanf, _except_handler3,
              ??_V@YAXPAX@Z, memmove, ??2@YAPAXI@Z, _CxxThrowException,
              ??0exception@@QAE@ABV0@@Z, ??3@YAXPAX@Z, __CxxFrameHandler,
              ??0exception@@QAE@XZ, ??1exception@@UAE@XZ, _wcsicmp,
              _vsnprintf, ??3@YAXPAX@Z, _except_handler3,
              _local_unwind2, _c_exit, _exit, _XcptFilter, _amsg_exit,
              __wgetmainargs, __initterm)

CLI:

  epwrapper <input_file> [output_file]

Arguments:
  input_file    输入文件路径
  output_file   输出文件路径（可选）
"""

from . import epwrapper_exp


def epwrapper_handle(args):
    """Run the EpWrapper tool."""
    return epwrapper_exp.run_function(
        input_file=args.input_file,
        output_file=args.output_file,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `epwrapper` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "epwrapper",
        help="EpWrapper 包装工具",
        description="EpWrapper — 包装工具。使用 WS2_32 socket、KERNEL32"
                    "文件/目录操作、MSVCR71 标准 C 运行时包装 EP 文件。",
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
    p.set_defaults(func=epwrapper_handle)
