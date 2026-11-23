#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
genkey — GenKey RSA 密钥生成工具。

Python 重写的 `GenKey.exe` (C++，MSVCR90)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/Pc/Tools/i386-winnt/GenKey.exe`。

该工具用于生成 RSA 公钥/私钥对，并验证加密/解密功能。
通过静态 PE 分析恢复，其导入的关键函数包括：
  - KERNEL32: IsDebuggerPresent, CreateFileW, WriteFile, CloseHandle,
              GetTickCount, QueryPerformanceCounter, GetSystemTimeAsFileTime,
              GetDiskFreeSpaceExW, GlobalMemoryStatus, WideCharToMultiByte,
              MultiByteToWideChar, SetLastError, GetLastError, etc.
  - USER32:   GetCursorPos
  - MSVCR90:  标准 C 运行时 (malloc, free, printf, fprintf, strlen, wcslen,
              _vsnprintf, memset, atoi, etc.)

CLI:

  genkey <key_size> [dir]

Arguments:
  key_size   密钥长度：1024 或 2048
  dir        输出目录 (默认：当前目录)

The tool generates public_key.bin and private_key.bin files, then performs
a self-test (encrypt/decrypt round-trip) to verify the keys work correctly.
"""

from . import genkey_exp


def genkey_handle(args):
    """Run the GenKey tool."""
    return genkey_exp.run_function(
        key_size=args.key_size,
        output_dir=args.dir,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `genkey` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "genkey",
        help="GenKey RSA 密钥生成工具",
        description="GenKey — RSA 密钥生成工具。生成 1024/2048 位 RSA"
                    "公钥/私钥对，并进行自测验证。",
    )
    p.add_argument(
        "key_size", metavar="KEY_SIZE", type=int, choices=[1024, 2048],
        help="密钥长度：1024 或 2048",
    )
    p.add_argument(
        "dir", metavar="DIR", nargs="?", default=".",
        help="输出目录 (默认：当前目录)",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="启用详细输出",
    )
    p.set_defaults(func=genkey_handle)
