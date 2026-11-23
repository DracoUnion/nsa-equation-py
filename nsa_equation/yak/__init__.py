#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
yak — Yak 键盘监听/归档工具。

Python 重写的 `yak.exe` (C++)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/Ops/Tools/i386-winnt/
yak2/yak.exe`。

该工具用于监听键盘输入、归档扫描码，支持服务创建、注册表操作、
键盘布局转换等。
通过静态 PE 分析恢复，其导入的关键函数包括：
  - KERNEL32: 文件操作 (CreateFileA, ReadFile, WriteFile, CloseHandle,
              SetFilePointer, GetFileSize, VirtualAlloc, VirtualFree),
              服务管理 (CreateServiceA, OpenSCManagerA, CloseServiceHandle),
              注册表操作 (RegQueryInfoKeyA, RegEnumKeyExA, RegCloseKey,
              RegSetValueExA, RegCreateKeyA, RegOpenKeyExA, RegDeleteKeyA,
              RegSetKeySecurity),
              设备控制 (DeviceIoControl, DefineDosDeviceA)
  - ADVAPI32: OpenProcessToken, LookupPrivilegeValueA, AdjustTokenPrivileges,
              InitializeSecurityDescriptor, SetSecurityDescriptorDacl
  - USER32:   ToUnicodeEx, MapVirtualKeyExW, LoadKeyboardLayoutA,
              ToAsciiEx, GetKeyNameTextA, LoadKeyboardLayoutW,
              GetKeyNameTextW, MapVirtualKeyExA (键盘布局)
  - MSVCR71/MSVCP71: 标准 C++ 运行时

CLI:

  yak <archive_file> [options]

Options:
  -d           Dump archive file in raw form
  -dp          Same as -d but break out data by packet boundaries
  -t           Convert scancodes in the archive file
  -ta          Translate archive
  -tau         Same as -ta but use unicode format
  -xt          Convert scancodes and store in keys.txt
  -xta         Same as -xt but show special chars & store in keys_all.txt
  -xtu         Same as -xt but use unicode format
  -s size      Size to make archive file
  -f           Filter special chars
  -w           Wrap archive file
  -lh          List language options
  -l language  Language used during archive translation
"""

from . import yak_exp


def yak_handle(args):
    """Run the yak tool."""
    return yak_exp.run_function(
        archive_file=args.archive_file,
        dump=args.dump,
        dump_packet=args.dump_packet,
        convert=args.convert,
        translate=args.translate,
        translate_unicode=args.translate_unicode,
        convert_scancodes=args.convert_scancodes,
        convert_scancodes_unicode=args.convert_scancodes_unicode,
        convert_scancodes_archive=args.convert_scancodes_archive,
        archive_size=args.archive_size,
        filter_special=args.filter_special,
        wrap_archive=args.wrap_archive,
        list_languages=args.list_languages,
        language=args.language,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `yak` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "yak",
        help="Yak 键盘监听/归档工具",
        description="Yak — 键盘监听/归档工具。使用 WS2_32 网络、KERNEL32"
                    "文件和服务操作、ADVAPI32 服务和注册表操作、USER32"
                    "键盘布局操作。支持键盘扫描码归档、转换和导出。",
    )
    p.add_argument(
        "archive_file", metavar="ARCHIVE_FILE",
        help="归档文件路径",
    )
    p.add_argument(
        "-d", "--dump", action="store_true",
        help="Dump archive file in raw form",
    )
    p.add_argument(
        "-dp", "--dump-packet", action="store_true",
        help="Same as -d but break out data by packet boundaries",
    )
    p.add_argument(
        "-t", "--convert", action="store_true",
        help="Convert scancodes in the archive file",
    )
    p.add_argument(
        "-ta", "--translate", action="store_true",
        help="Translate archive",
    )
    p.add_argument(
        "-tau", "--translate-unicode", action="store_true",
        help="Same as -ta but use unicode format",
    )
    p.add_argument(
        "-xt", "--convert-scancodes", action="store_true",
        help="Convert scancodes and store in keys.txt",
    )
    p.add_argument(
        "-xta", "--convert-scancodes-archive", action="store_true",
        help="Same as -xt but show special chars & store in keys_all.txt",
    )
    p.add_argument(
        "-xtu", "--convert-scancodes-unicode", action="store_true",
        help="Same as -xt but use unicode format",
    )
    p.add_argument(
        "-s", "--archive-size", metavar="SIZE",
        help="Size to make archive file",
    )
    p.add_argument(
        "-f", "--filter-special", action="store_true",
        help="Filter special chars",
    )
    p.add_argument(
        "-w", "--wrap-archive", action="store_true",
        help="Wrap archive file",
    )
    p.add_argument(
        "-lh", "--list-languages", action="store_true",
        help="List language options",
    )
    p.add_argument(
        "-l", "--language", metavar="LANGUAGE",
        help="Language used during archive translation",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="启用详细输出",
    )
    p.set_defaults(func=yak_handle)
