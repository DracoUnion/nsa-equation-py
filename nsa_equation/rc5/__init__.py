#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rc5 — RC5 加密/解密工具。

Python 重写的 `rc5.exe` (C++)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/ST1.14/Tools/rc5.exe`。

该工具用于 RC5 加密/解密，使用 KERNEL32 (大量文件/内存操作)、USER32 (MessageBoxW)、
MSVCRT (标准 C 运行时)。

CLI:

  rc5 <d|e> <session_key> <ciphertext>

Arguments:
  d|e         解密/加密模式 (d = decrypt, e = encrypt)
  session_key 会话密钥（十六进制字符串）
  ciphertext  密文（十六进制字符串）
"""

from . import rc5_exp


def rc5_handle(args):
    """Run the rc5 tool."""
    return rc5_exp.run_function(
        mode=args.mode,
        session_key=args.session_key,
        ciphertext=args.ciphertext,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `rc5` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "rc5",
        help="RC5 加密/解密工具",
        description="RC5 — 加密/解密工具。使用 KERNEL32 (大量文件/内存操作)、"
                    "USER32 (MessageBoxW)、MSVCRT (标准 C 运行时) 进行 RC5 "
                    "加密/解密。",
    )
    p.add_argument(
        "mode", metavar="MODE", choices=["d", "e"],
        help="模式：d = 解密，e = 加密",
    )
    p.add_argument(
        "session_key", metavar="SESSION_KEY",
        help="会话密钥（十六进制字符串）",
    )
    p.add_argument(
        "ciphertext", metavar="CIPHERTEXT",
        help="密文（十六进制字符串）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="启用详细输出",
    )
    p.set_defaults(func=rc5_handle)
