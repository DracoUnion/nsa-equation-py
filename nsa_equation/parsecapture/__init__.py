#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
parsecapture — DSky 抓包文件解析 / 解密工具。

Python 重写自 `ParseCapture.exe` (C++, MSVCRT)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/DSky/Tools/i386-winnt/ParseCapture.exe`。

读取 DSky/Darkskyline 的 capture 文件（内部为段式结构，每段以三种“日志类型”
头部之一开始），逐段提取为 `capture_%02u.pcap`。三种类型：

  type 0  — 明文 pcap 头，原样拷贝
  type 1  — pcap 头 XOR 0xE3 混淆，全段 XOR-0xE3 还原
  type 2  — 加密段；头 XOR-0xE3 + magic 归一化，记录体按 16B 块 AES-128-ECB 解密
            （key 为空格分隔的 16 字节十六进制）

CLI:

  parsecapture <capture_file> <results_dir> [encryption_key]

  encryption_key  - 可选，e.g. "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff"
"""

from . import parsecapture_exp


def parsecapture_handle(args):
    """Run the parsecapture tool."""
    return parsecapture_exp.run_function(
        capture_file=args.capture_file,
        results_dir=args.results_dir,
        encryption_key=args.encryption_key,
    )


def reg_subparser(subparsers):
    """Register the `parsecapture` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "parsecapture",
        help="DSky 抓包文件解析 / 解密工具",
        description="parsecapture — DSky/Darkskyline capture 文件解析器。"
                    "支持 type 0/1/2 三种日志头部；type 2 段按 AES-128-ECB "
                    "解密（需要 16 字节 key）。",
    )
    p.add_argument(
        "capture_file", metavar="CAPTURE_FILE",
        help="输入的 capture 文件路径",
    )
    p.add_argument(
        "results_dir", metavar="RESULTS_DIR",
        help="输出目录（capture_%%02u.pcap 将写入此处）",
    )
    p.add_argument(
        "encryption_key", metavar="ENCRYPTION_KEY", nargs="?", default=None,
        help='可选加密密钥，空格分隔的 16 字节十六进制，'
             'e.g. "00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff"',
    )
    p.set_defaults(func=parsecapture_handle)