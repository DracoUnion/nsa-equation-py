#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ds_parselogs — DSky/Darkskyline 抓包文件分片工具。

Python 重写自 `DS_ParseLogs.exe` (C++/MSVCRT)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/Darkskyline/DS_ParseLogs.exe`。

按标准 pcap 文件头 (`D4C3 B2A1` / v2.4 / snaplen 0xFFFF / net 1) 把输入
捕获文件切分为若干段，每段原样写出为 `<results_prefix>_%02d.pcap`。不做
XOR-0xE3 混淆也不做 AES 解密（那是 `ParseCapture.exe` 的职责）。

CLI:

  ds_parselogs <capture_file> <results_prefix>

  例如：ds_parselogs capture.bin out   -> out_01.pcap, out_02.pcap, ...
"""

from . import ds_parselogs_exp


def ds_parselogs_handle(args):
    """Run the ds_parselogs tool."""
    return ds_parselogs_exp.run_function(
        capture_file=args.capture_file,
        results_prefix=args.results_prefix,
    )


def reg_subparser(subparsers):
    """Register the `ds_parselogs` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "ds_parselogs",
        help="DSky/Darkskyline 抓包文件分片工具",
        description="ds_parselogs — DSky/Darkskyline capture 文件分片器。按标准 "
                    "pcap 文件头把输入文件切片，每段原样写出为 "
                    "<results_prefix>_%%02d.pcap；不做 XOR-0xE3 混淆或 AES 解密。",
    )
    p.add_argument(
        "capture_file", metavar="CAPTURE_FILE",
        help="输入的 capture 文件路径",
    )
    p.add_argument(
        "results_prefix", metavar="RESULTS_PREFIX",
        help="输出文件名前缀（将生成 <前缀>_%%02d.pcap）",
    )
    p.set_defaults(func=ds_parselogs_handle)
