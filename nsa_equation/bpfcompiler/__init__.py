#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bpfcompiler — BpfCompiler BPF 编译工具。

Python 重写的 `BpfCompiler.exe` (C++)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/DSky/Tools/i386-winnt/
BpfCompiler.exe`。

该工具用于编译 BPF (Berkeley Packet Filter) 过滤器，使用 libpcap/wpcap 库。
通过静态 PE 分析恢复，其导入的关键函数包括：
  - wpcap: pcap_open_dead, pcap_compile, pcap_geterr, pcap_close
  - WS2_32: inet_addr
  - KERNEL32: 文件和内存操作
  - MSVCR90: 标准 C 运行时

CLI:

  bpfcompiler <expression> [output_file]

Arguments:
  expression   BPF 过滤器表达式
  output_file  输出文件路径（可选）
"""

from . import bpfcompiler_exp


def bpfcompiler_handle(args):
    """Run the bpfcompiler tool."""
    return bpfcompiler_exp.run_function(
        expression=args.expression,
        output_file=args.output_file,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `bpfcompiler` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "bpfcompiler",
        help="BpfCompiler BPF 编译工具",
        description="BpfCompiler — BPF 编译工具。使用 wpcap 库编译 BPF"
                    "过滤器表达式。",
    )
    p.add_argument(
        "expression", metavar="EXPRESSION",
        help="BPF 过滤器表达式",
    )
    p.add_argument(
        "output_file", metavar="OUTPUT_FILE", nargs="?",
        help="输出文件路径（可选）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="启用详细输出",
    )
    p.set_defaults(func=bpfcompiler_handle)
