#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
xxxridearea — RideArea 文件处理工具（单段/多段模式）。

Python 重写自 `xxxRIDEAREA.exe` (C++/MSVCRT)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/Resources/Tools/xxxRIDEAREA.exe`。

支持 single/multi 两种模式的文件压缩/分段处理。
"""

from . import xxxridearea_exp


def xxxridearea_handle(args):
    """Run the xxxridearea tool."""
    return xxxridearea_exp.run_function(
        mode=args.mode,
        input_file=args.input_file,
        output_file=args.output_file,
    )


def reg_subparser(subparsers):
    """Register the `xxxridearea` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "xxxridearea",
        help="RideArea 文件处理工具（单段/多段模式）",
        description="xxxridearea — RideArea 文件处理工具。支持 single/multi 两种模式，"
                    "对输入文件进行压缩/分段处理。",
    )
    p.add_argument(
        "mode", metavar="MODE", choices=["single", "multi"],
        help="处理模式：single=单段，multi=多段",
    )
    p.add_argument(
        "input_file", metavar="INPUT_FILE",
        help="输入文件路径",
    )
    p.add_argument(
        "output_file", metavar="OUTPUT_FILE", nargs="?", default=None,
        help="输出文件路径（可选）",
    )
    p.set_defaults(func=xxxridearea_handle)
