#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
doublefeaturereader — DoubleFeature 隐蔽容器读取工具。

Python 重写自 `DoubleFeatureReader.exe` (C++/MSVCRT)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/Df/Tools/i386-winnt/DoubleFeatureReader.exe`。

读取并转储 DoubleFeature/CritterFrenzy 隐蔽容器文件中的字段。
"""

from . import doublefeaturereader_exp


def doublefeaturereader_handle(args):
    """Run the doublefeaturereader tool."""
    return doublefeaturereader_exp.run_function(
        container_file=args.container_file,
    )


def reg_subparser(subparsers):
    """Register the `doublefeaturereader` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "doublefeaturereader",
        help="DoubleFeature 隐蔽容器读取工具",
        description="doublefeaturereader — 读取并转储 DoubleFeature/CritterFrenzy "
                    "隐蔽容器文件中的字段（CFStore、CFContent、字体、系统信息等）。",
    )
    p.add_argument(
        "container_file", metavar="CONTAINER_FILE",
        help="DoubleFeature 容器文件路径",
    )
    p.set_defaults(func=doublefeaturereader_handle)
