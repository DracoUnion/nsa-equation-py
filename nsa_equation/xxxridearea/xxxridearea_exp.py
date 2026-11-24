#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
xxxridearea — RideArea 文件处理工具（单段/多段模式）。

Python 重写自 `xxxRIDEAREA.exe` (C++/MSVCRT)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/Resources/Tools/xxxRIDEAREA.exe`。

原工具支持“single”和“multi”两种模式，对文件进行压缩/分段处理，使用
临时文件和多线程。

CLI:

  xxxridearea <mode> <input_file> [output_file]

  mode        - single：单段处理；multi：多段分段处理
  input_file  - 输入文件路径
  output_file - 可选，输出文件路径（默认在输入文件同目录生成）
"""

import os
import sys
import zlib
import tempfile


def _compress(data):
    return zlib.compress(data)


def _split(data, chunk_size=4096):
    return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]


def run_function(mode, input_file, output_file=None):
    """核心入口。"""
    mode = mode.lower()
    if mode not in ("single", "multi"):
        prog = os.path.basename(sys.argv[0] or "xxxridearea")
        print('Usage: %s <single|multi> <input_file> [output_file]' % prog)
        return 1

    if not os.path.exists(input_file):
        print("Unable to open input file %s" % input_file)
        return 1

    try:
        with open(input_file, "rb") as f:
            data = f.read()
    except OSError:
        print("Unable to read input file %s" % input_file)
        return 1

    if output_file is None:
        base = os.path.splitext(input_file)[0]
        output_file = base + (".single" if mode == "single" else ".multi")

    try:
        if mode == "single":
            out_data = _compress(data)
        else:
            chunks = _split(data)
            out_data = b"".join(_compress(c) for c in chunks)

        with open(output_file, "wb") as f:
            f.write(out_data)
    except OSError as e:
        print("Compression failed! %s" % e)
        return 1

    print("Processed %s -> %s (%d bytes -> %d bytes, mode=%s)" % (
        input_file, output_file, len(data), len(out_data), mode))
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if len(argv) < 2 or len(argv) > 3:
        prog = os.path.basename(sys.argv[0] or "xxxridearea")
        print('Usage: %s <single|multi> <input_file> [output_file]' % prog)
        return 1
    mode = argv[0]
    input_file = argv[1]
    output_file = argv[2] if len(argv) > 2 else None
    return run_function(mode, input_file, output_file)


if __name__ == "__main__":
    sys.exit(main())