#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
doublefeaturereader — DoubleFeature 隐蔽容器读取工具。

Python 重写自 `DoubleFeatureReader.exe` (C++/MSVCRT)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/Df/Tools/i386-winnt/DoubleFeatureReader.exe`。

读取 DoubleFeature / CritterFrenzy 隐蔽存储容器文件，解析并打印其中的
字段（CFStore、CFContent、CFBytesFree、字体、系统信息等）。

CLI:

  doublefeaturereader <container_file>

示例:

  doublefeaturereader store.bin
"""

import os
import sys
import re


def run_function(container_file):
    """核心入口。"""
    if not os.path.exists(container_file):
        print("Unable to open input file %s" % container_file)
        return 1

    try:
        with open(container_file, "rb") as f:
            data = f.read()
    except OSError:
        print("Unable to read input file %s" % container_file)
        return 1

    if not data:
        print("Capture file is zero size -- unable to parse")
        return 1

    print("DoubleFeatureReader")
    print("=" * 40)
    print("File: %s" % container_file)
    print("Size: %d bytes" % len(data))
    print()

    # 提取可读的 ASCII 字符串（长度>=4），并把相关的字段名与值配对
    strings = []
    i = 0
    n = len(data)
    while i < n:
        if 0x20 <= data[i] < 0x7F:
            j = i
            while j < n and 0x20 <= data[j] < 0x7F:
                j += 1
            if j - i >= 4:
                s = data[i:j].decode("ascii", errors="replace")
                strings.append((i, s))
            i = j
        else:
            i += 1

    # 感兴趣的字段前缀（与原二进制字符串表对应）
    fields = (
        "CFVersion", "Version", "Type", "Name", "Store", "CFStore",
        "Covert Stores", "Size", "File", "CFContent", "Content",
        "CFBytesFree", "Free Space", "CFBytesUsed", "Size Of Store",
        "CFNumFiles", "Number Of Files", "CFCrashCount", "CFCrashId",
        "KillSuit ID", "CFCrash", "Crash Count", "Minor Error",
        "Major Error", "Minor Marker", "Major Marker", "Current Time",
        "Boot Time", "Start Configuration", "CFStart", "Reason",
        "SolarTime", "DiveBar", "DoctorOctopus", "JUVI",
        "Persistence Compatibility", "MultiLauncher",
    )

    printed = set()
    for off, s in strings:
        for field in fields:
            if s.startswith(field) and s not in printed:
                printed.add(s)
                rest = s[len(field):].strip()
                if rest:
                    print("%s: %s" % (field, rest))
                else:
                    print("%s" % field)

    print()
    print("End of DoubleFeatureReader output")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if len(argv) != 1:
        prog = os.path.basename(sys.argv[0] or "doublefeaturereader")
        print('Usage: %s <container_file>' % prog)
        return 1
    container_file = argv[0]
    return run_function(container_file)


if __name__ == "__main__":
    sys.exit(main())