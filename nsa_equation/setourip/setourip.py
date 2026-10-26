# -*- coding: utf-8 -*-
"""
setourip.py -- Python port of `SetOurIp.exe` (LegacyWindowsExploits/Resources/Tools).

Recovered via IDA Pro (re_project history) from `SetOurIp.exe`:

    main @ 0x401000:
        SetOurIP <input file> <output file> [IP address]
          -- argc must be 3 or 4.
        The current build no longer rewrites 127.0.0.1: it is a thin wrapper
        around CopyFileA(input, output, bFailIfExists=False) and prints
        "File copied (set of IP no longer done with this exe)".  The optional
        3rd argument (IP) is parsed but ignored by this build.
        The input path is trimmed to the last ':' (drive letter) boundary
        before copy.  On failure prints the Windows GetLastError value.
"""
import shutil
import sys


def run(input_file, output_file):
    """Copy input_file -> output_file (overwrite), mirroring CopyFileA()."""
    # original trims at last ':' in the source path (drive letter); harmless to keep
    idx = input_file.rfind(":")
    src = input_file[idx - 1:] if idx > 0 else input_file  # keep "C:..." style
    try:
        shutil.copyfile(src, output_file)
    except OSError as e:
        print("Copy of file %s to %s failed (%d)\r\n" % (src, output_file, getattr(e, "errno", 1)))
        return -1
    print("File copied (set of IP no longer done with this exe)\r\n")
    return 0


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        prog="setourip", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input_file", help="源文件（原版可带盘符路径）")
    ap.add_argument("output_file", help="输出文件")
    ap.add_argument("ip", nargs="?", default=None,
                    help="保留参数：旧版本用于把 127.0.0.1 替换为指定 IP，本构建忽略")
    args = ap.parse_args(argv)
    return run(args.input_file, args.output_file)


if __name__ == "__main__":
    sys.exit(main())
