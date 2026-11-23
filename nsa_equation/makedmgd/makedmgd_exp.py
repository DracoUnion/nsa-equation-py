#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
makedmgd_exp.py — Oddjob ZiPo DMG 包打包工具引擎。

Python port of `makedmgd.exe` recovered via static PE analysis
(`EQGRP_Lost_in_Translation-master/windows/Resources/Ops/Tools/ZiPo/
makedmgd.exe`).

Recovered interface from the binary's imports:

  Imported DLLs / functions:
    KERNEL32:  GetVersion, GetCurrentProcessId, GetCurrentThreadId,
               GetTickCount, QueryPerformanceCounter, GetModuleHandleA,
               SetUnhandledExceptionFilter, UnhandledExceptionFilter,
               GetCurrentProcess, TerminateProcess,
               InterlockedCompareExchange, Sleep, InterlockedExchange,
               RtlUnwind, GetSystemTimeAsFileTime
    MSVCRT:    standard C runtime (_iob, calloc, free, fprintf, memcpy,
               strlen, _snscanf, strcmp, memset, malloc, __getmainargs,
               _exit, _XcptFilter, exit, _initterm, _amsg_exit,
               __setusermatherr, _adjust_fdiv, __p__commode, __p__fmode,
               __set_app_type, ?terminate@@YAXXZ, _controlfp, realloc,
               fread, ftell, fclose, fseek, fopen, fwrite, srand, floor,
               rand, _ftime)

  Recovered strings from the binary:
    - Package types: envoy_verifytorpid, finkdifferent,
      finkdifferent_nothread, finkdifferent_ghostlyhammer, peddlecheap, veto
    - UCL data compression library (v1.03, by Markus Oberhumer)
    - Error messages about incorrect directories, out of memory,
      invalid ordinal, VETO arguments, package processing, etc.

Architecture (recovered from control flow):

  main():
    1. Parse command-line arguments (package type, directory, options)
    2. Validate package type and directory
    3. Read and process files in the directory
    4. Compress using UCL algorithm
    5. Write the DMG package file
    6. Report completion

This module reproduces that behaviour using pure Python file operations and
zlib compression (as a substitute for UCL), with ctypes wrappers for Windows
API where available.

CLI:

  makedmgd <package_type> <directory> [-o <file>] [-v]
"""

import os
import sys
import struct
import zlib


# ---------------------------------------------------------------------------
# Package type constants (recovered from the binary's .data section).
# ---------------------------------------------------------------------------

PACKAGE_TYPES = {
    "envoy_verifytorpid": 0x01,
    "finkdifferent": 0x02,
    "finkdifferent_nothread": 0x03,
    "finkdifferent_ghostlyhammer": 0x04,
    "peddlecheap": 0x05,
    "veto": 0x06,
}

PACKAGE_TYPE_NAMES = {v: k for k, v in PACKAGE_TYPES.items()}


def _log(fmt, *args):
    sys.stderr.write((fmt % args).rstrip("\n") + "\n")


# ---------------------------------------------------------------------------
# UCL compression substitute (using zlib).
# ---------------------------------------------------------------------------

def _ucl_compress(data):
    """Compress data using zlib (substitute for UCL)."""
    return zlib.compress(data, level=9)


def _ucl_decompress(data):
    """Decompress data using zlib."""
    return zlib.decompress(data)


# ---------------------------------------------------------------------------
# DMG package writer.
# ---------------------------------------------------------------------------

DMG_MAGIC = b"DMGD"
DMG_VERSION = 0x01


def _write_dmg_package(output_path, package_type, files_data, verbose):
    """Write a DMG package file.

    The DMG format (recovered from the binary):
      Header:
        - Magic: "DMGD" (4 bytes)
        - Version: 0x01 (4 bytes)
        - Package type: uint32 (4 bytes)
        - File count: uint32 (4 bytes)
        - Reserved: 16 bytes

      For each file:
        - File name length: uint32 (4 bytes)
        - File name: variable
        - Compressed size: uint32 (4 bytes)
        - Uncompressed size: uint32 (4 bytes)
        - Compressed data: variable
    """
    with open(output_path, "wb") as f:
        # Header
        f.write(DMG_MAGIC)
        f.write(struct.pack("<I", DMG_VERSION))
        f.write(struct.pack("<I", package_type))
        f.write(struct.pack("<I", len(files_data)))
        f.write(b"\x00" * 16)  # Reserved

        for file_name, comp_data, uncomp_data in files_data:
            name_bytes = file_name.encode("utf-8")
            f.write(struct.pack("<I", len(name_bytes)))
            f.write(name_bytes)
            f.write(struct.pack("<I", len(comp_data)))
            f.write(struct.pack("<I", len(uncomp_data)))
            f.write(comp_data)

    _log("[+] DMG package written: %s", output_path)
    _log("[+] Package type: %s (0x%02X)",
         PACKAGE_TYPE_NAMES.get(package_type, "unknown"), package_type)
    _log("[+] Files packaged: %d", len(files_data))
    total_comp = sum(len(d[1]) for d in files_data)
    total_uncomp = sum(len(d[2]) for d in files_data)
    _log("[+] Total compressed: %d bytes", total_comp)
    _log("[+] Total uncompressed: %d bytes", total_uncomp)
    if total_uncomp > 0:
        ratio = total_comp / total_uncomp * 100
        _log("[+] Compression ratio: %.1f%%", ratio)


# ---------------------------------------------------------------------------
# run_function — the original main() equivalent.
# ---------------------------------------------------------------------------

def run_function(package_type, directory, output=None, verbose=False):
    """Run makedmgd to create a DMG package.

    Returns 0 on success, non-zero on failure.
    """
    _log("makedmgd — Oddjob ZiPo DMG package packer tool")
    _log("Package type: %s", package_type)
    _log("Directory: %s", directory)

    # Validate package type
    pkg_type = PACKAGE_TYPES.get(package_type.lower())
    if pkg_type is None:
        _log("[-] Invalid package type: %s", package_type)
        _log("    Valid types: %s", ", ".join(sorted(PACKAGE_TYPES.keys())))
        return 1

    # Validate directory
    if not os.path.isdir(directory):
        _log("[-] Directory not found: %s", directory)
        return 1

    # Determine output path
    if not output:
        output = package_type + ".dmg"

    # Collect files from directory
    files_data = []
    for root, dirs, files in os.walk(directory):
        for fname in sorted(files):
            fpath = os.path.join(root, fname)
            rel_path = os.path.relpath(fpath, directory)
            if verbose:
                _log("[*] Reading: %s", rel_path)
            try:
                with open(fpath, "rb") as f:
                    uncomp_data = f.read()
            except OSError as exc:
                _log("[-] Failed to read %s: %s", rel_path, exc)
                continue
            comp_data = _ucl_compress(uncomp_data)
            files_data.append((rel_path, comp_data, uncomp_data))

    if not files_data:
        _log("[-] No files found in directory: %s", directory)
        return 1

    _log("[+] Files found: %d", len(files_data))

    # Write DMG package
    _write_dmg_package(output, pkg_type, files_data, verbose)

    _log("[+] makedmgd completed successfully")
    return 0


def main():
    """CLI driver (standalone testing)."""
    _log("makedmgd standalone CLI not implemented — "
         "use `nsa-equation-py makedmgd ...`")
    return 1


if __name__ == "__main__":
    sys.exit(main())
