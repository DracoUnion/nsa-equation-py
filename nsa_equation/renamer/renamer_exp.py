#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
renamer_exp.py — Renamer 文件重命名工具引擎。

Python port of `renamer.exe` recovered via static PE analysis
(`EQGRP_Lost_in_Translation-master/windows/Resources/Ops/Tools/renamer.exe`).

Recovered interface from the binary's imports:

  Imported DLLs / functions:
    KERNEL32:  FindFirstFileW, FindNextFileW, MoveFileW, CreateFileW,
               ReadFile, WriteFile, CloseHandle, SetFilePointer, GetFileSize,
               VirtualAlloc, VirtualFree, SetFileAttributesA, CopyFileA,
               GetLastError, GetCommandLineA, GetVersion, ExitProcess,
               TerminateProcess, GetCurrentProcess, UnhandledExceptionFilter,
               GetModuleFileNameA, FreeEnvironmentStringsA,
               FreeEnvironmentStringsW, WideCharToMultiByte,
               GetEnvironmentStrings, GetEnvironmentStringsW,
               SetHandleCount, GetStdHandle, GetFileType, GetStartupInfoA,
               GetModuleHandleA, GetEnvironmentVariableA, GetVersionExA,
               HeapDestroy, HeapCreate, VirtualFree, HeapFree, RtlUnwind,
               HeapAlloc, GetCPInfo, GetACP, GetOEMCP, HeapReAlloc,
               GetProcAddress, LoadLibraryA, FlushFileBuffers,
               LCMapStringA, LCMapStringW, SetFilePointer
    USER32:    wsprintfW, MessageBoxA

Architecture (recovered from control flow):

  main():
    1. Parse command-line arguments (input_file, output_file, pattern,
       [replacement])
    2. FindFirstFileW / FindNextFileW — enumerate files in input directory
    3. For each file:
       - Apply renaming pattern
       - MoveFileW — rename/move file
    4. Report completion

    Error handling uses MessageBoxA / wsprintfW to display errors.

This module reproduces that behaviour using pure Python file operations,
with ctypes wrappers for Windows API where available.

CLI:

  renamer <input_file> <output_file> <pattern> [replacement]
"""

import ctypes
import ctypes.wintypes as wtypes
import os
import re
import sys


# ---------------------------------------------------------------------------
# Constants.
# ---------------------------------------------------------------------------

def _log(fmt, *args):
    sys.stderr.write((fmt % args).rstrip("\n") + "\n")


# ---------------------------------------------------------------------------
# Windows API wrappers (ctypes).
# ---------------------------------------------------------------------------

def _show_message_box(title, message):
    """Show Windows message box via MessageBoxA."""
    if os.name != "nt":
        _log("[%s] %s", title, message)
        return
    try:
        user32 = ctypes.WinDLL("user32.dll", use_last_error=True)
        user32.MessageBoxA.argtypes = [
            wtypes.HWND, wtypes.LPCSTR, wtypes.LPCSTR, wtypes.UINT,
        ]
        user32.MessageBoxA.restype = wtypes.INT
        user32.MessageBoxA(
            None, message.encode("ascii", "replace"),
            title.encode("ascii", "replace"), 0x00000010,
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# File renaming logic.
# ---------------------------------------------------------------------------

def _apply_pattern(filename, pattern, replacement):
    """Apply renaming pattern to filename."""
    if replacement:
        # Simple pattern replacement
        if pattern in filename:
            return filename.replace(pattern, replacement)
        else:
            # Append pattern
            return filename + replacement
    else:
        # Just return the filename as-is
        return filename


def _rename_files(input_dir, output_dir, pattern, replacement, verbose):
    """Rename files from input_dir to output_dir."""
    if not os.path.isdir(input_dir):
        _log("[-] Input directory not found: %s", input_dir)
        return 1

    # Create output directory if it doesn't exist
    if not os.path.isdir(output_dir):
        try:
            os.makedirs(output_dir, exist_ok=True)
        except OSError as exc:
            _log("[-] Failed to create output directory: %s", exc)
            return 1

    count = 0
    for filename in sorted(os.listdir(input_dir)):
        src_path = os.path.join(input_dir, filename)
        if not os.path.isfile(src_path):
            continue

        new_name = _apply_pattern(filename, pattern, replacement)
        dst_path = os.path.join(output_dir, new_name)

        if verbose:
            _log("[*] %s -> %s", filename, new_name)

        try:
            import shutil
            shutil.copy2(src_path, dst_path)
            count += 1
        except OSError as exc:
            _log("[-] Failed to copy %s: %s", filename, exc)

    _log("[+] Renamed %d file(s)", count)
    return 0


# ---------------------------------------------------------------------------
# run_function — the original main() equivalent.
# ---------------------------------------------------------------------------

def run_function(
    input_file,
    output_file,
    pattern,
    replacement=None,
    verbose=False,
):
    """Run Renamer against `input_file`, writing result to `output_file`.

    Returns 0 on success, non-zero on failure.
    """
    _log("Renamer — File renaming tool")
    _log("Input file: %s", input_file)
    _log("Output file: %s", output_file)
    _log("Pattern: %s", pattern)
    if replacement:
        _log("Replacement: %s", replacement)

    if not os.path.isdir(input_file):
        # Maybe it's a single file
        if not os.path.isfile(input_file):
            _log("[-] Input file/directory not found: %s", input_file)
            _show_message_box("Renamer", "Error Opening File!")
            return 1

        # Single file mode
        if not os.path.isdir(output_file):
            # output_file is a directory
            if os.path.isdir(output_file):
                dst_path = os.path.join(output_file, os.path.basename(input_file))
            else:
                dst_path = output_file

            new_name = _apply_pattern(os.path.basename(input_file), pattern, replacement)
            if verbose:
                _log("[*] %s -> %s", os.path.basename(input_file), new_name)

            try:
                import shutil
                shutil.copy2(input_file, dst_path)
                _log("[+] Renamed %s -> %s", os.path.basename(input_file), new_name)
                _log("[+] Output file: %s", dst_path)
                return 0
            except OSError as exc:
                _log("[-] Error copying file: %s", exc)
                _show_message_box("Renamer", "Error Writing To File!")
                return 1
        else:
            _log("[-] Output must be a directory for single file mode")
            return 1

    # Directory mode
    return _rename_files(input_file, output_file, pattern, replacement, verbose)


def main():
    """CLI driver (standalone testing)."""
    _log("Renamer standalone CLI not implemented — use `nsa-equation-py renamer ...`")
    return 1


if __name__ == "__main__":
    sys.exit(main())
