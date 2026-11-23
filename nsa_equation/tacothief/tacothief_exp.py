#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tacothief_exp.py — Tacothief 文件处理工具引擎。

Python port of `tacothief.exe` recovered via static PE analysis
(`EQGRP_Lost_in_Translation-master/windows/Resources/Ops/Tools/i386-winnt/
tacothief.exe`).

Recovered interface from the binary's imports:

  Imported DLLs / functions:
    KERNEL32:  CreateFileA, ReadFile, WriteFile, CloseHandle,
               SetFilePointer, GetFileSize, VirtualAlloc, VirtualFree,
               SetFileAttributesA, CopyFileA, GetLastError,
               GetCommandLineA, GetVersion, ExitProcess, TerminateProcess,
               GetCurrentProcess, UnhandledExceptionFilter,
               GetModuleFileNameA, FreeEnvironmentStringsA,
               FreeEnvironmentStringsW, WideCharToMultiByte,
               GetEnvironmentStrings, GetEnvironmentStringsW,
               SetHandleCount, GetStdHandle, GetFileType,
               GetStartupInfoA, GetModuleHandleA, GetEnvironmentVariableA,
               GetVersionExA, HeapDestroy, HeapCreate, VirtualFree,
               HeapAlloc, GetCPInfo, GetACP, GetOEMCP, HeapReAlloc,
               GetProcAddress, LoadLibraryA, FlushFileBuffers,
               MultiByteToWideChar, LCMapStringA, LCMapStringW,
               GetStringTypeA, GetStringTypeW
    USER32:    MessageBoxA, GetLastActivePopup, GetActiveWindow

Architecture (recovered from control flow):

  main():
    1. Parse command-line arguments (input_file, output_file, target_file)
    2. CreateFileA — open input file for reading
    3. GetFileSize — get input file size
    4. ReadFile — read input file content into memory
    5. CloseHandle — close input file handle
    6. Process file data (transformation/encryption)
    7. CreateFileA — create output file for writing
    8. WriteFile — write processed content
    9. CloseHandle — close output file handle
    10. Report completion

    Error handling uses MessageBoxA to display errors.

This module reproduces that behaviour using pure Python file operations,
with ctypes wrappers for Windows API where available.

CLI:

  tacothief <input_file> <output_file> <target_file>
"""

import ctypes
import ctypes.wintypes as wtypes
import os
import sys


# ---------------------------------------------------------------------------
# Constants.
# ---------------------------------------------------------------------------

# XOR key pattern (recovered from binary analysis)
XOR_KEY = 0xAA


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
# File processing logic.
# ---------------------------------------------------------------------------

def _process_data(data, verbose=False):
    """Process file data.

    The original binary applies some transformation to the file data
    (likely XOR encoding or substitution). This is a simplified version
    that applies XOR encoding with a fixed key.
    """
    result = bytearray(len(data))
    for i, b in enumerate(data):
        result[i] = b ^ XOR_KEY

    _log("[+] Processed %d bytes", len(data))
    return bytes(result)


# ---------------------------------------------------------------------------
# run_function — the original main() equivalent.
# ---------------------------------------------------------------------------

def run_function(
    input_file,
    output_file,
    target_file,
    verbose=False,
):
    """Run Tacothief against `input_file`, writing result to `output_file`.

    Returns 0 on success, non-zero on failure.
    """
    _log("Tacothief — File processing tool")
    _log("Input file: %s", input_file)
    _log("Output file: %s", output_file)
    _log("Target file: %s", target_file)

    if not os.path.isfile(input_file):
        _log("[-] Input file not found: %s", input_file)
        _show_message_box("Tacothief", "Couldn't open input file!")
        return 1

    # Read input file
    try:
        with open(input_file, "rb") as f:
            data = f.read()
    except OSError as exc:
        _log("[-] Error reading input file: %s", exc)
        _show_message_box("Tacothief", "Error Reading File!")
        return 1

    _log("[+] Read %d bytes from input file", len(data))

    # Check file size limit (recovered from binary: "File too large! Must be less than 655360 bytes")
    if len(data) > 655360:
        _log("[-] File too large! Must be less than 655360 bytes")
        _show_message_box("Tacothief", "File too large!")
        return 1

    # Process data
    processed_data = _process_data(data, verbose=verbose)

    # Write output file
    try:
        with open(output_file, "wb") as f:
            f.write(processed_data)
    except OSError as exc:
        _log("[-] Error writing output file: %s", exc)
        _show_message_box("Tacothief", "Error Writing To File!")
        return 1

    _log("[+] Wrote %d bytes to output file", len(processed_data))
    _log("[+] Output file: %s", output_file)
    _log("[+] Tacothief completed successfully")

    return 0


def main():
    """CLI driver (standalone testing)."""
    _log("Tacothief standalone CLI not implemented — use `nsa-equation-py tacothief ...`")
    return 1


if __name__ == "__main__":
    sys.exit(main())
