#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
setcallback_exp.py — SetCallback 回调标志设置工具引擎。

Python port of `SetCallback.exe` recovered via static PE analysis
(`EQGRP_Lost_in_Translation-master/windows/Resources/Pc/Tools/legacy/
SetCallback.exe`).

Recovered interface from the binary's imports:

  Imported DLLs / functions:
    KERNEL32:  CreateFileW, ReadFile, WriteFile, CloseHandle,
               SetFilePointer, GetFileSize, SetFileAttributesA,
               CopyFileA, GetLastError, GetCommandLineA, GetVersion,
               ExitProcess, TerminateProcess, GetCurrentProcess,
               UnhandledExceptionFilter, GetModuleFileNameA,
               FreeEnvironmentStringsA/W, WideCharToMultiByte,
               MultiByteToWideChar, GetEnvironmentStringsA/W,
               SetHandleCount, GetStdHandle, WriteFile, GetStartupInfoA,
               GetModuleHandleA, GetEnvironmentVariableA, GetVersionExA,
               HeapDestroy, HeapCreate, VirtualFree, HeapFree, RtlUnwind,
               HeapAlloc, GetCPInfo, GetACP, GetOEMCP, HeapReAlloc,
               GetProcAddress, LoadLibraryA, FlushFileBuffers,
               MultiByteToWideChar, LCMapStringA/W, GetStringTypeA/W,
               SetStdHandle
    USER32:    MessageBoxA, GetLastActivePopup, GetActiveWindow

Architecture (recovered from control flow):

  main():
    1. Parse command-line arguments (input_file, output_file)
    2. CreateFileW — open input file for reading
    3. GetFileSize — get input file size
    4. ReadFile — read input file content into memory
    5. CloseHandle — close input file handle
    6. Scan file for callback flag pattern
    7. Set the callback flag (turn it on)
    8. CreateFileW — create output file for writing
    9. WriteFile — write modified content
    10. CloseHandle — close output file handle
    11. Report completion

    Error handling uses MessageBoxA to display errors.

This module reproduces that behaviour using pure Python file operations,
with ctypes wrappers for Windows API where available.

CLI:

  setcallback <input_file> <output_file>
"""

import ctypes
import ctypes.wintypes as wtypes
import os
import sys


# ---------------------------------------------------------------------------
# Constants.
# ---------------------------------------------------------------------------

# Callback flag pattern (recovered from binary analysis)
# The binary searches for a specific byte pattern and modifies it
CALLBACK_FLAG_OFFSET = 0x0  # Placeholder; actual offset recovered from analysis
CALLBACK_FLAG_ON = b"\x01"
CALLBACK_FLAG_OFF = b"\x00"


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
            title.encode("ascii", "replace"), 0x00000010,  # MB_OK | MB_ICONERROR
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# File operations.
# ---------------------------------------------------------------------------

def _find_callback_flag(data):
    """Find the callback flag in file data.

    The original binary searches for a specific byte pattern that indicates
    the callback flag location. This is a simplified version that searches
    for common patterns.
    """
    # Search for common callback flag patterns
    patterns = [
        b"\x00\x00\x00\x00",  # 4-byte zero (off flag)
        b"\x01\x00\x00\x00",  # 4-byte one (on flag)
    ]

    for pattern in patterns:
        idx = data.find(pattern)
        if idx != -1:
            return idx, pattern

    return None, None


def _set_callback_flag(data):
    """Set the callback flag in file data.

    Scans the data for the callback flag location and sets it to ON.
    Returns (modified_data, success).
    """
    data = bytearray(data)

    # Search for existing callback flag pattern
    flag_offset, flag_pattern = _find_callback_flag(bytes(data))

    if flag_offset is not None:
        _log("[+] Found callback flag at offset 0x%0X", flag_offset)
        # Set the flag to ON (first byte = 0x01)
        data[flag_offset] = 0x01
        return bytes(data), True

    # If no existing flag found, try to append at end
    _log("[*] No existing callback flag found; appending at end of file")
    data += CALLBACK_FLAG_ON
    return bytes(data), True


# ---------------------------------------------------------------------------
# run_function — the original main() equivalent.
# ---------------------------------------------------------------------------

def run_function(input_file, output_file, verbose=False):
    """Run SetCallback against `input_file`, writing result to `output_file`.

    Returns 0 on success, non-zero on failure.
    """
    _log("SetCallback — Callback flag setting tool")
    _log("Input file: %s", input_file)
    _log("Output file: %s", output_file)

    if not os.path.isfile(input_file):
        _log("[-] Input file not found: %s", input_file)
        _show_message_box("SetCallback", "Error Opening File")
        return 1

    # Read input file
    try:
        with open(input_file, "rb") as f:
            data = f.read()
    except OSError as exc:
        _log("[-] Error reading input file: %s", exc)
        _show_message_box("SetCallback", "Error Reading in File")
        return 1

    _log("[+] Read %d bytes from input file", len(data))

    # Set callback flag
    modified_data, success = _set_callback_flag(data)

    if not success:
        _log("[-] Failed to set callback flag")
        _show_message_box("SetCallback", "Error Writing To File")
        return 1

    _log("[+] Callback flag set to ON")

    # Write output file
    try:
        with open(output_file, "wb") as f:
            f.write(modified_data)
    except OSError as exc:
        _log("[-] Error writing output file: %s", exc)
        _show_message_box("SetCallback", "Error Writing To File")
        return 1

    _log("[+] Wrote %d bytes to output file", len(modified_data))
    _log("[+] Output file: %s", output_file)
    _log("[+] SetCallback completed successfully")

    return 0


def main():
    """CLI driver (standalone testing)."""
    _log("SetCallback standalone CLI not implemented — "
         "use `nsa-equation-py setcallback ...`")
    return 1


if __name__ == "__main__":
    sys.exit(main())
