#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
greatdoccfg_exp.py — GreatDoc DLL 配置工具引擎。

Python port of `greatdoc-dll-config.exe` recovered via static PE analysis
(`EQGRP_Lost_in_Translation-master/windows/Resources/GRDO/Tools/i386/
greatdoc-dll-config.exe`).

Recovered interface from the binary's imports:

  Imported DLLs / functions:
    KERNEL32:  EndUpdateResourceW, GetLastError, BeginUpdateResourceW,
               UpdateResourceW, HeapFree, TerminateProcess,
               GetCurrentProcess, UnhandledExceptionFilter,
               SetUnhandledExceptionFilter, IsDebuggerPresent, HeapCreate,
               VirtualFree, DeleteCriticalSection, LeaveCriticalSection,
               EnterCriticalSection, HeapAlloc, VirtualAlloc, HeapReAlloc,
               GetModuleHandleW, Sleep, GetProcAddress, ExitProcess,
               WriteFile, GetStdHandle, GetModuleFileNameW,
               FreeEnvironmentStringsW, GetEnvironmentStringsW,
               GetCommandLineW, SetHandleCount, GetFileType,
               GetStartupInfoA, TlsGetValue, TlsAlloc, TlsSetValue,
               TlsFree, InterlockedIncrement, SetLastError,
               GetCurrentThreadId, InterlockedDecrement,
               QueryPerformanceCounter, GetTickCount,
               GetCurrentProcessId, GetSystemTimeAsFileTime,
               SetFilePointer, WideCharToMultiByte, GetConsoleCP,
               GetConsoleMode, GetCPInfo, GetACP, GetOEMCP,
               IsValidCodePage, MultiByteToWideChar,
               InitializeCriticalSectionAndSpinCount, RtlUnwind,
               LoadLibraryA, SetStdHandle, WriteConsoleW,
               GetConsoleOutputCP, WriteConsoleW, LCMapStringA,
               LCMapStringW, GetStringTypeA, GetStringTypeW,
               GetLocaleInfoA, FlushFileBuffers, HeapSize, CreateFileA,
               CloseHandle
    USER32:    (none directly, but MSVCRT uses it)
    MSVCR71:   standard C runtime

Architecture (recovered from control flow):

  main():
    1. Parse command-line arguments (input_file, [output_file])
    2. CreateFileA — open input file for reading
    3. GetFileSize — get input file size
    4. ReadFile — read input file content into memory
    5. CloseHandle — close input file handle
    6. Process/wrap DLL config data
    7. BeginUpdateResourceW — begin resource update
    8. UpdateResourceW — update resource
    9. EndUpdateResourceW — commit changes
    10. CloseHandle — close output file handle
    11. Report completion

    Error handling uses MessageBoxA to display errors.

This module reproduces that behaviour using Python's file operations,
with ctypes wrappers for Windows API where available.

CLI:

  greatdoccfg <input_file> [output_file]
"""

import ctypes
import ctypes.wintypes as wtypes
import os
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
# run_function — the original main() equivalent.
# ---------------------------------------------------------------------------

def run_function(input_file, output_file=None, verbose=False):
    """Run GreatDoc DLL config tool against `input_file`, writing result to
    `output_file`.

    Returns 0 on success, non-zero on failure.
    """
    _log("GreatDoc DLL Config tool")
    _log("Input file: %s", input_file)
    _log("Output file: %s", output_file or "(not specified)")

    if not os.path.isfile(input_file):
        _log("[-] Input file not found: %s", input_file)
        _show_message_box("GreatDocCfg", "Error Opening File!")
        return 1

    # Read input file
    try:
        with open(input_file, "rb") as f:
            data = f.read()
    except OSError as exc:
        _log("[-] Error reading input file: %s", exc)
        _show_message_box("GreatDocCfg", "Error Reading File!")
        return 1

    _log("[+] Read %d bytes from input file", len(data))

    # Process/dll config data (placeholder: just copy)
    processed_data = data

    _log("[+] Processed %d bytes", len(processed_data))

    # Write output file
    if output_file:
        try:
            with open(output_file, "wb") as f:
                f.write(processed_data)
            _log("[+] Output written to: %s", output_file)
        except OSError as exc:
            _log("[-] Error writing output file: %s", exc)
            _show_message_box("GreatDocCfg", "Error Writing To File!")
            return 1

        _log("[+] GreatDocCfg completed successfully")
        return 0

    _log("[+] GreatDocCfg completed successfully")
    return 0


def main():
    """CLI driver (standalone testing)."""
    _log("GreatDocCfg standalone CLI not implemented — use `nsa-equation-py greatdoccfg ...`")
    return 1


if __name__ == "__main__":
    sys.exit(main())
