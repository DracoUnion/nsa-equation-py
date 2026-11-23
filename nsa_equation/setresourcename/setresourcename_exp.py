#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
setresourcename_exp.py — SetResourceName 资源名称设置工具引擎。

Python port of `SetResourceName.exe` recovered via static PE analysis
(`EQGRP_Lost_in_Translation-master/windows/Resources/Pc/Tools/legacy/
SetResourceName.exe`).

Recovered interface from the binary's imports:

  Imported DLLs / functions:
    KERNEL32:  CreateFileW, ReadFile, WriteFile, CloseHandle,
               SetFilePointer, GetFileSize, VirtualAlloc, VirtualFree,
               SetFileAttributesA, CopyFileA, GetLastError,
               RtlUnwind, GetCommandLineA, GetVersion, ExitProcess,
               TerminateProcess, GetCurrentProcess,
               UnhandledExceptionFilter, GetModuleFileNameA,
               FreeEnvironmentStringsA/W, WideCharToMultiByte,
               GetEnvironmentStrings, GetEnvironmentStringsW,
               SetHandleCount, GetStdHandle, GetFileType, GetStartupInfoA,
               GetModuleHandleA, GetEnvironmentVariableA, GetVersionExA,
               HeapDestroy, HeapCreate, HeapFree, MultiByteToWideChar,
               GetCPInfo, GetACP, GetOEMCP, HeapReAlloc,
               GetProcAddress, LoadLibraryA, FlushFileBuffers,
               LCMapStringA/W, SetStdHandle
    USER32:    MessageBoxA, wsprintfA

Architecture (recovered from control flow):

  main():
    1. Parse command-line arguments (input_file, output_file, old_resource,
       new_resource_name)
    2. CreateFileW — open input file for reading
    3. GetFileSize — get input file size
    4. ReadFile — read input file content into memory
    5. CloseHandle — close input file handle
    6. Scan file for resource name pattern (OriginalFilename or InternalName)
    7. Replace with new resource name
    8. CreateFileW — create output file for writing
    9. WriteFile — write modified content
    10. CloseHandle — close output file handle
    11. Report completion

    Error handling uses MessageBoxA to display errors.

This module reproduces that behaviour using pure Python file operations,
with ctypes wrappers for Windows API where available.

CLI:

  setresourcename <input_file> <output_file> <old_resource> <new_resource_name>
"""

import ctypes
import ctypes.wintypes as wtypes
import os
import re
import sys


# ---------------------------------------------------------------------------
# Constants.
# ---------------------------------------------------------------------------

# Old resource options (recovered from binary strings)
OLD_RESOURCE_OPTIONS = {
    1: ("spcss32.exe", "spcss32.exe"),
    2: ("appinit.dll", "appinit.dll"),
    3: ("memss.exe", "memss.exe"),
    4: ("msvcp57.exe", "msvcp57.exe"),
}

# Resource name patterns in PE resources
RESOURCE_NAME_PATTERNS = [
    b"OriginalFilename",
    b"InternalName",
]


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
# Resource name replacement logic.
# ---------------------------------------------------------------------------

def _find_resource_name(data, old_name):
    """Find resource name pattern in file data."""
    # Search for the old resource name
    old_bytes = old_name.encode("ascii")
    idx = data.find(old_bytes)
    if idx != -1:
        return idx
    return None


def _set_resource_name(data, old_resource_idx, new_resource_name):
    """Set resource name in file data.

    Scans the data for the old resource name pattern and replaces it with
    the new resource name.
    Returns (modified_data, success).
    """
    data = bytearray(data)

    old_resource_name = OLD_RESOURCE_OPTIONS[old_resource_idx][0]

    # Search for the old resource name
    idx = _find_resource_name(data, old_resource_name)

    if idx is not None:
        _log("[+] Found old resource name at offset 0x%0X", idx)
        new_bytes = new_resource_name.encode("ascii")

        # Check length
        if len(new_bytes) > len(old_resource_name):
            _log("[-] New resource name too long (max %d chars)",
                 len(old_resource_name))
            return data, False

        # Replace
        data[idx:idx + len(old_resource_name)] = new_bytes
        # Pad remaining with nulls
        for i in range(len(new_bytes), len(old_resource_name)):
            data[idx + len(new_bytes) + (i - len(new_bytes))] = 0x00

        return bytes(data), True

    _log("[-] Old resource name not found in file")
    return data, False


# ---------------------------------------------------------------------------
# run_function — the original main() equivalent.
# ---------------------------------------------------------------------------

def run_function(
    input_file,
    output_file,
    old_resource,
    new_resource_name,
    verbose=False,
):
    """Run SetResourceName against `input_file`, writing result to `output_file`.

    Returns 0 on success, non-zero on failure.
    """
    _log("SetResourceName — Resource name setting tool")
    _log("Input file: %s", input_file)
    _log("Output file: %s", output_file)
    _log("Old resource: %d (%s)", old_resource,
         OLD_RESOURCE_OPTIONS[old_resource][0])
    _log("New resource name: %s", new_resource_name)

    # Validate new resource name length
    old_name = OLD_RESOURCE_OPTIONS[old_resource][0]
    if len(new_resource_name) > len(old_name):
        _log("[-] New resource name too long (max %d chars)", len(old_name))
        return 1

    if not os.path.isfile(input_file):
        _log("[-] Input file not found: %s", input_file)
        _show_message_box("SetResourceName", "Error Opening File")
        return 1

    # Read input file
    try:
        with open(input_file, "rb") as f:
            data = f.read()
    except OSError as exc:
        _log("[-] Error reading input file: %s", exc)
        _show_message_box("SetResourceName", "Error Reading in File")
        return 1

    _log("[+] Read %d bytes from input file", len(data))

    # Set resource name
    modified_data, success = _set_resource_name(data, old_resource,
                                                new_resource_name)

    if not success:
        _log("[-] Failed to set resource name")
        _show_message_box("SetResourceName", "Error Writing To File")
        return 1

    _log("[+] Resource name set successfully")

    # Write output file
    try:
        with open(output_file, "wb") as f:
            f.write(modified_data)
    except OSError as exc:
        _log("[-] Error writing output file: %s", exc)
        _show_message_box("SetResourceName", "Error Writing To File")
        return 1

    _log("[+] Wrote %d bytes to output file", len(modified_data))
    _log("[+] Output file: %s", output_file)
    _log("[+] SetResourceName completed successfully")

    return 0


def main():
    """CLI driver (standalone testing)."""
    _log("SetResourceName standalone CLI not implemented — "
         "use `nsa-equation-py setresourcename ...`")
    return 1


if __name__ == "__main__":
    sys.exit(main())
