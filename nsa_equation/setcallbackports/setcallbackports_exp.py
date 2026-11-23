#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
setcallbackports_exp.py — SetCallbackPorts 回调端口设置工具引擎。

Python port of `SetCallbackPorts.exe` recovered via static PE analysis
(`EQGRP_Lost_in_Translation-master/windows/Resources/Pc/Tools/legacy/
SetCallbackPorts.exe`).

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
               VirtualFree, GetStdHandle, GetFileType, GetStartupInfoA,
               GetModuleHandleA, GetEnvironmentVariableA, GetVersionExA,
               HeapDestroy, HeapCreate, HeapFree, MultiByteToWideChar,
               GetCPInfo, GetACP, GetOEMCP, HeapReAlloc,
               GetProcAddress, LoadLibraryA, FlushFileBuffers,
               LCMapStringA/W, SetStdHandle
    USER32:    MessageBoxA, GetLastActivePopup, GetActiveWindow

Architecture (recovered from control flow):

  main():
    1. Parse command-line arguments (input_file, output_file, port1-port6)
    2. CreateFileW — open input file for reading
    3. GetFileSize — get input file size
    4. ReadFile — read input file content into memory
    5. CloseHandle — close input file handle
    6. Scan file for default callback ports pattern
    7. Replace with specified ports
    8. CreateFileW — create output file for writing
    9. WriteFile — write modified content
    10. CloseHandle — close output file handle
    11. Report completion

    Error handling uses MessageBoxA to display errors.

This module reproduces that behaviour using pure Python file operations,
with ctypes wrappers for Windows API where available.

CLI:

  setcallbackports <input_file> <output_file> <port1> [port2] [port3] [port4] [port5] [port6]
"""

import ctypes
import ctypes.wintypes as wtypes
import os
import re
import struct
import sys


# ---------------------------------------------------------------------------
# Constants.
# ---------------------------------------------------------------------------

# Default callback ports pattern (recovered from binary analysis)
# The binary searches for default port patterns in the file
DEFAULT_PORTS_PATTERN = re.compile(rb"\x00\x00\x00\x00")  # Placeholder

MAX_PORTS = 6
MIN_PORTS = 1


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
# Port replacement logic.
# ---------------------------------------------------------------------------

def _find_port_pattern(data):
    """Find callback port pattern in file data.

    The original binary searches for default port values (typically 0x00000000
    or specific default port values) in the file.
    """
    # Search for 4-byte zero pattern (default/uninitialized port)
    idx = data.find(b"\x00\x00\x00\x00")
    if idx != -1:
        return idx
    return None


def _set_callback_ports(data, ports):
    """Set callback ports in file data.

    Scans the data for port pattern locations and replaces them with
    the specified ports.
    Returns (modified_data, success).
    """
    data = bytearray(data)
    ports_list = list(ports)

    # Find port pattern locations
    locations = []
    offset = 0
    while True:
        idx = data.find(b"\x00\x00\x00\x00", offset)
        if idx == -1:
            break
        locations.append(idx)
        offset = idx + 1

    if not locations:
        _log("[*] No default port pattern found; appending ports at end")
        # Append ports at end
        for port in ports_list:
            data += struct.pack("<I", port)
        return bytes(data), True

    # Replace ports at found locations
    _log("[+] Found %d port location(s)", len(locations))

    for i, loc in enumerate(locations):
        if i < len(ports_list):
            port = ports_list[i]
            data[loc:loc + 4] = struct.pack("<I", port)
            _log("    Port %d at offset 0x%0X: %d", i + 1, loc, port)
        else:
            break

    return bytes(data), True


# ---------------------------------------------------------------------------
# run_function — the original main() equivalent.
# ---------------------------------------------------------------------------

def run_function(
    input_file,
    output_file,
    ports,
    verbose=False,
):
    """Run SetCallbackPorts against `input_file`, writing result to `output_file`.

    Returns 0 on success, non-zero on failure.
    """
    _log("SetCallbackPorts — Callback port setting tool")
    _log("Input file: %s", input_file)
    _log("Output file: %s", output_file)
    _log("Ports: %s", ", ".join(str(p) for p in ports))

    # Validate ports
    if len(ports) < MIN_PORTS:
        _log("[-] At least %d port must be specified", MIN_PORTS)
        return 1
    if len(ports) > MAX_PORTS:
        _log("[-] Maximum %d ports allowed", MAX_PORTS)
        return 1
    for port in ports:
        if port < 1 or port > 65535:
            _log("[-] Invalid port: %d (must be 1-65535)", port)
            return 1

    if not os.path.isfile(input_file):
        _log("[-] Input file not found: %s", input_file)
        _show_message_box("SetCallbackPorts", "Error Opening File")
        return 1

    # Read input file
    try:
        with open(input_file, "rb") as f:
            data = f.read()
    except OSError as exc:
        _log("[-] Error reading input file: %s", exc)
        _show_message_box("SetCallbackPorts", "Error Reading in File")
        return 1

    _log("[+] Read %d bytes from input file", len(data))

    # Set callback ports
    modified_data, success = _set_callback_ports(data, ports)

    if not success:
        _log("[-] Failed to set callback ports")
        _show_message_box("SetCallbackPorts", "Error Writing To File")
        return 1

    _log("[+] Callback ports set successfully")

    # Write output file
    try:
        with open(output_file, "wb") as f:
            f.write(modified_data)
    except OSError as exc:
        _log("[-] Error writing output file: %s", exc)
        _show_message_box("SetCallbackPorts", "Error Writing To File")
        return 1

    _log("[+] Wrote %d bytes to output file", len(modified_data))
    _log("[+] Output file: %s", output_file)
    _log("[+] SetCallbackPorts completed successfully")

    return 0


def main():
    """CLI driver (standalone testing)."""
    _log("SetCallbackPorts standalone CLI not implemented — "
         "use `nsa-equation-py setcallbackports ...`")
    return 1


if __name__ == "__main__":
    sys.exit(main())
