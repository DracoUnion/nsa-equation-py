#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
setouraddr_exp.py — SetOurAddr 地址设置工具引擎。

Python port of `SetOurAddr.exe` recovered via static PE analysis
(`EQGRP_Lost_in_Translation-master/windows/Resources/Pc/Tools/legacy/
SetOurAddr.exe`).

Recovered interface from the binary's imports:

  Imported DLLs / functions:
    WS2_32:   WSAStartup, gethostbyname, inet_addr, gethostname
    KERNEL32: WideCharToMultiByte, GetEnvironmentStrings, LCMapStringW,
              LCMapStringA, SetStdHandle, WriteFile, SetFilePointer,
              ReadFile, CloseHandle, VirtualAlloc, GetFileSize,
              CreateFileA, SetFileAttributesA, CopyFileA, lstrlenA,
              lstrcmpiA, GetLastError, GetEnvironmentVariableA,
              GetModuleHandleA, GetCommandLineA, GetVersion,
              ExitProcess, TerminateProcess, GetCurrentProcess,
              UnhandledExceptionFilter, GetModuleFileNameA,
              FreeEnvironmentStringsA/W, FlushFileBuffers, LoadLibraryA,
              GetEnvironmentStringsW, SetHandleCount, GetStdHandle,
              GetFileType, GetStartupInfoA, GetProcAddress, MultiByteToWideChar,
              GetVersionExA, HeapDestroy, HeapCreate, VirtualFree,
              HeapFree, RtlUnwind, HeapAlloc, GetStringTypeA/W,
              GetCPInfo, GetACP, GetOEMCP, HeapReAlloc
    USER32:   wsprintfA, MessageBoxA

Architecture (recovered from control flow):

  main():
    1. Parse command-line arguments (input_file, output_file, protocol,
       [address])
    2. WSAStartup — initialize Winsock
    3. gethostname / gethostbyname — resolve local host address
    4. CreateFileW — open input file for reading
    5. GetFileSize — get input file size
    6. ReadFile — read input file content into memory
    7. CloseHandle — close input file handle
    8. Scan file for default IP address (127.0.0.1) or IPX address
       (99999999.999999999999)
    9. Replace with specified address or local host address
    10. CreateFileW — create output file for writing
    11. WriteFile — write modified content
    12. CloseHandle — close output file handle
    13. WSACleanup — cleanup Winsock

    Error handling uses MessageBoxA / wsprintfA to display errors.

This module reproduces that behaviour using Python's `socket` module for
network address operations and pure Python file I/O.

CLI:

  setouraddr <input_file> <output_file> <protocol> [IP/IPX_address]
"""

import ctypes
import ctypes.wintypes as wtypes
import os
import socket
import sys
import re


# ---------------------------------------------------------------------------
# Constants.
# ---------------------------------------------------------------------------

DEFAULT_IP = "127.0.0.1"
DEFAULT_IPX = "99999999.999999999999"

PROTOCOL_IP = 1
PROTOCOL_IPX = 2

IP_PATTERN = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
IPX_PATTERN = re.compile(r"\b\d{8}\.\d{12}\b")


def _log(fmt, *args):
    sys.stderr.write((fmt % args).rstrip("\n") + "\n")


# ---------------------------------------------------------------------------
# Windows API wrappers (ctypes).
# ---------------------------------------------------------------------------

def _ws2_startup():
    """Initialize Winsock via WSAStartup."""
    if os.name != "nt":
        return True
    try:
        ws2 = ctypes.WinDLL("ws2_32.dll", use_last_error=True)
        ws2.WSAStartup.argtypes = [ctypes.c_ushort, ctypes.c_void_p]
        ws2.WSAStartup.restype = ctypes.c_int
        wsa_data = ctypes.create_string_buffer(512)
        ret = ws2.WSAStartup(0x0202, ctypes.byref(wsa_data))
        if ret != 0:
            _log("[-] WSAStartup failed: error %d", ret)
            return False
        return True
    except Exception as exc:
        _log("[-] WSAStartup failed: %s", exc)
        return False


def _ws2_cleanup():
    """Cleanup Winsock via WSACleanup."""
    if os.name != "nt":
        return
    try:
        ws2 = ctypes.WinDLL("ws2_32.dll")
        ws2.WSACleanup.argtypes = []
        ws2.WSACleanup.restype = wtypes.BOOL
        ws2.WSACleanup()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Address helpers.
# ---------------------------------------------------------------------------

def _get_local_ip():
    """Get local host IP address."""
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        return ip
    except Exception:
        return DEFAULT_IP


def _validate_ip(address):
    """Validate IPv4 address."""
    try:
        socket.inet_aton(address)
        return True
    except OSError:
        return False


def _validate_ipx(address):
    """Validate IPX address format (basic check)."""
    # IPX format: XXXXXXXX.XXXXXXXXXXXX (4 bytes network + 6 bytes node)
    parts = address.split(".")
    if len(parts) != 2:
        return False
    if len(parts[0]) != 8 or len(parts[1]) != 12:
        return False
    try:
        int(parts[0], 16)
        int(parts[1], 16)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# File address replacement.
# ---------------------------------------------------------------------------

def _replace_address_in_data(data, protocol, address):
    """Replace default address in file data.

    For IP protocol: replaces 127.0.0.1 with specified address.
    For IPX protocol: replaces 99999999.999999999999 with specified address.
    """
    if protocol == PROTOCOL_IP:
        default_addr = DEFAULT_IP
        new_addr = address or _get_local_ip()
        pattern = DEFAULT_IP
    else:
        default_addr = DEFAULT_IPX
        new_addr = address
        if not new_addr:
            _log("[-] IPX address must be specified for IPX protocol")
            return None, False
        pattern = DEFAULT_IPX

    if not _validate_ip(new_addr) and protocol == PROTOCOL_IP:
        _log("[-] Invalid IP address: %s", new_addr)
        return None, False

    if protocol == PROTOCOL_IPX and not _validate_ipx(new_addr):
        _log("[-] Invalid IPX address: %s", new_addr)
        return None, False

    # Count occurrences
    count = data.count(pattern.encode("ascii"))
    if count == 0:
        _log("[-] Default %s address not found in file",
             "IP" if protocol == PROTOCOL_IP else "IPX")
        return data, False

    # Replace all occurrences
    new_data = data.replace(pattern.encode("ascii"), new_addr.encode("ascii"))
    _log("[+] Replaced %d occurrence(s) of default %s address with %s",
         count, "IP" if protocol == PROTOCOL_IP else "IPX", new_addr)
    return new_data, True


# ---------------------------------------------------------------------------
# run_function — the original main() equivalent.
# ---------------------------------------------------------------------------

def run_function(
    input_file,
    output_file,
    protocol,
    address=None,
    verbose=False,
):
    """Run SetOurAddr against `input_file`, writing result to `output_file`.

    Returns 0 on success, non-zero on failure.
    """
    _log("SetOurAddr — Address setting tool")
    _log("Input file: %s", input_file)
    _log("Output file: %s", output_file)
    _log("Protocol: %s", "IP" if protocol == PROTOCOL_IP else "IPX")
    if address:
        _log("Address: %s", address)
    else:
        _log("Address: (use local host address)")

    if not os.path.isfile(input_file):
        _log("[-] Input file not found: %s", input_file)
        return 1

    # Initialize Winsock
    if not _ws2_startup():
        return 1

    try:
        # Read input file
        try:
            with open(input_file, "rb") as f:
                data = f.read()
        except OSError as exc:
            _log("[-] Error reading input file: %s", exc)
            return 1

        _log("[+] Read %d bytes from input file", len(data))

        # Replace address
        new_data, replaced = _replace_address_in_data(data, protocol, address)

        if not replaced:
            _log("[-] No address replacement performed")
            return 1

        # Write output file
        try:
            with open(output_file, "wb") as f:
                f.write(new_data)
        except OSError as exc:
            _log("[-] Error writing output file: %s", exc)
            return 1

        _log("[+] Wrote %d bytes to output file", len(new_data))
        _log("[+] Output file: %s", output_file)
        _log("[+] SetOurAddr completed successfully")
        return 0

    finally:
        _ws2_cleanup()


def main():
    """CLI driver (standalone testing)."""
    _log("SetOurAddr standalone CLI not implemented — "
         "use `nsa-equation-py setouraddr ...`")
    return 1


if __name__ == "__main__":
    sys.exit(main())
