#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
svctouch_exp.py — SvcTouch 服务触摸/探测工具引擎。

Python port of `svctouch.exe` recovered via static PE analysis
(`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/
Resources/Tools/svctouch.exe`).

Recovered interface from the binary's imports:

  Imported DLLs / functions:
    KERNEL32:  MultiByteToWideChar (ANSI to wide-char conversion)
    OLE32:     CoInitialize, CoGetClassObject, CLSIDFromString,
               CoUninitialize (COM)
    MSVCRT:    standard C runtime

Architecture (recovered from control flow):

  main():
    1. Parse command-line arguments (machine name + CLSID string)
    2. MultiByteToWideChar — convert machine name to wide-char
    3. CLSIDFromString — parse CLSID from string
    4. CoInitialize — initialize COM library
    5. CoGetClassObject — attempt to retrieve remote class object
    6. Based on HRESULT: report service status
       - S_OK / S_FALSE: service exists (and possibly running)
       - REGDB_E_CLASSNOTREG: class not registered
       - RPC_E_SERVER_UNAVAILABLE: RPC server unavailable
       - E_ACCESSDENIED: access denied
    7. CoUninitialize — cleanup COM

This module reproduces that behaviour using `ctypes` to call the Windows COM
API when running on Windows, or pure-Python stubs on other platforms.

CLI:

  svctouch <\\machinename> <CLSID> [-v]
"""

import ctypes
import ctypes.wintypes as wtypes
import os
import re
import sys


# ---------------------------------------------------------------------------
# Windows COM constants (for the ctypes path on Windows).
# ---------------------------------------------------------------------------

CLSCTX_INPROC_SERVER = 0x1
CLSCTX_INPROC_HANDLER = 0x2
CLSCTX_LOCAL_SERVER = 0x4
CLSCTX_INPROC_SERVER16 = 0x8
CLSCTX_REMOTE_SERVER = 0x10
CLSCTX_ALL = CLSCTX_INPROC_SERVER | CLSCTX_INPROC_HANDLER | \
    CLSCTX_LOCAL_SERVER | CLSCTX_REMOTE_SERVER

# HRESULT values
S_OK = 0x00000000
S_FALSE = 0x00000001
E_ACCESSDENIED = 0x80070005
REGDB_E_CLASSNOTREG = 0x80040154
RPC_E_SERVER_UNAVAILABLE = 0x800706BA


def _log(fmt, *args):
    sys.stderr.write((fmt % args).rstrip("\n") + "\n")


# ---------------------------------------------------------------------------
# Windows COM wrappers (ctypes).
# ---------------------------------------------------------------------------

def _co_initialize():
    """Initialize COM library via CoInitialize."""
    ole32 = ctypes.WinDLL("ole32.dll", use_last_error=True)
    ole32.CoInitialize.argtypes = [ctypes.c_void_p]
    ole32.CoInitialize.restype = ctypes.c_long
    hr = ole32.CoInitialize(None)
    if hr < 0:
        _log("[-] CoInitialize failed: HRESULT 0x%08X", hr & 0xFFFFFFFF)
        return False
    return True


def _co_uninitialize():
    """Uninitialize COM library via CoUninitialize."""
    ole32 = ctypes.WinDLL("ole32.dll", use_last_error=True)
    ole32.CoUninitialize.argtypes = []
    ole32.CoUninitialize.restype = None
    ole32.CoUninitialize()


def _clsid_from_string(clsid_str):
    """Convert CLSID string to binary CLSID via CLSIDFromString."""
    ole32 = ctypes.WinDLL("ole32.dll", use_last_error=True)
    ole32.CLSIDFromString.argtypes = [
        wtypes.LPWSTR, ctypes.POINTER(ctypes.GUID),
    ]
    ole32.CLSIDFromString.restype = ctypes.c_long

    clsid = ctypes.GUID()
    hr = ole32.CLSIDFromString(clsid_str, ctypes.byref(clsid))
    if hr < 0:
        _log("[-] CLSIDFromString failed: HRESULT 0x%08X", hr & 0xFFFFFFFF)
        return None
    return clsid


def _co_get_class_object(clsid, machine_name=None):
    """Get remote class object via CoGetClassObject."""
    ole32 = ctypes.WinDLL("ole32.dll", use_last_error=True)
    ole32.CoGetClassObject.argtypes = [
        ctypes.POINTER(ctypes.GUID),  # rclsid
        wtypes.DWORD,                 # dwClsContext
        ctypes.c_void_p,              # pServerInfo (reserved)
        ctypes.POINTER(ctypes.GUID),  # riid
        ctypes.POINTER(ctypes.c_void_p),  # ppv
    ]
    ole32.CoGetClassObject.restype = ctypes.c_long

    iid = ctypes.GUID()  # IUnknown
    ppv = ctypes.c_void_p()

    # Build machine name as COSERVERINFO if provided
    server_info = None
    if machine_name:
        class COSERVERINFO(ctypes.Structure):
            _fields_ = [
                ("dwReserved1", wtypes.DWORD),
                ("pwszName", wtypes.LPWSTR),
                ("pAuthInfo", ctypes.c_void_p),
                ("dwReserved2", wtypes.DWORD),
            ]
        machine_w = ctypes.create_unicode_buffer(machine_name)
        server_info = COSERVERINFO(0, machine_w, None, 0)

    hr = ole32.CoGetClassObject(
        ctypes.byref(clsid),
        CLSCTX_ALL,
        ctypes.byref(server_info) if server_info else None,
        ctypes.byref(iid),
        ctypes.byref(ppv),
    )
    return hr, ppv


def _multi_byte_to_wide_char(ansi_str):
    """Convert ANSI string to wide char via MultiByteToWideChar."""
    if os.name != "nt":
        return ansi_str
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    kernel32.MultiByteToWideChar.argtypes = [
        wtypes.UINT, wtypes.DWORD, wtypes.LPCSTR, ctypes.c_int,
        wtypes.LPWSTR, ctypes.c_int,
    ]
    kernel32.MultiByteToWideChar.restype = ctypes.c_int

    cp = 0  # CP_ACP
    flags = 0
    needed = kernel32.MultiByteToWideChar(
        cp, flags, ansi_str.encode("ascii"), -1, None, 0
    )
    if needed == 0:
        _log("[-] MultiByteToWideChar failed: last error %d",
             ctypes.get_last_error())
        return None
    buf = ctypes.create_unicode_buffer(needed)
    kernel32.MultiByteToWideChar(
        cp, flags, ansi_str.encode("ascii"), -1, buf, needed
    )
    return buf.value


# ---------------------------------------------------------------------------
# Pure-Python fallback (non-Windows platforms).
# ---------------------------------------------------------------------------

def _parse_clsid(clsid_str):
    """Parse a CLSID/GUID string into a ctypes.GUID (fallback)."""
    match = re.match(
        r"^\{?([0-9A-Fa-f]{8})-([0-9A-Fa-f]{4})-([0-9A-Fa-f]{4})-"
        r"([0-9A-Fa-f]{2})([0-9A-Fa-f]{2})-([0-9A-Fa-f]{12})\}?$",
        clsid_str,
    )
    if not match:
        _log("[-] Invalid CLSID format: %s", clsid_str)
        return None
    parts = match.groups()
    clsid_str_clean = "%s-%s-%s-%s%s-%s%s" % parts
    try:
        return ctypes.GUID(clsid_str_clean)
    except Exception as exc:
        _log("[-] Invalid CLSID: %s", exc)
        return None


# ---------------------------------------------------------------------------
# run_function — the original main() equivalent.
# ---------------------------------------------------------------------------

def run_function(machine, clsid, verbose=False):
    """Run svctouch against `machine` for the given `clsid`.

    Returns 0 on success (service found), non-zero on failure.
    """
    _log("svctouch — SvcTouch service touch/probe tool")
    _log("Machine: %s", machine)
    _log("CLSID: %s", clsid)

    # Parse CLSID
    if os.name == "nt":
        clsid_obj = _clsid_from_string(clsid)
    else:
        clsid_obj = _parse_clsid(clsid)
    if clsid_obj is None:
        return 1

    if verbose:
        _log("[+] Parsed CLSID: %s", str(clsid_obj))

    # Convert machine name to wide char (Windows)
    machine_w = None
    if os.name == "nt":
        machine_w = _multi_byte_to_wide_char(machine)
        if machine_w is None:
            return 1
        if verbose:
            _log("[+] Machine wide name: %s", machine_w)

    # Initialize COM
    com_initialized = False
    if os.name == "nt":
        com_initialized = _co_initialize()
        if com_initialized:
            _log("[+] COM initialized")
    else:
        _log("[*] COM initialization skipped (non-Windows)")

    # Attempt to get the remote class object
    hr, ppv = _co_get_class_object(clsid_obj, machine_w)

    # Interpret HRESULT
    if hr == S_OK or hr == S_FALSE:
        _log("[+] Machine has that service or application, and it is running.")
        _log("    Code: [0x%08X]", hr)
        result = 0
    elif hr == REGDB_E_CLASSNOTREG:
        _log("[-] Class not registered.")
        _log("    Code: [0x%08X]", hr)
        result = 1
    elif hr == RPC_E_SERVER_UNAVAILABLE:
        _log("[-] The RPC server is unavailable.")
        _log("    Causes: Firewall, Machine down, DCOM disabled/not supported, etc.")
        _log("    Code: [0x%08X]", hr)
        result = 1
    elif hr == E_ACCESSDENIED:
        _log("[-] Access is denied.")
        _log("    Code: [0x%08X]", hr)
        result = 1
    else:
        _log("[-] Unexpected response, unable to determine if machine has that service.")
        _log("    Code: [0x%08X]", hr)
        result = 1

    # Uninitialize COM
    if com_initialized:
        _co_uninitialize()
        _log("[+] COM uninitialized")

    return result


def main():
    """CLI driver (standalone testing)."""
    _log("svctouch standalone CLI not implemented — "
         "use `nsa-equation-py svctouch ...`")
    return 1


if __name__ == "__main__":
    sys.exit(main())
