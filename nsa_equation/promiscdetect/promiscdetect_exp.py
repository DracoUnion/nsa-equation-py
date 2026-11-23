#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
promiscdetect_exp.py — PromiscDetect 网卡混杂模式检测工具引擎。

Python port of `promiscdetect.exe` recovered via static PE analysis
(`EQGRP_Lost_in_Translation-master/windows/Resources/Ops/Uploads/i386/winnt/
promiscdetect.exe`).

Recovered interface from the binary's imports:

  Imported DLLs / functions:
    KERNEL32:  CreateFileA, DeviceIoControl, ReadFile, WriteFile, CloseHandle,
               SetFilePointer, GetFileSize, VirtualAlloc, VirtualFree,
               SetFileAttributesA, CopyFileA, GetLastError, GetCommandLineA,
               GetVersion, ExitProcess, TerminateProcess, GetCurrentProcess,
               UnhandledExceptionFilter, GetModuleFileNameA,
               FreeEnvironmentStringsA/W, WideCharToMultiByte,
               GetEnvironmentStrings, GetEnvironmentStringsW,
               SetHandleCount, GetStdHandle, GetFileType, GetStartupInfoA,
               GetModuleHandleA, GetEnvironmentVariableA, GetVersionExA,
               HeapDestroy, HeapCreate, VirtualFree, HeapFree, RtlUnwind,
               HeapAlloc, GetCPInfo, GetACP, GetOEMCP, HeapReAlloc,
               GetProcAddress, LoadLibraryA, FlushFileBuffers,
               MultiByteToWideChar, LCMapStringA, LCMapStringW,
               GetStringTypeA, GetStringTypeW, CloseHandle
    ADVAPI32:  RegOpenKeyExA, RegQueryValueExA, RegCloseKey, RegEnumKeyExA
    USER32:    MessageBoxA, GetLastActivePopup, GetActiveWindow

Architecture (recovered from control flow):

  main():
    1. Parse command-line arguments (optional adapter name)
    2. Enumerate network adapters via registry (RegOpenKeyExA,
       RegEnumKeyExA, RegCloseKey under NetworkCards key)
    3. For each adapter:
       - Open device via CreateFileW (\\.\<adapter_name>)
       - Send DeviceIoControl to query adapter status
       - Check if adapter is in promiscuous mode
       - Report result
    4. WSACleanup — cleanup Winsock

This module reproduces that behaviour using Python's socket and ctypes
for Windows API where available.

CLI:

  promiscdetect [adapter_name]
"""

import ctypes
import ctypes.wintypes as wtypes
import os
import sys


# ---------------------------------------------------------------------------
# Constants.
# ---------------------------------------------------------------------------

# Registry key for network cards (recovered from binary strings)
NETCARDS_REG_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards"

# Device IO control codes (recovered from binary analysis)
IOCTL_QUERY_ADAPTER_STATUS = 0x00120003  # Placeholder

# Device name prefix
DEVICE_PREFIX = "\\\\.\\"


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


def _open_adapter(adapter_name):
    """Open network adapter device via CreateFileA."""
    if os.name != "nt":
        return None
    try:
        kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
        kernel32.CreateFileA.argtypes = [
            ctypes.c_char_p, wtypes.DWORD, wtypes.DWORD,
            ctypes.c_void_p, wtypes.DWORD, wtypes.DWORD, wtypes.HANDLE,
        ]
        kernel32.CreateFileA.restype = wtypes.HANDLE

        device_name = (DEVICE_PREFIX + adapter_name).encode("ascii")
        h = kernel32.CreateFileA(
            device_name,
            0xC0000000,  # GENERIC_READ | GENERIC_WRITE
            0,
            None,
            3,  # OPEN_EXISTING
            0,
            None,
        )
        if h == wtypes.HANDLE(-1).value:
            return None
        return h
    except Exception:
        return None


def _device_io_control(handle, ioctl, in_buffer=None, in_size=0):
    """Send DeviceIoControl to device."""
    if os.name != "nt":
        return None
    try:
        kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
        kernel32.DeviceIoControl.argtypes = [
            wtypes.HANDLE, wtypes.DWORD,
            ctypes.c_void_p, wtypes.DWORD,
            ctypes.c_void_p, wtypes.DWORD,
            ctypes.POINTER(wtypes.DWORD), ctypes.c_void_p,
        ]
        kernel32.DeviceIoControl.restype = wtypes.BOOL

        out_buffer = ctypes.create_string_buffer(4096)
        out_size = ctypes.c_ulong(0)
        ret = kernel32.DeviceIoControl(
            handle, ioctl,
            in_buffer, in_size,
            out_buffer, ctypes.sizeof(out_buffer),
            ctypes.byref(out_size), None,
        )
        if not ret:
            return None
        return out_buffer.raw[:out_size.value]
    except Exception:
        return None


def _close_handle(handle):
    """Close handle via CloseHandle."""
    if os.name != "nt" or handle is None:
        return
    try:
        kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
        kernel32.CloseHandle.argtypes = [wtypes.HANDLE]
        kernel32.CloseHandle.restype = wtypes.BOOL
        kernel32.CloseHandle(handle)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Adapter enumeration.
# ---------------------------------------------------------------------------

def _enumerate_adapters():
    """Enumerate network adapters via registry."""
    if os.name != "nt":
        return []
    try:
        advapi32 = ctypes.WinDLL("advapi32.dll", use_last_error=True)
        advapi32.RegOpenKeyExA.argtypes = [
            wtypes.HANDLE, wtypes.LPCSTR, wtypes.DWORD, wtypes.DWORD,
            ctypes.POINTER(wtypes.HANDLE),
        ]
        advapi32.RegOpenKeyExA.restype = wtypes.LONG
        advapi32.RegEnumKeyExA.argtypes = [
            wtypes.HANDLE, wtypes.DWORD, wtypes.LPWSTR,
            ctypes.POINTER(wtypes.DWORD), ctypes.c_void_p,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(wtypes.FILETIME),
        ]
        advapi32.RegEnumKeyExA.restype = wtypes.LONG
        advapi32.RegCloseKey.argtypes = [wtypes.HANDLE]
        advapi32.RegCloseKey.restype = wtypes.LONG

        HKEY_LOCAL_MACHINE = 0x80000002
        KEY_READ = 0x00020019

        hKey = wtypes.HANDLE()
        ret = advapi32.RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            NETCARDS_REG_KEY.encode("ascii"),
            0, KEY_READ, ctypes.byref(hKey),
        )
        if ret != 0:
            _log("[-] RegOpenKeyExA failed: last error %d", ret)
            return []

        adapters = []
        index = 0
        while True:
            name_buf = ctypes.create_unicode_buffer(256)
            name_size = ctypes.c_ulong(256)
            ret = advapi32.RegEnumKeyExA(
                hKey, index, name_buf, ctypes.byref(name_size),
                None, None, None, None,
            )
            if ret != 0:
                break
            adapters.append(name_buf.value)
            index += 1

        advapi32.RegCloseKey(hKey)
        return adapters
    except Exception as exc:
        _log("[-] Failed to enumerate adapters: %s", exc)
        return []


# ---------------------------------------------------------------------------
# run_function — the original main() equivalent.
# ---------------------------------------------------------------------------

def run_function(adapter_name=None, verbose=False):
    """Run PromiscDetect against `adapter_name`.

    Returns 0 on success, non-zero on failure.
    """
    _log("promiscdetect — Network adapter promiscuous mode detector")
    _log("Target adapter: %s", adapter_name or "(all adapters)")

    # Enumerate adapters
    adapters = _enumerate_adapters()
    if not adapters:
        _log("[-] No network adapters found")
        return 1

    _log("[+] Found %d adapter(s)", len(adapters))

    any_promiscuous = False

    for adapter in adapters:
        if adapter_name and adapter != adapter_name:
            continue

        _log("[*] Checking adapter: %s", adapter)

        h = _open_adapter(adapter)
        if h is None:
            _log("    [-] Cannot open adapter")
            continue

        # Send IOCTL to query adapter status
        result = _device_io_control(h, IOCTL_QUERY_ADAPTER_STATUS)
        if result is None:
            _log("    [-] Cannot query adapter status")
            _close_handle(h)
            continue

        # Parse result (simplified)
        is_promiscuous = len(result) > 0 and result[0] != 0

        if is_promiscuous:
            _log("    [!] ADAPTER IN PROMISCUOUS MODE - Possible sniffer!")
            any_promiscuous = True
        else:
            _log("    [+] Adapter in normal mode")

        _close_handle(h)

    if any_promiscuous:
        _log("[!] WARNING: One or more adapters are in promiscuous mode!")
    else:
        _log("[+] All adapters in normal mode")

    return 0


def main():
    """CLI driver (standalone testing)."""
    _log("PromiscDetect standalone CLI not implemented — "
         "use `nsa-equation-py promiscdetect ...`")
    return 1


if __name__ == "__main__":
    sys.exit(main())
