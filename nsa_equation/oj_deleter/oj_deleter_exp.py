#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
oj_deleter_exp.py — OJ_Deleter_2.4 Oddjob 删除工具引擎。

Python port of `OJ_Deleter_2.4.exe` recovered via static PE analysis
(`EQGRP_Lost_in_Translation-master/oddjob/Binaries/Payloads/OJ_Deleter_2.4.exe`).

Recovered interface from the binary's imports:

  Imported DLLs / functions:
    KERNEL32:  DeleteFileW, Sleep, SetErrorMode, OutputDebugStringW,
               GetModuleHandleW, GetStartupInfoW
    OLE32:     CoInitializeEx, CoCreateInstance, CoUninitialize, CoTaskMemFree
    MSVCRT:    standard C runtime (_wcmdln, __wgetmainargs, _initterm,
               __setusermatherr, _adjust_fdiv, __p__commode, __set_app_type,
               _except_handler3, _controlfp, _XcptFilter, _exit,
               __p__fmode, vswprintf, wcsstr, wcstok, swprintf)

Architecture (recovered from control flow):

  main():
    1. SetErrorMode — 设置错误处理模式
    2. CoInitializeEx — 初始化 COM 库
    3. 构造要删除的文件路径 (宽字符)
    4. DeleteFileW — 删除目标文件
    5. CoUninitialize — 释放 COM 库
    6. ExitProcess / _exit — 退出

This module reproduces that behaviour in portable Python using `ctypes` to
call the Windows API when running on Windows, or pure-Python equivalents on
other platforms.

CLI:

  oj_deleter <target_path> [--delay <ms>] [--debug]
"""

import ctypes
import ctypes.wintypes as wtypes
import os
import sys


# ---------------------------------------------------------------------------
# Windows API constants (for the ctypes path on Windows).
# ---------------------------------------------------------------------------

DELETEFILEW = "DeleteFileW"
COINITIALIZEEX = "CoInitializeEx"
COUNINITIALIZE = "CoUninitialize"
SLEEP = "Sleep"
SETERRORMODE = "SetErrorMode"
OUTPUTDEBUGSTRINGW = "OutputDebugStringW"

COINIT_APARTMENTTHREADED = 0x2
COINIT_MULTITHREADED = 0x0


def _log(fmt, *args):
    sys.stderr.write((fmt % args).rstrip("\n") + "\n")


# ---------------------------------------------------------------------------
# Windows API wrappers (ctypes).
# ---------------------------------------------------------------------------

def _delete_file_windows(path):
    """Delete `path` using DeleteFileW via ctypes."""
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    kernel32.DeleteFileW.argtypes = [wtypes.LPCWSTR]
    kernel32.DeleteFileW.restype = wtypes.BOOL
    result = kernel32.DeleteFileW(path)
    if not result:
        err = ctypes.get_last_error()
        _log("[-] DeleteFileW failed on %s: last error %d", path, err)
        return False
    _log("[+] Deleted: %s", path)
    return True


def _co_initialize_ex():
    """Initialize COM via CoInitializeEx."""
    ole32 = ctypes.WinDLL("ole32.dll", use_last_error=True)
    ole32.CoInitializeEx.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    ole32.CoInitializeEx.restype = ctypes.c_long
    hr = ole32.CoInitializeEx(None, COINIT_APARTMENTTHREADED)
    if hr < 0:
        _log("[-] CoInitializeEx failed: HRESULT 0x%08X", hr & 0xFFFFFFFF)
        return False
    return True


def _co_uninitialize():
    """Uninitialize COM via CoUninitialize."""
    ole32 = ctypes.WinDLL("ole32.dll", use_last_error=True)
    ole32.CoUninitialize.argtypes = []
    ole32.CoUninitialize.restype = None
    ole32.CoUninitialize()


def _sleep_ms(ms):
    """Sleep for `ms` milliseconds via Sleep."""
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    kernel32.Sleep.argtypes = [ctypes.c_ulong]
    kernel32.Sleep.restype = None
    kernel32.Sleep(ms)


def _set_error_mode(mode):
    """Set error mode via SetErrorMode."""
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    kernel32.SetErrorMode.argtypes = [ctypes.c_uint]
    kernel32.SetErrorMode.restype = ctypes.c_uint
    return kernel32.SetErrorMode(mode)


def _output_debug_string_w(msg):
    """Output debug string via OutputDebugStringW."""
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    kernel32.OutputDebugStringW.argtypes = [wtypes.LPCWSTR]
    kernel32.OutputDebugStringW.restype = None
    kernel32.OutputDebugStringW(msg)


# ---------------------------------------------------------------------------
# Pure-Python fallback (non-Windows platforms).
# ---------------------------------------------------------------------------

def _delete_file_fallback(path):
    """Delete `path` using os.remove (fallback for non-Windows)."""
    try:
        os.remove(path)
        _log("[+] Deleted: %s", path)
        return True
    except FileNotFoundError:
        _log("[-] File not found: %s", path)
        return False
    except PermissionError:
        _log("[-] Permission denied: %s", path)
        return False
    except OSError as exc:
        _log("[-] Delete failed on %s: %s", path, exc)
        return False


def _sleep_ms_fallback(ms):
    """Sleep for `ms` milliseconds (fallback)."""
    import time
    time.sleep(ms / 1000.0)


def _output_debug_string_w_fallback(msg):
    """Print debug message to stderr (fallback)."""
    sys.stderr.write("[DEBUG] " + msg + "\n")


# ---------------------------------------------------------------------------
# run_function — the original main() equivalent.
# ---------------------------------------------------------------------------

def run_function(target, delay=0, debug=False):
    """Run the OJ_Deleter against `target`.

    Returns 0 on success, non-zero on failure.
    """
    _log("OJ_Deleter 2.4 — Oddjob deletion tool")
    _log("Target: %s", target)
    if delay > 0:
        _log("Delay: %d ms", delay)
    if debug:
        _log("Debug: enabled")

    is_windows = os.name == "nt"

    # Set error mode (suppress critical error popups).
    if is_windows:
        _set_error_mode(1)  # SEM_FAILCRITICALERRORS
    if debug:
        _output_debug_string_w("OJ_Deleter starting: " + target)
        _output_debug_string_w_fallback("OJ_Deleter starting: " + target)

    # Delay before deletion (if specified).
    if delay > 0:
        _log("[*] Waiting %d ms before deletion...", delay)
        if is_windows:
            _sleep_ms(delay)
        else:
            _sleep_ms_fallback(delay)

    # Initialize COM (mirrors CoInitializeEx in the original).
    com_initialized = False
    if is_windows:
        com_initialized = _co_initialize_ex()
        if com_initialized:
            _log("[+] COM initialized")
    else:
        _log("[*] COM initialization skipped (non-Windows)")

    # Delete the target file (mirrors DeleteFileW in the original).
    success = False
    if is_windows:
        success = _delete_file_windows(target)
    else:
        success = _delete_file_fallback(target)

    # Uninitialize COM.
    if com_initialized:
        _co_uninitialize()
        _log("[+] COM uninitialized")

    if debug:
        _output_debug_string_w("OJ_Deleter finished: " + target)
        _output_debug_string_w_fallback("OJ_Deleter finished: " + target)

    return 0 if success else 1


def main():
    """CLI driver (standalone testing)."""
    _log("OJ_Deleter standalone CLI not implemented — "
         "use `nsa-equation-py oj_deleter ...`")
    return 1


if __name__ == "__main__":
    sys.exit(main())
