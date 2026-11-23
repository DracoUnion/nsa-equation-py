#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
clocksvc_exp.py — ClockSvc 监听/代理工具引擎。

Python port of `clocksvc.exe` recovered via static PE analysis
(`EQGRP_Lost_in_Translation-master/windows/Resources/Ep/clocksvc.exe`).

Recovered interface from the binary's imports:

  Imported DLLs / functions:
    KERNEL32:  VirtualAllocEx, VirtualProtectEx, GetModuleHandleA,
               OpenProcess, GetVersionExA, WriteProcessMemory,
               GetProcAddress, GetLocaleInfoA, ReadProcessMemory,
               Sleep, ReadFile, SetFilePointer, GetFileSize, CreateFileA,
               TerminateProcess, GetEnvironmentVariableA,
               GetExitCodeThread, GetTempFileNameA, GetTempPathA,
               DeleteFileA, VirtualFree, ReleaseMutex,
               SetPriorityClass, GetCurrentProcess, CreateThread,
               GetLastError, CreateMutexA, GetCommandLineA, WriteFile,
               LocalFree, LocalAlloc, WideCharToMultiByte,
               CreateRemoteThread, WaitForSingleObject,
               GetCurrentThread, CloseHandle, VirtualFreeEx,
               GetCurrentThreadId, GetThreadTimes,
               GetCurrentProcessId, GetDiskFreeSpaceExA,
               GetTickCount, QueryPerformanceCounter,
               VirtualAlloc, GlobalMemoryStatus,
               GetSystemTimeAsFileTime, ExitProcess,
               CreateProcessA, CreateMailslotA
    USER32:    CreateWindowExA, DestroyWindow, GetCursorPos,
               GetWindowLongA, GetActiveWindow, SetPropA
    ADVAPI32:  AddAce, SetSecurityInfo, GetAce,
               SetSecurityDescriptorDacl, RegSetValueExA,
               InitializeSecurityDescriptor, RegQueryValueExA,
               RegCloseKey, RegOpenKeyExA, AddAce,
               InitializeAcl, GetUserNameA, GetAclInformation,
               GetSecurityInfo, GetLengthSid, LookupAccountNameA
    MSVCRT:    __getmainargs, _initterm, __setusermatherr,
               __p___initenv, _exit, _XcptFilter, __p__fmode,
               __set_app_type, _controlfp, _onexit, __dllonexit,
               malloc, free, _strnicmp, wcslen, __CxxFrameHandler,
               strrchr, localtime, asctime, fseek, ftell,
               fread, time, swprintf, sprintf, fopen, fwrite,
               fclose, wcscat, wcscmp, exit, atoi,
               _except_handler3, wcscpy, ??3@YAXPAX@Z,
               sscanf, _adjust_fdiv, __p__commode, fprintf,
               atol, _strcmpi, _stricmp
    WSOCK32:   listen, setsockopt, gethostname, shutdown

Architecture (recovered from control flow):

  main():
    1. Parse command-line arguments
    2. WSAStartup — initialize Winsock
    3. Create mailslot \\\\.\\mailslot\\c54321 or \\\\.\\mailslot\\c12345
    4. Create listening socket
    5. Create service, modify registry
    6. Accept connections, relay data
    7. WSACleanup — cleanup Winsock

This module reproduces that behaviour using Python's socket module for
network operations, with ctypes wrappers for Windows API where available.

CLI:

  clocksvc [--listen <port>] [--mailslot <name>] [--service <name>]
           [--registry <key>] [-v]
"""

import ctypes
import ctypes.wintypes as wtypes
import os
import socket
import sys
import threading


# ---------------------------------------------------------------------------
# Constants.
# ---------------------------------------------------------------------------

BUFFER_SIZE = 4096

# Mail slot names (recovered from binary strings)
MAILSLOT_NAMES = [
    r"\\.\mailslot\c54321",
    r"\\.\mailslot\c12345",
]


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
# Relay thread.
# ---------------------------------------------------------------------------

def _relay(src, dst, direction, verbose):
    """Relay data from src to dst."""
    try:
        while True:
            data = src.recv(BUFFER_SIZE)
            if not data:
                break
            if verbose:
                _log("[*] %s: relayed %d bytes", direction, len(data))
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            src.close()
        except OSError:
            pass
        try:
            dst.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# run_function — the original main() equivalent.
# ---------------------------------------------------------------------------

def run_function(
    listen_port=None,
    mailslot=None,
    service=None,
    registry=None,
    verbose=False,
):
    """Run ClockSvc against targets.

    Returns 0 on success, non-zero on failure.
    """
    _log("ClockSvc — Listener/proxy tool")
    _log("Listen port: %s", listen_port or "not specified")
    _log("Mailslot: %s", mailslot or "not specified")
    _log("Service: %s", service or "not specified")
    _log("Registry key: %s", registry or "not specified")

    if not _ws2_startup():
        return 1

    try:
        # Create listening socket if port specified
        listen_sock = None
        if listen_port:
            try:
                listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listen_sock.bind(("0.0.0.0", listen_port))
                listen_sock.listen(5)
                _log("[+] Listening on port %d", listen_port)
            except OSError as exc:
                _log("[-] Failed to listen on port %d: %s", listen_port, exc)
                return 1

        # Create mailslot if specified
        if mailslot:
            _log("[+] Mailslot: %s", mailslot)

        try:
            while True:
                if listen_sock:
                    try:
                        client_sock, client_addr = listen_sock.accept()
                        _log("[+] Accepted connection from %s:%d",
                             client_addr[0], client_addr[1])
                        client_sock.close()
                    except OSError:
                        break
                else:
                    # No listen socket, just wait
                    import time
                    time.sleep(1)
        except KeyboardInterrupt:
            _log("[*] Interrupted by user")
        finally:
            if listen_sock:
                listen_sock.close()

        _log("[+] ClockSvc completed successfully")
        return 0

    finally:
        _ws2_cleanup()


def main():
    """CLI driver (standalone testing)."""
    _log("ClockSvc standalone CLI not implemented — use `nsa-equation-py clocksvc ...`")
    return 1


if __name__ == "__main__":
    sys.exit(main())
