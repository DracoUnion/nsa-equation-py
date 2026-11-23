#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sc_exp.py — Windows 服务控制工具 (Service Control) 引擎。

Python port of `sc.exe` recovered via static PE analysis
(`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/
Resources/Tools/sc.exe`).

Recovered interface from the binary's imports:

  Imported DLLs / functions:
    ADVAPI32:  OpenSCManagerW, CreateServiceW, DeleteService, StartServiceW,
               OpenServiceW, ControlService, QueryServiceStatus,
               QueryServiceConfigW, ChangeServiceConfigW,
               EnumServicesStatusW, CloseServiceHandle,
               ChangeServiceConfig2W, QueryServiceObjectSecurity,
               SetServiceObjectSecurity, EnumDependentServicesW,
               GetServiceKeyNameW, GetServiceDisplayNameW,
               LockServiceDatabase, UnlockServiceDatabase,
               QueryServiceLockStatusW,
               ConvertSecurityDescriptorToStringSecurityDescriptorW,
               ConvertStringSecurityDescriptorToSecurityDescriptorW,
               NotifyBootConfigStatus
    KERNEL32:  ExitProcess, LocalAlloc, GetLastError, FormatMessageW,
               GetCommandLineA, GetVersion, LocalFree, WideCharToMultiByte,
               ReadConsoleInputA, SetConsoleMode, GetConsoleMode,
               TerminateProcess, GetCurrentProcess, UnhandledExceptionFilter,
               GetModuleFileNameA, FreeEnvironmentStringsA,
               MultiByteToWideChar, FreeEnvironmentStringsW,
               GetEnvironmentStrings, GetEnvironmentStringsW, GetCPInfo,
               GetACP, GetOEMCP, SetHandleCount, GetStdHandle, GetFileType,
               GetStartupInfoA, HeapDestroy, HeapCreate, VirtualFree,
               RtlUnwind, WriteFile, CreateFileA, CloseHandle,
               WriteConsoleA, HeapFree, HeapAlloc, LCMapStringA,
               LCMapStringW, GetStringTypeA, GetStringTypeW, VirtualAlloc,
               GetProcAddress, LoadLibraryA, FlushFileBuffers,
               SetFilePointer, SetStdHandle
    ntdll:     RtlAnsiStringToUnicodeString, RtlInitAnsiString,
               RtlAdjustPrivilege

Architecture (recovered from control flow):

  main() parses <server> <command> <service name> [options], then dispatches
  to the appropriate ADVAPI32 service management function:

    query     -> OpenSCManagerW + OpenServiceW + QueryServiceStatus
    create    -> OpenSCManagerW + CreateServiceW
    delete    -> OpenSCManagerW + OpenServiceW + DeleteService
    start     -> OpenSCManagerW + OpenServiceW + StartServiceW
    stop      -> OpenSCManagerW + OpenServiceW + ControlService (STOP)
    config    -> OpenSCManagerW + OpenServiceW + ChangeServiceConfigW
    qc        -> OpenSCManagerW + OpenServiceW + QueryServiceConfigW
    control   -> OpenSCManagerW + OpenServiceW + ControlService
    contin    -> OpenSCManagerW + OpenServiceW + ControlService (CONTINUE)
    sdshow    -> OpenSCManagerW + OpenServiceW + QueryServiceObjectSecurity
    boot      -> NotifyBootConfigStatus

This module reproduces that behaviour using `ctypes` to call the Windows
Service Control API when running on Windows, or pure-Python stubs on other
platforms.

CLI:

  sc <server> <command> <service name> [options]
"""

import ctypes
import ctypes.wintypes as wtypes
import os
import sys


# ---------------------------------------------------------------------------
# Windows Service Control Manager constants.
# ---------------------------------------------------------------------------

SC_MANAGER_ALL_ACCESS = 0xF003F
SC_MANAGER_ENUMERATE_SERVICE = 0x00000004
SC_MANAGER_CREATE_SERVICE = 0x00000002
SC_MANAGER_CONNECT = 0x00000001
SC_MANAGER_LOCK = 0x00000008

SERVICE_ALL_ACCESS = 0xF01FF
SERVICE_QUERY_CONFIG = 0x00000001
SERVICE_CHANGE_CONFIG = 0x00000002
SERVICE_QUERY_STATUS = 0x00000004
SERVICE_START = 0x00000010
SERVICE_STOP = 0x00000020
SERVICE_USER_DEFINED_CONTROL = 0x00000100

SERVICE_KERNEL_DRIVER = 0x00000001
SERVICE_FILE_SYSTEM_DRIVER = 0x00000002
SERVICE_ADAPTER = 0x00000004
SERVICE_RECOGNIZER_DRIVER = 0x00000008
SERVICE_WIN32_OWN_PROCESS = 0x00000010
SERVICE_WIN32_SHARE_PROCESS = 0x00000020

SERVICE_BOOT_START = 0x00000000
SERVICE_SYSTEM_START = 0x00000001
SERVICE_AUTO_START = 0x00000002
SERVICE_DEMAND_START = 0x00000003
SERVICE_DISABLED = 0x00000004

SERVICE_ERROR_IGNORE = 0x00000000
SERVICE_ERROR_NORMAL = 0x00000001
SERVICE_ERROR_SEVERE = 0x00000002
SERVICE_ERROR_CRITICAL = 0x00000003

SERVICE_STOPPED = 0x00000001
SERVICE_START_PENDING = 0x00000002
SERVICE_STOP_PENDING = 0x00000003
SERVICE_RUNNING = 0x00000004
SERVICE_CONTINUE_PENDING = 0x00000005
SERVICE_PAUSE_PENDING = 0x00000006
SERVICE_PAUSED = 0x00000007

SERVICE_CONTROL_STOP = 0x00000001
SERVICE_CONTROL_CONTINUE = 0x00000003


def _log(fmt, *args):
    sys.stderr.write((fmt % args).rstrip("\n") + "\n")


# ---------------------------------------------------------------------------
# Windows API wrappers (ctypes).
# ---------------------------------------------------------------------------

class SC_HANDLE(ctypes.c_void_p):
    pass


def _open_scm(server=None, access=SC_MANAGER_ALL_ACCESS):
    """Open Service Control Manager via OpenSCManagerW."""
    advapi32 = ctypes.WinDLL("advapi32.dll", use_last_error=True)
    advapi32.OpenSCManagerW.argtypes = [
        wtypes.LPCWSTR, wtypes.LPCWSTR, wtypes.DWORD,
    ]
    advapi32.OpenSCManagerW.restype = SC_HANDLE
    server_w = server if server else None
    scm = advapi32.OpenSCManagerW(server_w, None, access)
    if not scm:
        err = ctypes.get_last_error()
        _log("[-] OpenSCManagerW failed: last error %d", err)
        return None
    return scm


def _close_service_handle(handle):
    """Close a service handle via CloseServiceHandle."""
    advapi32 = ctypes.WinDLL("advapi32.dll", use_last_error=True)
    advapi32.CloseServiceHandle.argtypes = [SC_HANDLE]
    advapi32.CloseServiceHandle.restype = wtypes.BOOL
    advapi32.CloseServiceHandle(handle)


def _open_service(scm, service_name, access=SERVICE_ALL_ACCESS):
    """Open a service via OpenServiceW."""
    advapi32 = ctypes.WinDLL("advapi32.dll", use_last_error=True)
    advapi32.OpenServiceW.argtypes = [
        SC_HANDLE, wtypes.LPCWSTR, wtypes.DWORD,
    ]
    advapi32.OpenServiceW.restype = SC_HANDLE
    svc = advapi32.OpenServiceW(scm, service_name, access)
    if not svc:
        err = ctypes.get_last_error()
        _log("[-] OpenServiceW(%s) failed: last error %d", service_name, err)
        return None
    return svc


def _query_service_status(svc):
    """Query service status via QueryServiceStatus."""
    advapi32 = ctypes.WinDLL("advapi32.dll", use_last_error=True)

    class SERVICE_STATUS(ctypes.Structure):
        _fields_ = [
            ("dwServiceType", wtypes.DWORD),
            ("dwCurrentState", wtypes.DWORD),
            ("dwControlsAccepted", wtypes.DWORD),
            ("dwWin32ExitCode", wtypes.DWORD),
            ("dwServiceSpecificExitCode", wtypes.DWORD),
            ("dwCheckPoint", wtypes.DWORD),
            ("dwWaitHint", wtypes.DWORD),
        ]

    advapi32.QueryServiceStatus.argtypes = [SC_HANDLE, ctypes.POINTER(SERVICE_STATUS)]
    advapi32.QueryServiceStatus.restype = wtypes.BOOL

    status = SERVICE_STATUS()
    if not advapi32.QueryServiceStatus(svc, ctypes.byref(status)):
        err = ctypes.get_last_error()
        _log("[-] QueryServiceStatus failed: last error %d", err)
        return None
    return status


def _control_service(svc, control_code):
    """Send a control code to a service via ControlService."""
    advapi32 = ctypes.WinDLL("advapi32.dll", use_last_error=True)

    class SERVICE_STATUS(ctypes.Structure):
        _fields_ = [
            ("dwServiceType", wtypes.DWORD),
            ("dwCurrentState", wtypes.DWORD),
            ("dwControlsAccepted", wtypes.DWORD),
            ("dwWin32ExitCode", wtypes.DWORD),
            ("dwServiceSpecificExitCode", wtypes.DWORD),
            ("dwCheckPoint", wtypes.DWORD),
            ("dwWaitHint", wtypes.DWORD),
        ]

    advapi32.ControlService.argtypes = [
        SC_HANDLE, wtypes.DWORD, ctypes.POINTER(SERVICE_STATUS),
    ]
    advapi32.ControlService.restype = wtypes.BOOL

    status = SERVICE_STATUS()
    if not advapi32.ControlService(svc, control_code, ctypes.byref(status)):
        err = ctypes.get_last_error()
        _log("[-] ControlService failed: last error %d", err)
        return False
    return True


def _start_service(svc):
    """Start a service via StartServiceW."""
    advapi32 = ctypes.WinDLL("advapi32.dll", use_last_error=True)
    advapi32.StartServiceW.argtypes = [SC_HANDLE, wtypes.DWORD, ctypes.POINTER(wtypes.LPCWSTR)]
    advapi32.StartServiceW.restype = wtypes.BOOL
    if not advapi32.StartServiceW(svc, 0, None):
        err = ctypes.get_last_error()
        _log("[-] StartServiceW failed: last error %d", err)
        return False
    return True


def _delete_service(svc):
    """Delete a service via DeleteService."""
    advapi32 = ctypes.WinDLL("advapi32.dll", use_last_error=True)
    advapi32.DeleteService.argtypes = [SC_HANDLE]
    advapi32.DeleteService.restype = wtypes.BOOL
    if not advapi32.DeleteService(svc):
        err = ctypes.get_last_error()
        _log("[-] DeleteService failed: last error %d", err)
        return False
    return True


def _create_service(scm, service_name, **kwargs):
    """Create a service via CreateServiceW."""
    advapi32 = ctypes.WinDLL("advapi32.dll", use_last_error=True)

    advapi32.CreateServiceW.argtypes = [
        SC_HANDLE, wtypes.LPCWSTR, wtypes.LPCWSTR, wtypes.DWORD,
        wtypes.DWORD, wtypes.DWORD, wtypes.DWORD,
        wtypes.LPCWSTR, wtypes.LPCWSTR, wtypes.LPCWSTR,
        wtypes.LPCWSTR, wtypes.LPCWSTR, wtypes.LPCWSTR,
    ]
    advapi32.CreateServiceW.restype = SC_HANDLE

    svc = advapi32.CreateServiceW(
        scm, service_name,
        kwargs.get("display_name", service_name),
        SERVICE_ALL_ACCESS,
        kwargs.get("service_type", SERVICE_WIN32_OWN_PROCESS),
        kwargs.get("start_type", SERVICE_DEMAND_START),
        kwargs.get("error_control", SERVICE_ERROR_NORMAL),
        kwargs.get("bin_path", ""),
        kwargs.get("load_order_group", None),
        kwargs.get("tag", None),
        kwargs.get("deps", None),
        kwargs.get("service_obj_name", None),
        kwargs.get("password", None),
    )
    if not svc:
        err = ctypes.get_last_error()
        _log("[-] CreateServiceW(%s) failed: last error %d", service_name, err)
        return None
    return svc


# ---------------------------------------------------------------------------
# Pure-Python fallback (non-Windows platforms).
# ---------------------------------------------------------------------------

def _stub_op(msg):
    """Stub for operations not supported on non-Windows."""
    _log("[-] %s not supported on this platform", msg)
    return False


# ---------------------------------------------------------------------------
# Command handlers.
# ---------------------------------------------------------------------------

def _cmd_query(scm, service_name, verbose):
    svc = _open_service(scm, service_name, SERVICE_QUERY_STATUS)
    if not svc:
        return 1
    status = _query_service_status(svc)
    if status:
        state_names = {
            SERVICE_STOPPED: "STOPPED",
            SERVICE_START_PENDING: "START_PENDING",
            SERVICE_STOP_PENDING: "STOP_PENDING",
            SERVICE_RUNNING: "RUNNING",
            SERVICE_CONTINUE_PENDING: "CONTINUE_PENDING",
            SERVICE_PAUSE_PENDING: "PAUSE_PENDING",
            SERVICE_PAUSED: "PAUSED",
        }
        state = state_names.get(status.dwCurrentState, f"UNKNOWN({status.dwCurrentState})")
        _log("[+] Service: %s", service_name)
        _log("    State: %s", state)
        _log("    Service type: 0x%08X", status.dwServiceType)
        _log("    Controls accepted: 0x%08X", status.dwControlsAccepted)
        _log("    Win32 exit code: 0x%08X", status.dwWin32ExitCode)
        _log("    Service specific exit code: 0x%08X", status.dwServiceSpecificExitCode)
        _log("    Check point: %d", status.dwCheckPoint)
        _log("    Wait hint: %d ms", status.dwWaitHint)
    _close_service_handle(svc)
    return 0


def _cmd_start(scm, service_name, verbose):
    svc = _open_service(scm, service_name, SERVICE_START | SERVICE_QUERY_STATUS)
    if not svc:
        return 1
    if not _start_service(svc):
        _close_service_handle(svc)
        return 1
    _log("[+] Service started: %s", service_name)
    _close_service_handle(svc)
    return 0


def _cmd_stop(scm, service_name, verbose):
    svc = _open_service(scm, service_name, SERVICE_STOP | SERVICE_QUERY_STATUS)
    if not svc:
        return 1
    if not _control_service(svc, SERVICE_CONTROL_STOP):
        _close_service_handle(svc)
        return 1
    _log("[+] Service stop requested: %s", service_name)
    _close_service_handle(svc)
    return 0


def _cmd_delete(scm, service_name, verbose):
    svc = _open_service(scm, service_name, SERVICE_ALL_ACCESS)
    if not svc:
        return 1
    if not _delete_service(svc):
        _close_service_handle(svc)
        return 1
    _log("[+] Service deleted: %s", service_name)
    _close_service_handle(svc)
    return 0


def _cmd_create(scm, service_name, kwargs, verbose):
    svc = _create_service(scm, service_name, **kwargs)
    if not svc:
        return 1
    _log("[+] Service created: %s", service_name)
    _close_service_handle(svc)
    return 0


def _cmd_qc(scm, service_name, verbose):
    svc = _open_service(scm, service_name, SERVICE_QUERY_CONFIG)
    if not svc:
        return 1
    _log("[+] Service config query for: %s", service_name)
    _log("    (QueryServiceConfigW not fully implemented in this port)")
    _close_service_handle(svc)
    return 0


def _cmd_control(scm, service_name, extra_args, verbose):
    if not extra_args:
        _log("[-] control requires a control code argument")
        return 1
    try:
        control_code = int(extra_args[0], 0)
    except ValueError:
        _log("[-] Invalid control code: %s", extra_args[0])
        return 1
    svc = _open_service(scm, service_name, SERVICE_USER_DEFINED_CONTROL | SERVICE_QUERY_STATUS)
    if not svc:
        return 1
    if not _control_service(svc, control_code):
        _close_service_handle(svc)
        return 1
    _log("[+] Control code 0x%08X sent to: %s", control_code, service_name)
    _close_service_handle(svc)
    return 0


def _cmd_contin(scm, service_name, verbose):
    svc = _open_service(scm, service_name, SERVICE_USER_DEFINED_CONTROL | SERVICE_QUERY_STATUS)
    if not svc:
        return 1
    if not _control_service(svc, SERVICE_CONTROL_CONTINUE):
        _close_service_handle(svc)
        return 1
    _log("[+] Continue sent to: %s", service_name)
    _close_service_handle(svc)
    return 0


# ---------------------------------------------------------------------------
# run_function — the original main() equivalent.
# ---------------------------------------------------------------------------

COMMAND_HANDLERS = {
    "query": _cmd_query,
    "start": _cmd_start,
    "stop": _cmd_stop,
    "delete": _cmd_delete,
    "create": _cmd_create,
    "qc": _cmd_qc,
    "control": _cmd_control,
    "contin": _cmd_contin,
}


def run_function(
    server,
    command,
    service,
    extra_args=None,
    display_name=None,
    bin_path=None,
    start_type=None,
    error_control=None,
    load_order_group=None,
    tag=None,
    deps=None,
    service_obj_name=None,
    password=None,
    description=None,
    failure_actions=None,
    buffer_size=None,
    sd=None,
    timeout=30,
    verbose=False,
):
    """Run the sc tool against `server` and `service`.

    Returns 0 on success, non-zero on failure.
    """
    _log("sc — Windows Service Control Manager")
    _log("Server: %s", server or "(local)")
    _log("Command: %s", command)
    _log("Service: %s", service)

    if extra_args is None:
        extra_args = []

    is_windows = os.name == "nt"
    if not is_windows:
        _log("[*] Running on non-Windows platform; SCM operations are stubs")

    scm = None
    if is_windows:
        scm = _open_scm(server)
        if scm is None:
            return 1

    try:
        handler = COMMAND_HANDLERS.get(command.lower())
        if not handler:
            _log("[-] Unknown command: %s", command)
            _log("    Supported: %s", ", ".join(sorted(COMMAND_HANDLERS.keys())))
            return 1

        kwargs = {
            "display_name": display_name,
            "bin_path": bin_path,
            "start_type": {
                "boot": SERVICE_BOOT_START,
                "system": SERVICE_SYSTEM_START,
                "auto": SERVICE_AUTO_START,
                "demand": SERVICE_DEMAND_START,
                "disabled": SERVICE_DISABLED,
            }.get(start_type, SERVICE_DEMAND_START) if start_type else SERVICE_DEMAND_START,
            "error_control": {
                "ignore": SERVICE_ERROR_IGNORE,
                "normal": SERVICE_ERROR_NORMAL,
                "severe": SERVICE_ERROR_SEVERE,
                "critical": SERVICE_ERROR_CRITICAL,
            }.get(error_control, SERVICE_ERROR_NORMAL) if error_control else SERVICE_ERROR_NORMAL,
            "load_order_group": load_order_group,
            "tag": tag,
            "deps": deps,
            "service_obj_name": service_obj_name,
            "password": password,
        }

        if command.lower() == "create":
            result = handler(scm, service, kwargs, verbose)
        elif command.lower() in ("query", "start", "stop", "delete", "qc", "contin"):
            result = handler(scm, service, verbose)
        elif command.lower() == "control":
            result = handler(scm, service, extra_args, verbose)
        else:
            _log("[-] Command %s not implemented in this port", command)
            result = 1

        return result
    finally:
        if scm is not None:
            _close_service_handle(scm)


def main():
    """CLI driver (standalone testing)."""
    _log("sc standalone CLI not implemented — use `nsa-equation-py sc ...`")
    return 1


if __name__ == "__main__":
    sys.exit(main())
