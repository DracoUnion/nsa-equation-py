#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
w9xpopen_exp.py — Windows 95/98 popen workaround tool engine.

Python port of `w9xpopen.exe` recovered via static PE analysis
(`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/
Exploits/EAFU 2.2.0/EAFU_SSL_exe/w9xpopen.exe`).

Recovered interface from the binary's imports:

  Imported DLLs / functions:
    KERNEL32:  CreateProcessA, WaitForSingleObject, GetExitCodeProcess,
               CloseHandle, GetFileType, GetStdHandle, GetModuleHandleA
    USER32:    MessageBoxA
    MSVCR71:   standard C runtime

Architecture (recovered from control flow):

  main():
    1. Parse command-line arguments (the command to run + its args)
    2. If no args: print "Internal popen error - no args specified" and exit
    3. GetModuleHandleA / GetStartupInfoW — prepare process creation
    4. GetStdHandle / GetFileType — retrieve standard handles for redirection
    5. CreateProcessA — create the child process with inherited handles
    6. WaitForSingleObject — wait for the child process to exit (INFINITE)
    7. GetExitCodeProcess — retrieve the child's exit code
    8. CloseHandle — close process and thread handles
    9. If error: MessageBoxA — show error dialog
    10. ExitProcess with the child's exit code

This module reproduces that behaviour using Python's `subprocess` module on
all platforms, with `ctypes` wrappers for the Windows API where available.

CLI:

  w9xpopen <command> [args...] [--show-errors]
"""

import ctypes
import ctypes.wintypes as wtypes
import os
import subprocess
import sys


# ---------------------------------------------------------------------------
# Windows API constants.
# ---------------------------------------------------------------------------

CREATE_NEW_CONSOLE = 0x00000010
CREATE_NO_WINDOW = 0x08000000
INFINITE = 0xFFFFFFFF
STD_INPUT_HANDLE = -10
STD_OUTPUT_HANDLE = -11
STD_ERROR_HANDLE = -12

MB_OK = 0x00000000
MB_ICONERROR = 0x00000010


def _log(fmt, *args):
    sys.stderr.write((fmt % args).rstrip("\n") + "\n")


# ---------------------------------------------------------------------------
# Windows API wrappers (ctypes).
# ---------------------------------------------------------------------------

def _show_message_box(title, message):
    """Show a Windows message box via MessageBoxA."""
    user32 = ctypes.WinDLL("user32.dll", use_last_error=True)
    user32.MessageBoxA.argtypes = [
        wtypes.HWND, wtypes.LPCSTR, wtypes.LPCSTR, wtypes.UINT,
    ]
    user32.MessageBoxA.restype = wtypes.INT
    user32.MessageBoxA(None, message.encode("ascii", "replace"),
                       title.encode("ascii", "replace"),
                       MB_OK | MB_ICONERROR)


def _get_std_handle(std_id):
    """Get a standard handle via GetStdHandle."""
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    kernel32.GetStdHandle.argtypes = [ctypes.c_uint]
    kernel32.GetStdHandle.restype = wtypes.HANDLE
    return kernel32.GetStdHandle(std_id)


def _get_file_type(handle):
    """Get the type of a file handle via GetFileType."""
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    kernel32.GetFileType.argtypes = [wtypes.HANDLE]
    kernel32.GetFileType.restype = ctypes.c_uint
    return kernel32.GetFileType(handle)


# ---------------------------------------------------------------------------
# Pure-Python fallback.
# ---------------------------------------------------------------------------

def _show_message_box_fallback(title, message):
    """Print error message to stderr (fallback for non-Windows)."""
    sys.stderr.write(f"[{title}] {message}\n")


# ---------------------------------------------------------------------------
# run_function — the original main() equivalent.
# ---------------------------------------------------------------------------

def run_function(command, args=None, show_errors=False):
    """Run `command` with `args`, wait for completion, return exit code.

    Returns the child process's exit code, or non-zero on failure.
    """
    if args is None:
        args = []

    _log("w9xpopen — Windows 95/98 popen workaround")
    _log("Command: %s", command)
    if args:
        _log("Args: %s", " ".join(args))

    # Build the full command line.
    cmdline = [command] + list(args)

    # Validate: the original prints "Internal popen error - no args specified"
    # if no command is given.
    if not command:
        _log("[-] Internal popen error - no args specified")
        if show_errors:
            _show_message_box("w9xpopen", "Internal popen error - no args specified")
            _show_message_box_fallback("w9xpopen", "Internal popen error - no args specified")
        return 1

    try:
        # Get standard handles for inheritance (mirrors GetStdHandle/GetFileType).
        if os.name == "nt":
            stdin_handle = _get_std_handle(STD_INPUT_HANDLE)
            stdout_handle = _get_std_handle(STD_OUTPUT_HANDLE)
            stderr_handle = _get_std_handle(STD_ERROR_HANDLE)
            _log("[*] stdin handle: 0x%08X", stdin_handle)
            _log("[*] stdout handle: 0x%08X", stdout_handle)
            _log("[*] stderr handle: 0x%08X", stderr_handle)

        # Create the child process (mirrors CreateProcessA).
        _log("[*] Creating process...")
        proc = subprocess.Popen(
            cmdline,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=CREATE_NO_WINDOW if os.name == "nt" else 0,
        )

        # Wait for the child process to exit (mirrors WaitForSingleObject).
        _log("[*] Waiting for process to exit...")
        proc.wait()

        # Get the exit code (mirrors GetExitCodeProcess).
        exit_code = proc.returncode
        _log("[+] Process exited with code: %d", exit_code)

        # Close handles (mirrors CloseHandle — handled by subprocess).
        try:
            proc.stdout.close()
            proc.stderr.close()
            proc.stdin.close()
        except OSError:
            pass

        return exit_code

    except FileNotFoundError:
        _log("[-] Command not found: %s", command)
        if show_errors:
            _show_message_box("w9xpopen", f"Command not found: {command}")
            _show_message_box_fallback("w9xpopen", f"Command not found: {command}")
        return 1
    except PermissionError:
        _log("[-] Permission denied: %s", command)
        if show_errors:
            _show_message_box("w9xpopen", f"Permission denied: {command}")
            _show_message_box_fallback("w9xpopen", f"Permission denied: {command}")
        return 1
    except OSError as exc:
        _log("[-] Failed to create process: %s", exc)
        if show_errors:
            _show_message_box("w9xpopen", f"Failed to create process: {exc}")
            _show_message_box_fallback("w9xpopen", f"Failed to create process: {exc}")
        return 1


def main():
    """CLI driver (standalone testing)."""
    _log("w9xpopen standalone CLI not implemented — "
         "use `nsa-equation-py w9xpopen ...`")
    return 1


if __name__ == "__main__":
    sys.exit(main())
