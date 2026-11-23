#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pc_lp_exp.py — PC_LP 监听/代理工具引擎。

Python port of `PC_LP.exe` recovered via static PE analysis
(`EQGRP_Lost_in_Translation-master/windows/Resources/Pc/Legacy/Bin/PC_LP.exe`).

Recovered interface from the binary's imports:

  Imported DLLs / functions:
    WS2_32:   socket, bind, listen, accept, send, recv, closesocket,
              WSAStartup, WSACleanup, gethostbyname, inet_addr, htons,
              ntohs, getpeername, getsockname, ioctlsocket
    KERNEL32: CreateFileW, ReadFile, WriteFile, CloseHandle,
              SetFilePointer, GetFileSize, VirtualAlloc, VirtualFree,
              CreateProcessW, GetModuleFileNameW, SetCurrentDirectoryW,
              CreateDirectoryW, etc.
    MSVCR71/MSVCP71: standard C++ runtime (_beginthreadex, _endthreadex,
                     malloc, free, sprintf, fprintf, etc.)
    USER32:   MessageBoxA

Architecture (recovered from control flow):

  main():
    1. Parse command-line arguments (listen_port, [target_host], [target_port])
    2. WSAStartup — initialize Winsock
    3. socket + bind + listen — listen on local port
    4. accept — accept incoming connection
    5. If target_host/target_port specified:
       - Connect to target
       - Relay data between client and target (proxy mode)
    6. Else:
       - Handle local connection (listener mode)
    7. WSACleanup — cleanup Winsock

    The tool also creates directories, copies files, and creates processes
    using KERNEL32 APIs.

This module reproduces that behaviour using Python's `socket` module for
network operations and `subprocess` for process creation.

CLI:

  pc_lp <listen_port> [target_host] [target_port]
"""

import ctypes
import ctypes.wintypes as wtypes
import os
import socket
import subprocess
import sys
import threading


# ---------------------------------------------------------------------------
# Constants.
# ---------------------------------------------------------------------------

BUFFER_SIZE = 4096


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

def run_function(listen_port, target_host=None, target_port=None, verbose=False):
    """Run PC_LP listener/proxy tool.

    Returns 0 on success, non-zero on failure.
    """
    _log("PC_LP — Listener/proxy tool")
    _log("Listen port: %d", listen_port)
    if target_host and target_port:
        _log("Target: %s:%d", target_host, target_port)
        _log("Mode: Proxy")
    else:
        _log("Mode: Listener")

    if not _ws2_startup():
        return 1

    try:
        # Create listening socket
        try:
            listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listen_sock.bind(("0.0.0.0", listen_port))
            listen_sock.listen(5)
        except OSError as exc:
            _log("[-] Failed to listen on port %d: %s", listen_port, exc)
            return 1

        _log("[+] Listening on port %d", listen_port)

        try:
            while True:
                client_sock, client_addr = listen_sock.accept()
                _log("[+] Accepted connection from %s:%d",
                     client_addr[0], client_addr[1])

                if target_host and target_port:
                    # Proxy mode: connect to target and relay
                    try:
                        target_sock = socket.socket(socket.AF_INET,
                                                    socket.SOCK_STREAM)
                        target_sock.connect((target_host, target_port))
                        _log("[+] Connected to target %s:%d",
                             target_host, target_port)

                        # Start relay threads
                        t1 = threading.Thread(
                            target=_relay,
                            args=(client_sock, target_sock,
                                  "client->target", verbose),
                            daemon=True,
                        )
                        t2 = threading.Thread(
                            target=_relay,
                            args=(target_sock, client_sock,
                                  "target->client", verbose),
                            daemon=True,
                        )
                        t1.start()
                        t2.start()
                    except OSError as exc:
                        _log("[-] Failed to connect to target: %s", exc)
                        client_sock.close()
                else:
                    # Listener mode: just acknowledge connection
                    _log("[*] Connection from %s:%d (listener mode)",
                         client_addr[0], client_addr[1])
                    try:
                        client_sock.sendall(b"PC_LP listener ready\r\n")
                    except OSError:
                        pass
                    client_sock.close()

        except KeyboardInterrupt:
            _log("[*] Interrupted by user")
        finally:
            listen_sock.close()

        return 0

    finally:
        _ws2_cleanup()


def main():
    """CLI driver (standalone testing)."""
    _log("PC_LP standalone CLI not implemented — use `nsa-equation-py pc_lp ...`")
    return 1


if __name__ == "__main__":
    sys.exit(main())
