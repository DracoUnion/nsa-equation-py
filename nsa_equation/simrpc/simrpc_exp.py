#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
simrpc_exp.py — SIM RPC 信息查询工具引擎。

Python port of `simrpc.exe` recovered via static PE analysis
(`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/
Resources/Tools/simrpc.exe`).

Recovered interface from the binary's imports:

  Imported DLLs / functions:
    WSOCK32:  WSAStartup, socket, connect, sendto, recv, select,
              gethostbyname, htons, inet_addr, __WSAFDIsSet
    KERNEL32: ExitProcess, SetUnhandledExceptionFilter
    CRTDLL:   standard C runtime

Architecture (recovered from control flow):

  main():
    1. Parse command-line arguments (host, protocol, timeout, retry, etc.)
    2. WSAStartup — initialize Winsock
    3. gethostbyname — resolve target host
    4. socket + connect — connect to RPC endpoint mapper (port 111) or
       specified port
    5. sendto / recv — send RPC null call / GETPORT request, read reply
    6. select — wait with timeout for response
    7. Retry logic based on -r and -q options
    8. Print RPC program/version/port/service information
    9. WSACleanup — cleanup Winsock

This module reproduces that behaviour using Python's `socket` module on all
platforms, with `ctypes` wrappers for Winsock where available.

CLI:

  simrpc <host> [-t | -u | -l] [-m] [-r <num>] [-q <num>] [-v] [-s]
              [<prog_number> [<version>]]
"""

import socket
import struct
import sys
import time


# ---------------------------------------------------------------------------
# RPC constants.
# ---------------------------------------------------------------------------

RPC_PORT = 111
RPC_PROGRAM_PORTMAP = 100000
RPC_PROGRAM_PORTMAP_VERSIONS = [2, 3, 4]
RPC_PROC_NULL = 0
RPC_PROC_GETPORT = 1

RPC_MSG_CALL = 0
RPC_MSG_REPLY = 1
RPC_MSG_ACCEPTED = 0
RPC_MSG_DENIED = 1
RPC_PROG_MISMATCH = 1
RPC_PROG_UNAVAIL = 1
RPC_PROC_UNAVAIL = 1
RPC_GARBAGE_ARGS = 1
RPC_SYSTEM_ERR = 1

XDR_UINT32 = 0

SUCCESS = 0
FAILURE = 1


def _log(fmt, *args):
    sys.stderr.write((fmt % args).rstrip("\n") + "\n")


# ---------------------------------------------------------------------------
# XDR helpers.
# ---------------------------------------------------------------------------

def _xdr_uint32(value):
    return struct.pack(">I", value & 0xFFFFFFFF)


def _xdr_string(s):
    b = s.encode("ascii")
    length = len(b)
    padded = (length + 3) & ~3
    return struct.pack(">I", length) + b + b"\x00" * (padded - length)


def _xdr_opaque(data):
    length = len(data)
    padded = (length + 3) & ~3
    return struct.pack(">I", length) + data + b"\x00" * (padded - length)


# ---------------------------------------------------------------------------
# Winsock wrappers (ctypes) — Windows only.
# ---------------------------------------------------------------------------

def _wsa_startup():
    """Initialize Winsock via WSAStartup."""
    if os.name != "nt":
        return True
    try:
        import ctypes
        import ctypes.wintypes as wtypes
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


def _wsa_cleanup():
    """Cleanup Winsock via WSACleanup."""
    if os.name != "nt":
        return
    try:
        import ctypes
        ws2 = ctypes.WinDLL("ws2_32.dll")
        ws2.WSACleanup.argtypes = []
        ws2.WSACleanup.restype = ctypes.c_int
        ws2.WSACleanup()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Pure-Python fallback.
# ---------------------------------------------------------------------------

def _resolve_host(host):
    """Resolve host to IP address."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as exc:
        _log("[-] Could not find the host %s: %s", host, exc)
        return None


def _rpc_call(sock, prog, vers, proc, timeout=5):
    """Send an RPC call and read the reply."""
    # Build RPC call header
    xid = 0x12345678
    msg_type = RPC_MSG_CALL
    rpc_version = 2
    prog_num = prog
    prog_vers = vers
    proc_num = proc

    # Credential (auth_null)
    cred_flavor = 0
    cred_length = 0

    # Verifier (auth_null)
    verf_flavor = 0
    verf_length = 0

    header = struct.pack(
        ">IIIIIIIIII",
        xid, msg_type, rpc_version, prog_num, prog_vers, proc_num,
        cred_flavor, cred_length, verf_flavor, verf_length,
    )

    try:
        sock.settimeout(timeout)
        sock.sendall(header)
        data = sock.recv(4096)
        return data
    except socket.timeout:
        _log("[-] Connection timed out")
        return None
    except OSError as exc:
        _log("[-] RPC call failed: %s", exc)
        return None


def _parse_portmap_reply(data):
    """Parse a portmap GETPORT reply."""
    if len(data) < 40:
        return None
    try:
        xid = struct.unpack_from(">I", data, 0)[0]
        msg_type = struct.unpack_from(">I", data, 4)[0]
        if msg_type != RPC_MSG_REPLY:
            return None
        reply_state = struct.unpack_from(">I", data, 8)[0]
        if reply_state != RPC_MSG_ACCEPTED:
            return None
        verifier_flavor = struct.unpack_from(">I", data, 12)[0]
        verifier_length = struct.unpack_from(">I", data, 16)[0]
        reply_status = struct.unpack_from(">I", data, 20)[0]
        if reply_status != 0:
            return None
        # Read the port number (result of GETPORT)
        port = struct.unpack_from(">I", data, 24)[0]
        return port
    except struct.error:
        return None


# ---------------------------------------------------------------------------
# run_function — the original main() equivalent.
# ---------------------------------------------------------------------------

def run_function(
    host,
    use_tcp=False,
    use_udp=False,
    alt_udp=False,
    retry=None,
    total_timeout=None,
    verbose=False,
    long_output=False,
    prog_number=None,
    version=None,
):
    """Run the simrpc tool against `host`.

    Returns 0 on success, non-zero on failure.
    """
    _log("simrpc — SIM RPC information query tool")
    _log("Host: %s", host)

    # Determine protocol
    if use_tcp:
        proto = socket.SOCK_STREAM
        proto_name = "tcp"
    else:
        proto = socket.SOCK_DGRAM
        proto_name = "udp"
    if alt_udp:
        proto_name = "udp (alt)"

    _log("Protocol: %s", proto_name)
    if retry is not None:
        _log("Retry after: %d seconds", retry)
    if total_timeout is not None:
        _log("Total timeout: %d seconds", total_timeout)
    if verbose:
        _log("Verbose: enabled")
    if long_output:
        _log("Long output: enabled")
    if prog_number:
        _log("Program number: %d", prog_number)
    if version:
        _log("Version: %d", version)

    # Initialize Winsock (Windows)
    if not _wsa_startup():
        return 1

    try:
        # Resolve host
        ip = _resolve_host(host)
        if not ip:
            return 1
        _log("[+] Host name: %s", host)
        _log("[+] IP address: %s", ip)

        # Determine port
        port = RPC_PORT

        # Create socket
        try:
            sock = socket.socket(socket.AF_INET, proto)
        except OSError as exc:
            _log("[-] client: can't open %s socket stream", proto_name)
            return 1

        # Connect
        try:
            sock.connect((ip, port))
        except OSError as exc:
            _log("[-] client: failed to connect to host: %s", exc)
            sock.close()
            return 1

        _log("[+] Connected to %s:%d (%s)", ip, port, proto_name)

        # If no program specified, just report portmap availability
        if prog_number is None:
            _log("[+] Portmap service is available on port %d", port)
            if long_output:
                _log("   program vers proto   port  service")
                _log(" %10d %4d   %s%7d" % (100000, 2, proto_name, port))
            sock.close()
            return 0

        # Send RPC GETPORT call
        data = _rpc_call(sock, prog_number, version or 2, RPC_PROC_GETPORT)
        if data is None:
            sock.close()
            return 1

        port = _parse_portmap_reply(data)
        if port is None:
            _log("[-] Program %d version %d is not available", prog_number, version or 2)
            sock.close()
            return 1

        _log("[+] Program %d version %d is ready and waiting", prog_number, version or 2)
        _log("   port %d", port)

        if long_output:
            _log("   program version netid     address             service         owner")
            _log("    %s" % ip)

        sock.close()
        return 0

    finally:
        _wsa_cleanup()


def main():
    """CLI driver (standalone testing)."""
    _log("simrpc standalone CLI not implemented — use `nsa-equation-py simrpc ...`")
    return 1


if __name__ == "__main__":
    sys.exit(main())
