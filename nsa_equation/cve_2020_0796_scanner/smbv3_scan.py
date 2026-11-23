#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
smbv3_scan.py — Python rewrite of the CVE-2020-0796 (SMBGhost) scanner logic.

Binary analysis (via IDA Pro + PyInstaller archive recovery) of
`CVE-2020-0796-Scanner.exe`:

    main  (PyInstaller bootstrap, 0x401000)  ->  smb_poc.run_function(subnet)

The packed native module `smb_poc.pyd` receives a target (single IP or subnet)
and reports whether each reachable SMB host negotiates the SMB 3.1.1 dialect —
the trigger surface for CVE-2020-0796 (a buffer overflow in the SMBv3.1.1
compression handler, AKA *SMBGhost*).

This module reproduces that behaviour in portable, dependency-free Python:

  1. expands the CLI target(s) into a list of IPv4 addresses,
  2. opens a TCP connection to the SMB port (445),
  3. sends an SMB2 NEGOTIATE request advertising dialects up to SMB 3.1.1,
  4. parses the negotiated dialect out of the NEGOTIATE response,
  5. flags hosts that negotiate 0x0311 (SMB 3.1.1) as potentially affected.

No exploit is performed — this is detection/scanning only.

Observed in the original (via x32dbg memory dump of the packed module): the
native scanner also links WTSAPI32 (`WTSSendMessageW`) — it can send a
terminal-services popup message to sessions, a post-scan/messaging behaviour
kept out of this detection-only rewrite.
"""

import ipaddress
import socket
import struct
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

# ---------------------------------------------------------------------------
# SMB2 protocol constants.
# ---------------------------------------------------------------------------
SMB_DIALECT_0202 = 0x0202   # SMB 2.0.2
SMB_DIALECT_0210 = 0x0210   # SMB 2.1
SMB_DIALECT_0300 = 0x0300   # SMB 3.0
SMB_DIALECT_0302 = 0x0302   # SMB 3.0.2
SMB_DIALECT_0311 = 0x0311   # SMB 3.1.1  <- CVE-2020-0796 trigger surface

SMB2_COMMAND_NEGOTIATE = 0x0000

SMB2_NEGOTIATE_STRUCT_SIZE = 36
DEFAULT_PORT = 445
SMB_PROTOCOL_ID = b"\xfeSMB"
RECV_CHUNK = 4096

# SecurityMode: SMB2_NEGOTIATE_SIGNING_ENABLED (0x0002).
SECURITY_MODE = 0x0002
# Capabilities advertised by the client (SMB2_GLOBAL_CAP_DFS | ... ).
CAPABILITIES = 0x00000027


def log(fmt, *args):
    """printf-style logger (matches the behaviour of the leged codebase)."""
    sys.stderr.write((fmt % args).rstrip("\n") + "\n")


# ---------------------------------------------------------------------------
# sub_scan_one — negotiate SMB with a single host and pull out its dialect.
#
#   C (smb_poc):  int scan_host(const char *ip, int port)
#                 -> 0 no-SMB / closed, otherwise the negotiated dialect
# ---------------------------------------------------------------------------
def build_negotiate_request(dialects):
    """Assemble an SMB2 NEGOTIATE request that offers `dialects`.

    Layout (native, little-endian):

    header (64 bytes)
      +0x00  UINT32  ProtocolId     '\xfeSMB'
      +0x04  UINT16  StructureSize  64
      +0x06  UINT16  CreditCharge   0
      +0x08  UINT32  ChannelSeq     0
      +0x0c  UINT16  Command        SMB2_NEGOTIATE
      +0x0e  UINT16  CreditRequest  1
      +0x10  UINT32  Flags          0
      +0x14  UINT32  NextCommand    0
      +0x18  UINT64  MessageId      0
      +0x20  UINT32  ProcessId      (arbitrary)
      +0x24  UINT32  TreeId         0
      +0x28  UINT64  SessionId      0
      +0x30  128-bit Signature      0

    body (36 bytes)
      +0x40  UINT16  StructureSize  36
      +0x42  UINT16  DialectCount
      +0x44  UINT16  SecurityMode   0x0002 (signing enabled)
      +0x46  UINT16  Reserved       0
      +0x48  UINT32  Capabilities   0x27
      +0x4c  GUID    ClientGuid     (16 bytes)
      +0x5c  UINT64  ClientStartTime 0

    dialects:  DialectCount * UINT16, immediately after the 36-byte body.
    """
    header = struct.pack(
        "<4sHHI H H I I Q I I Q 16s",
        SMB_PROTOCOL_ID,
        64,                # StructureSize
        0,                 # CreditCharge
        0,                 # ChannelSequence
        SMB2_COMMAND_NEGOTIATE,
        1,                 # CreditRequest
        0,                 # Flags
        0,                 # NextCommand
        0,                 # MessageId
        0xFEFF,            # ProcessId             (arbitrary non-zero)
        0,                 # TreeId
        0,                 # SessionId
        b"\x00" * 16,      # Signature
    )
    assert len(header) == 64

    body = struct.pack(
        "<HHHHI16sQ",
        SMB2_NEGOTIATE_STRUCT_SIZE,
        len(dialects),
        SECURITY_MODE,
        0,                 # Reserved
        CAPABILITIES,
        b"\x00" * 16,      # ClientGuid
        0,                 # ClientStartTime
    )
    assert len(body) == SMB2_NEGOTIATE_STRUCT_SIZE

    dialbytes = b"".join(struct.pack("<H", d) for d in dialects)
    return header + body + dialbytes


def parse_negotiated_dialect(response, offset=0):
    """Extract the DialectRevision (UINT16) from an SMB2 NEGOTIATE response.

    The response header is 64 bytes; the NEGOTIATE body starts right after:

      +0x40  UINT16  StructureSize
      +0x42  UINT16  SecurityMode
      +0x44  UINT16  DialectRevision     <-- we read this
    """
    if len(response) < offset + 0x46:
        return 0
    return struct.unpack_from("<H", response, offset + 0x44)[0]


def is_negotiate_response(response):
    """Accept only a well-formed SMB2 header / NEGOTIATE response."""
    return (len(response) >= 64
            and response[0:4] == SMB_PROTOCOL_ID
            and struct.unpack_from("<H", response, 0x04)[0] == 64)


# ---------------------------------------------------------------------------
# sub_scan_host — the per-host probe (C: `scan_host`).
# ---------------------------------------------------------------------------
def scan_host(host, port=DEFAULT_PORT, timeout=3.0):
    """Return the negotiated SMB dialect for `host`, or a status sentinel.

      0x0000 / 0      no SMB service or connection failed
      0xFFFF          port open but no SMB negotiate response
      otherwise       the negotiated dialect (e.g. 0x0311)
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
    except OSError:
        s.close()
        return 0
    try:
        s.sendall(build_negotiate_request(
            [SMB_DIALECT_0202, SMB_DIALECT_0210,
             SMB_DIALECT_0300, SMB_DIALECT_0302, SMB_DIALECT_0311],
        ))
        response = s.recv(RECV_CHUNK)
        while not is_negotiate_response(response):
            try:
                more = s.recv(RECV_CHUNK)
            except socket.timeout:
                break
            if not more:
                break
            response += more
            if len(response) >= RECV_CHUNK * 4:
                break
        if not response:
            return 0xFFFF
        if not is_negotiate_response(response):
            return 0xFFFF
        return parse_negotiated_dialect(response)
    except OSError:
        return 0
    finally:
        try:
            s.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Return codes for run_function: (status, dialect).
# ---------------------------------------------------------------------------
def classify(dialect):
    """Map a negotiated dialect to a human-readable verdict."""
    if dialect == SMB_DIALECT_0311:
        # Windows 10 1903/1909/2004 + Server 1903/1909 — CVE-2020-0796 surface.
        return "SMB 3.1.1 (potentially vulnerable to CVE-2020-0796 / SMBGhost)"
    if dialect == SMB_DIALECT_0302:
        return "SMB 3.0.2"
    if dialect == SMB_DIALECT_0300:
        return "SMB 3.0"
    if dialect == SMB_DIALECT_0210:
        return "SMB 2.1"
    if dialect == SMB_DIALECT_0202:
        return "SMB 2.0.2"
    if dialect == 0xFFFF:
        return "SMB port open, no valid negotiate response"
    return "no SMB service / unreachable"


def expand_targets(raw_targets):
    """Expand CLI targets (IPs and CIDR subnets) into a list of addresses."""
    hosts = []
    for target in raw_targets:
        try:
            for ip in ipaddress.ip_network(target, strict=False).hosts():
                hosts.append(str(ip))
        except ValueError:
            # not a network — treat as a bare address if it parses
            try:
                hosts.append(str(ipaddress.ip_address(target)))
            except ValueError:
                log("[!] - skipping invalid target: %s", target)
    # de-duplicate while preserving order
    seen = set()
    out = []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


# ---------------------------------------------------------------------------
# run_function — the entry called by the original `main` with a subnet arg.
#
#   C (main.pyc):  smb_poc.run_function(subnet)
# ---------------------------------------------------------------------------
def run_function(targets, port=DEFAULT_PORT, timeout=3.0, threads=32):
    """Scan targets and report each reachable SMB host's negotiated dialect."""
    hosts = expand_targets(targets)
    if not hosts:
        log("[!] - no valid targets supplied")
        return 0

    log("[.] - scanning %d host(s) on port %d ...", len(hosts), port)

    results = []

    def _work(host):
        dialect = scan_host(host, port, timeout)
        if dialect:                      # skip non-SMB / unreachable hosts
            results.append((host, dialect))

    with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        list(pool.map(_work, hosts))

    for host, dialect in sorted(results):
        what = classify(dialect)
        if dialect == SMB_DIALECT_0311:
            log("[!] - %-16s %s", host, what)
        elif dialect in (SMB_DIALECT_0302, SMB_DIALECT_0300):
            log("[*] - %-16s %s", host, what)
        else:
            log("[ ] - %-16s %s", host, what)

    vulnerable = sum(1 for _, d in results if d == SMB_DIALECT_0311)
    log("[.] - done; %d host(s) negotiate SMB 3.1.1 (CVE-2020-0796 surface)",
        vulnerable)
    return vulnerable


def main():
    """CLI driver (sgates straight to run_function, mirroring the C entry)."""
    hexpand = []
    args = sys.argv[1:]
    port, timeout, threads = DEFAULT_PORT, 3.0, 32
    targets = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-p", "--port") and i + 1 < len(args):
            port = int(args[i + 1]); i += 2; continue
        if a in ("-t", "--timeout") and i + 1 < len(args):
            timeout = float(args[i + 1]); i += 2; continue
        if a in ("-n", "--threads") and i + 1 < len(args):
            threads = int(args[i + 1]); i += 2; continue
        if a.startswith("-") and a not in ("-h", "--help"):
            log("[!] - unknown option: %s", a); i += 1; continue
        targets.append(a); i += 1
    if not targets:
        log("usage: %s <target|subnet> [-p port] [-t timeout] [-n threads]",
            sys.argv[0])
        return 1
    run_function(targets, port=port, timeout=timeout, threads=threads)
    return 0


if __name__ == "__main__":
    main()