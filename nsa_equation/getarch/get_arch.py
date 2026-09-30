#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
get_arch.py — Python rewrite of the `getArch` OS-architecture detector.

Binary analysis (via IDA Pro + PyInstaller archive recovery) of
`getArch.exe`:

    getArch.exe  is a PyInstaller 2.1 bundle (Python 2.7).
    entry point   -> getArch.pyc  (the embedded `getArch.py` script)

The recovered `getArch.py` is an impacket example.  `TARGETARCH.run()`
probes each host over the RPC Endpoint Mapper (ncacn_ip_tcp, TCP 135) and
binds the portmapper UUID (`MSRPC_UUID_PORTMAP`) *using the NDR64 transfer
syntax* (`71710533-BEBA-4937-8319-B5DBEF9CCC36 / 1.0`):

    64-bit Windows    accepts NDR64          -> BIND_ACK result = accept  -> "64-bit"
    32-bit Windows    no NDR64               -> BIND_ACK result = reject,
                                               reason = proposed_transfer_syntaxes_not_supported
                                                                          -> "32-bit"

This module reproduces that behaviour in portable, dependency-free Python.
It builds a single DCERPC BIND packet by hand, sends it to TCP 135, and
classifies the BIND_ACK / BIND_NAK response.  No impacket is required.

The NDR64-presentation heuristic is a read-only architectural probe; no
state is modified on the target.
"""

import socket
import struct
import sys

# ---------------------------------------------------------------------------
# DCERPC / endpoint-mapper constants.
# ---------------------------------------------------------------------------
PORT = 135                     # RPC Endpoint Mapper default port

# Abstract syntax UUID bound: the RPC Endpoint Mapper, version 3.0.
#   string form  E1AF8308-5D1F-11C9-91A4-08002B14A0FA / 3.0
#   binary form  Data1/2/3 little-endian + Data4 raw + version 3.0.
PORTMAP_UUID = bytes.fromhex("0883afe11f5dc91191a408002b14a0fa03000000")

# Transfer syntax presented: NDR64, version 1.0.
#   string form  71710533-BEBA-4937-8319-B5DBEF9CCC36 / 1.0
NDR64_UUID = bytes.fromhex("33057171babe37498319b5dbef9ccc3601000000")

# DCERPC packet types (connection-oriented).
RPC_BIND    = 0x0B
RPC_BINDACK = 0x0C
RPC_BINDNAK = 0x0D
RPC_FAULT   = 0x03

PFC_FIRST_FRAG = 0x01
PFC_LAST_FRAG  = 0x02

# Presentation-context negotiation results (CtxItemResult.Result).
CTX_ACCEPT        = 0
CTX_USER_REJECT   = 1
CTX_PROV_REJECT   = 2

# Provider reject reasons (CtxItemResult.Reason).
REASON_ABSTRACT_SYN_NOT_SUPPORTED     = 1
REASON_TRANSFER_SYN_NOT_SUPPORTED     = 2

MAX_FRAG = 4280                       # max_xmit/recv frag negotiated

DEFAULT_TIMEOUT = 2.0                 # connect + read timeout (seconds)


def log(fmt, *args):
    """printf-style logger (matches the legacy codebase)."""
    sys.stderr.write((fmt % args).rstrip("\n") + "\n")


# ---------------------------------------------------------------------------
# build_bind_request — the single DCERPC BIND packet sent to TCP 135.
#
# Reconstructed from impacket's `MSRPCHeader` + `MSRPCBind` + `CtxItem`
# (what `getArch.py` sent via `dce.bind(MSRPC_UUID_PORTMAP,
# transfer_syntax=NDR64Syntax)`), as a flat 72-byte buffer.
#
#   common header (16 bytes)
#     +0x00  ver_major   5
#     +0x01  ver_minor   0
#     +0x02  type        BIND (0x0B)
#     +0x03  flags       FIRST | LAST (0x03)
#     +0x04  repr        packed_drep little-endian (0x10)
#     +0x08  frag_len    72
#     +0x0a  auth_len    0
#     +0x0c  call_id     1
#
#   bind PDU (12 + 44 = 56 bytes)
#     +0x10  max_xmit_frag  4280
#     +0x12  max_recv_frag  4280
#     +0x14  assoc_group    0
#     +0x18  ctx_num        1
#     +0x19  reserved       0
#     +0x1a  reserved2      0
#     +0x1c  p_ctx_id       0
#     +0x1e  n_trans_syn    1
#     +0x1f  pad            0
#     +0x20  abstract_syntax  PORTMAP_UUID   (20 bytes)
#     +0x34  transfer_syntax  NDR64_UUID     (20 bytes)
# ---------------------------------------------------------------------------
def build_bind_request(call_id=1):
    ctx_item = struct.pack("<HBB", 0, 1, 0) + PORTMAP_UUID + NDR64_UUID
    bind_pdu = struct.pack("<HHLBBH", MAX_FRAG, MAX_FRAG, 0, 1, 0, 0) + ctx_item
    header = struct.pack("<BBBBIHHI", 5, 0, RPC_BIND,
                         PFC_FIRST_FRAG | PFC_LAST_FRAG, 0x10,
                         16 + len(bind_pdu), 0, call_id)
    return header + bind_pdu


# ---------------------------------------------------------------------------
# recv_packet — read one full DCERPC packet off the connected TCP socket.
# ---------------------------------------------------------------------------
class ProtocolError(Exception):
    """Raised when the peer does not return a well-formed RPC response."""


def recv_packet(sock, timeout=DEFAULT_TIMEOUT):
    sock.settimeout(timeout)
    header = sock.recv(16)
    if len(header) < 16:
        raise ProtocolError("short/closed DCERPC header (%d bytes)" % len(header))
    frag_len = struct.unpack_from("<H", header, 8)[0]
    pkt = header
    while len(pkt) < frag_len:
        chunk = sock.recv(frag_len - len(pkt))
        if not chunk:
            break
        pkt += chunk
    return pkt


# ---------------------------------------------------------------------------
# classify_response — turn a BIND reply into an architecture verdict.
#
#   C (getArch.py):  try:  dce.bind(MSRPC_UUID_PORTMAP, transfer_syntax=NDR64)
#                    except DCERPCException as e:
#                        if 'syntaxes_not_supported' in str(e):  -> 32-bit
#                    else:                                       -> 64-bit
#
# The equivalent raw-signal decision: a BIND_ACK whose presentation context
# is accepted => NDR64 supported => 64-bit; a BIND_ACK whose context is
# rejected because the *transfer syntax* is unsupported => 32-bit.
# ---------------------------------------------------------------------------
def classify_response(pkt):
    ptype = pkt[2] if len(pkt) >= 3 else None

    if ptype == RPC_BINDACK:
        # max_tfrag(2) max_rfrag(2) assoc_group(4) SecondaryAddrLen(2)
        # SecondaryAddr(SecondaryAddrLen) Pad(ctx items 4-aligned) then
        # ctx_num(1) Reserved(1) Reserved2(2) then ctx items (24 each).
        sec_len = struct.unpack_from("<H", pkt, 24)[0]
        off = 26 + sec_len
        off += (4 - (off % 4)) % 4                 # align ctx list to 4 bytes
        ctx_num = pkt[off]
        if ctx_num < 1:
            return "64-bit"  # NDR64 accepted (no rejection listed)
        ctx_off = off + 4
        result, reason = struct.unpack_from("<HH", pkt, ctx_off)
        if result == CTX_ACCEPT:
            return "64-bit"
        if result == CTX_PROV_REJECT and reason == REASON_TRANSFER_SYN_NOT_SUPPORTED:
            return "32-bit"  # proposed_transfer_syntaxes_not_supported
        return "unknown (%s/%s)" % (result, reason)

    if ptype == RPC_BINDNAK:
        # The abstract syntax itself was rejected; unexpected for the
        # endpoint mapper, surface it rather than guess.
        raise ProtocolError("BIND_NAK (abstract syntax not supported)")

    if ptype == RPC_FAULT:
        raise ProtocolError("RPC fault during bind")

    raise ProtocolError("unexpected DCERPC packet type: %r" % ptype)


# ---------------------------------------------------------------------------
# detect_arch — probe a single host (the C `TARGETARCH.run` inner loop).
# ---------------------------------------------------------------------------
def detect_arch(host, timeout=DEFAULT_TIMEOUT):
    """Return '64-bit' or '32-bit' for `host`, or raise on failure.

    Raises OSError if the target is unreachable, ProtocolError if the peer
    does not return a well-formed BIND reply.
    """
    sock = socket.create_connection((host, PORT), timeout=timeout)
    try:
        sock.sendall(build_bind_request())
        pkt = recv_packet(sock, timeout)
    finally:
        sock.close()
    return classify_response(pkt)


# ---------------------------------------------------------------------------
# run_function — the entry called by the recovered `TARGETARCH.run()`.
# ---------------------------------------------------------------------------
def run_function(targets, timeout=DEFAULT_TIMEOUT):
    """Probe each target and report its OS architecture (32- vs 64-bit)."""
    machines = list(targets) if targets else []
    log("Gathering OS architecture for %d machine(s)", len(machines))
    log("Socket connect timeout set to %s secs", timeout)

    for machine in machines:
        try:
            verdict = detect_arch(machine, timeout)
            log("%s is %s", machine, verdict)
        except (OSError, ProtocolError) as e:
            log("[!] - %s: %s", machine, e)
    return 0


def main():
    """CLI driver (mirrors the original getArch.py `if __name__ == '__main__'`)."""
    args = sys.argv[1:]
    target = None
    targets = []
    timeout = DEFAULT_TIMEOUT
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-target",) and i + 1 < len(args):
            target = args[i + 1]; i += 2; continue
        if a in ("-targets",) and i + 1 < len(args):
            try:
                with open(args[i + 1], "r") as f:
                    targets = [ln.strip(" \r\n") for ln in f if ln.strip()]
            except OSError as e:
                log("[!] - cannot read targets file: %s", e)
                return 1
            i += 2; continue
        if a in ("-timeout",) and i + 1 < len(args):
            timeout = float(args[i + 1]); i += 2; continue
        if a == "-debug":
            i += 1; continue
        if a in ("-h", "--help"):
            log("usage: %s -target <host> | -targets <file> [-timeout secs]",
                sys.argv[0])
            return 0
        i += 1

    if target is None and not targets:
        log("[!] - you have to specify a target (-target or -targets)")
        return 1
    if target is not None:
        targets.insert(0, target)
    return run_function(targets, timeout)


if __name__ == "__main__":
    sys.exit(main())
