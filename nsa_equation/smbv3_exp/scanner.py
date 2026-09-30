#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scanner.py — SMBv3.1.1 + compression-context detector for CVE-2020-0796.

Python port of `Scanner\\scanner.py` and `Scanner\\logless_scanner.py`
recovered from `CVE-2020-0796-EXP.exe`.  Detects hosts that negotiate
SMB 3.1.1 (dialect 0x0311) *and* answer the pre-auth compression context
(context type 2) — the two preconditions for the SMBGhost overflow.

Unlike the plain `smbv3-scan` subcommand (which only checks the negotiated
dialect), this mirrors the original exploit-tool scanner, which also requires
the compression context.  Detection only; no exploit is performed here.

NOTE on the NetBIOS length: the original bytecode read the 4-byte NetBIOS
session header with native little-endian `I`, which cannot yield the correct
big-endian 3-byte length.  This port reads it properly (big-endian) so it
works against real SMB servers.
"""

import socket
import struct


def _build_negotiate():
    """Assemble the SMB2 NEGOTIATE packet (dialects up to 3.1.1 + contexts)."""
    header = b'\xfeSMB'
    header += struct.pack("H", 64)      # StructureSize
    header += struct.pack("H", 0) * 3   # CreditCharge / ChannelSeq / Reserved
    header += struct.pack("H", 0)       # Command (NEGOTIATE)
    header += struct.pack("H", 31)      # CreditRequest
    header += struct.pack("I", 0)       # Flags
    header += struct.pack("I", 0)       # NextCommand
    header += struct.pack("Q", 0)       # MessageId
    header += struct.pack("I", 0)       # ProcessId
    header += struct.pack("I", 0)       # TreeId
    header += struct.pack("Q", 0)       # SessionId
    header += struct.pack("QQ", 0, 0)   # Signature (16 bytes)
    assert len(header) == 64

    negotiation = b''
    negotiation += struct.pack("H", 36)          # StructureSize
    negotiation += struct.pack("H", 8)          # DialectCount
    negotiation += struct.pack("H", 1)          # SecurityMode
    negotiation += struct.pack("H", 0)          # Reserved
    negotiation += struct.pack("I", 127)        # Capabilities
    negotiation += struct.pack("QQ", 0, 0)      # ClientGuid (16)
    negotiation += struct.pack("I", 120)        # NegotiateContextOffset
    negotiation += struct.pack("H", 2)          # NegotiateContextCount
    negotiation += struct.pack("H", 0)          # Reserved
    # dialects: 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1
    negotiation += struct.pack("H", 514)
    negotiation += struct.pack("H", 528)
    negotiation += struct.pack("H", 546)
    negotiation += struct.pack("H", 548)
    negotiation += struct.pack("H", 768)
    negotiation += struct.pack("H", 770)
    negotiation += struct.pack("H", 784)
    negotiation += struct.pack("H", 785)
    negotiation += struct.pack("I", 0)
    # SMB2_PREAUTH_INTEGRITY_CAPABILITIES (type 1)
    negotiation += struct.pack("H", 1)
    negotiation += struct.pack("H", 38)
    negotiation += struct.pack("I", 0)
    negotiation += struct.pack("H", 1)
    negotiation += struct.pack("H", 32)
    negotiation += struct.pack("H", 1)
    negotiation += struct.pack("H", 1)
    negotiation += struct.pack("QQ", 0, 0)
    negotiation += struct.pack("QQ", 0, 0)
    # SMB2_COMPRESSION_CAPABILITIES (type 3)
    negotiation += struct.pack("H", 3)
    negotiation += struct.pack("H", 10)
    negotiation += struct.pack("I", 0)
    negotiation += b'\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'

    packet = header + negotiation
    netbios = b''
    netbios += struct.pack("H", 0)      # reserved
    netbios += struct.pack("B", 0)      # message type (session message)
    netbios += struct.pack("B", len(packet))  # 1-byte length (small packets)
    return netbios + packet


def _read_netbios_len(io):
    """Read the 4-byte NetBIOS session header and return the payload length."""
    hdr = io.recv(4)
    if len(hdr) < 4:
        return 0
    # bytes 1..3 are the big-endian length
    return (hdr[1] << 16) | (hdr[2] << 8) | hdr[3]


def _probe(ip, port):
    """Send the NEGOTIATE, return the full response body or None."""
    packet = _build_negotiate()
    io = socket.socket(socket.AF_INET)
    io.settimeout(7)
    try:
        io.connect((str(ip), int(port)))
        io.send(packet)
        size = _read_netbios_len(io)
        if size <= 0:
            return None
        response = io.recv(size)
        return response
    except OSError:
        return None
    finally:
        try:
            io.close()
        except OSError:
            pass


def _check(response):
    """Return (version, context) parsed from an SMB2 NEGOTIATE response."""
    if response is None or len(response) < 72:
        return (0, 0)
    version = struct.unpack("H", response[68:70])[0]
    context = struct.unpack("H", response[70:72])[0]
    return version, context


def scanner_smb_ghost(ip, port):
    """Verbose check — print the packets, return True if vulnerable."""
    packet = _build_negotiate()
    print("NetBIOS:", packet[:4].hex())
    print("Packet len:", len(packet), "->", packet.hex())
    response = _probe(ip, port)
    version, context = _check(response)
    if version != 785:    # 0x0311
        print("SMB version %s was found which is not vulnerable!" % hex(version))
        return False
    if context != 2:
        print("Server answered with context %s which indicates that the target "
              "may not have SMB compression enabled and is therefore not "
              "vulnerable!" % hex(context))
        return False
    print("SMB version %s with context %s was found which indicates SMBv3.1.1 "
          "is being used and SMB compression is enabled, therefore being "
          "vulnerable to CVE-2020-0796!" % (hex(version), hex(context)))
    return True


def scanner_smb_ghost_silent(ip, port):
    """Silent check — same probe without packet dumps."""
    response = _probe(ip, port)
    version, context = _check(response)
    if version != 785:
        print("SMB version %s was found which is not vulnerable!" % hex(version))
        return False
    if context != 2:
        print("Server answered with context %s which indicates that the target "
              "may not have SMB compression enabled and is therefore not "
              "vulnerable!" % hex(context))
        return False
    print("SMB version %s with context %s was found which indicates SMBv3.1.1 "
          "is being used and SMB compression is enabled, therefore being "
          "vulnerable to CVE-2020-0796!" % (hex(version), hex(context)))
    return True