# -*- coding: utf-8 -*-
"""
dave.posh — POSH 字节序转换（big/little endian 读写）。

对应 DLL：posh-0.dll（31 个导出函数）。

函数命名与原二进制导出表保持一致，方便与 IDA 还原的调用点对照：
  POSH_Read{U|I}{16|32|64}From{Big|Little}
  POSH_Write{U|I}{16|32|64}To{Big|Little}
  POSH_Swap{U|I}{16|32|64}
  POSH_GetArchString
"""

import struct
import sys


# ---------------------------------------------------------------------------
# Read helpers (little-endian host assumed by Python struct '<')
# ---------------------------------------------------------------------------

def POSH_ReadU16FromLittle(buf, off=0):
    return struct.unpack_from("<H", buf, off)[0]


def POSH_ReadU16FromBig(buf, off=0):
    return struct.unpack_from(">H", buf, off)[0]


def POSH_ReadI16FromLittle(buf, off=0):
    return struct.unpack_from("<h", buf, off)[0]


def POSH_ReadI16FromBig(buf, off=0):
    return struct.unpack_from(">h", buf, off)[0]


def POSH_ReadU32FromLittle(buf, off=0):
    return struct.unpack_from("<I", buf, off)[0]


def POSH_ReadU32FromBig(buf, off=0):
    return struct.unpack_from(">I", buf, off)[0]


def POSH_ReadI32FromLittle(buf, off=0):
    return struct.unpack_from("<i", buf, off)[0]


def POSH_ReadI32FromBig(buf, off=0):
    return struct.unpack_from(">i", buf, off)[0]


def POSH_ReadU64FromLittle(buf, off=0):
    return struct.unpack_from("<Q", buf, off)[0]


def POSH_ReadU64FromBig(buf, off=0):
    return struct.unpack_from(">Q", buf, off)[0]


def POSH_ReadI64FromLittle(buf, off=0):
    return struct.unpack_from("<q", buf, off)[0]


def POSH_ReadI64FromBig(buf, off=0):
    return struct.unpack_from(">q", buf, off)[0]


# ---------------------------------------------------------------------------
# Write helpers
# ---------------------------------------------------------------------------

def POSH_WriteU16ToLittle(buf, off, val):
    struct.pack_into("<H", buf, off, val & 0xFFFF)


def POSH_WriteU16ToBig(buf, off, val):
    struct.pack_into(">H", buf, off, val & 0xFFFF)


def POSH_WriteI16ToLittle(buf, off, val):
    struct.pack_into("<h", buf, off, val)


def POSH_WriteI16ToBig(buf, off, val):
    struct.pack_into(">h", buf, off, val)


def POSH_WriteU32ToLittle(buf, off, val):
    struct.pack_into("<I", buf, off, val & 0xFFFFFFFF)


def POSH_WriteU32ToBig(buf, off, val):
    struct.pack_into(">I", buf, off, val & 0xFFFFFFFF)


def POSH_WriteI32ToLittle(buf, off, val):
    struct.pack_into("<i", buf, off, val)


def POSH_WriteI32ToBig(buf, off, val):
    struct.pack_into(">i", buf, off, val)


def POSH_WriteU64ToLittle(buf, off, val):
    struct.pack_into("<Q", buf, off, val & 0xFFFFFFFFFFFFFFFF)


def POSH_WriteU64ToBig(buf, off, val):
    struct.pack_into(">Q", buf, off, val & 0xFFFFFFFFFFFFFFFF)


def POSH_WriteI64ToLittle(buf, off, val):
    struct.pack_into("<q", buf, off, val)


def POSH_WriteI64ToBig(buf, off, val):
    struct.pack_into(">q", buf, off, val)


# ---------------------------------------------------------------------------
# Swap helpers
# ---------------------------------------------------------------------------

def POSH_SwapU16(val):
    return ((val & 0xFF) << 8) | ((val >> 8) & 0xFF)


def POSH_SwapI16(val):
    return POSH_SwapU16(val) & 0xFFFF


def POSH_SwapU32(val):
    return (
        ((val & 0xFF) << 24)
        | ((val & 0xFF00) << 8)
        | ((val >> 8) & 0xFF00)
        | ((val >> 24) & 0xFF)
    ) & 0xFFFFFFFF


def POSH_SwapI32(val):
    return POSH_SwapU32(val)


def POSH_SwapU64(val):
    v = val & 0xFFFFFFFFFFFFFFFF
    return (
        ((v & 0xFF) << 56)
        | ((v & 0xFF00) << 40)
        | ((v & 0xFF0000) << 24)
        | ((v & 0xFF000000) << 8)
        | ((v >> 8) & 0xFF000000)
        | ((v >> 24) & 0xFF0000)
        | ((v >> 40) & 0xFF00)
        | ((v >> 56) & 0xFF)
    )


def POSH_SwapI64(val):
    return POSH_SwapU64(val)


# ---------------------------------------------------------------------------
# Architecture string
# ---------------------------------------------------------------------------

def POSH_GetArchString():
    """Return host architecture string (mirrors original behavior)."""
    if sys.maxsize > 2 ** 32:
        return "x64"
    return "x86"
