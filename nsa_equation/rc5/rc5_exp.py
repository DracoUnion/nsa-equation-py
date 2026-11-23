#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rc5_exp.py — RC5 加密/解密工具引擎。

Python port of `rc5.exe` recovered via static PE analysis
(`EQGRP_Lost_in_Translation-master/windows/Resources/ST1.14/Tools/rc5.exe`).

Recovered interface from the binary's imports:

  Imported DLLs / functions:
    KERNEL32:  EnterCriticalSection, LeaveCriticalSection,
               GetCommandLineA, HeapSetInformation, TerminateProcess,
               GetCurrentProcess, UnhandledExceptionFilter, IsDebuggerPresent,
               EncodePointer, DecodePointer, HeapAlloc, RaiseException,
               SetHandleCount, GetStdHandle, InitializeCriticalSectionAndSpinCount,
               GetFileType, GetStartupInfoW, DeleteCriticalSection, Sleep,
               GetLastError, HeapFree, GetProcAddress, GetModuleHandleW,
               ExitProcess, WriteFile, GetModuleFileNameW, GetModuleFileNameA,
               FreeEnvironmentStringsW, WideCharToMultiByte,
               GetEnvironmentStringsW, TlsAlloc, TlsGetValue, TlsSetValue,
               TlsFree, InterlockedIncrement, SetLastError,
               GetCurrentThreadId, InterlockedDecrement, HeapCreate,
               QueryPerformanceCounter, GetTickCount, GetCurrentProcessId,
               GetSystemTimeAsFileTime, HeapSize, GetCPInfo, GetACP,
               GetOEMCP, IsValidCodePage, MultiByteToWideChar, RtlUnwind,
               HeapReAlloc, LoadLibraryW, GetConsoleCP, GetConsoleMode,
               FlushFileBuffers, IsProcessorFeaturePresent, LCMapStringW,
               GetStringTypeW, ReadFile, SetFilePointer, CloseHandle,
               WriteConsoleW, SetStdHandle, CreateFileW
    USER32:    wsprintfW, MessageBoxW
    MSVCRT:    wcscpy, wcscmp, wcsstr, swprintf, _CxxThrowException,
               _vsnwprintf, ftell, fseek, malloc, fread, strncmp,
               strstr, isspace, fopen, fwrite, fclose, fprintf, wcslen,
               __CxxFrameHandler, printf, free, _wcsdup

Architecture (recovered from control flow):

  main():
    1. Parse command-line arguments (mode: d/e, session_key, ciphertext)
    2. Validate mode (d for decrypt, e for encrypt)
    3. Decrypt/encrypt using RC5 algorithm
    4. Print result

This module reproduces that behaviour using Python's cryptography
(or pure-Python RC5 implementation) where available.

CLI:

  rc5 <d|e> <session_key> <ciphertext>
"""

import ctypes
import ctypes.wintypes as wtypes
import os
import sys


# ---------------------------------------------------------------------------
# Constants.
# ---------------------------------------------------------------------------

RC5_W = 32  # Word size in bits
RC5_R = 12  # Number of rounds
RC5_P = 0xB7E15163  # P constant for 32-bit RC5
RC5_Q = 0x9E3779B9  # Q constant for 32-bit RC5


def _log(fmt, *args):
    sys.stderr.write((fmt % args).rstrip("\n") + "\n")


# ---------------------------------------------------------------------------
# RC5 implementation.
# ---------------------------------------------------------------------------

def _left_rotate(value, shift, width=32):
    """Left rotate a 32-bit value."""
    shift &= width - 1
    return ((value << shift) | (value >> (width - shift))) & 0xFFFFFFFF


def _right_rotate(value, shift, width=32):
    """Right rotate a 32-bit value."""
    shift &= width - 1
    return ((value >> shift) | (value << (width - shift))) & 0xFFFFFFFF


def _rc5_key_schedule(key):
    """Generate RC5 round keys."""
    w = 32  # Word size in bits
    r = 12  # Number of rounds
    b = len(key)  # Key length in bytes
    u = w // 8  # Word size in bytes
    c = max(1, b // u)  # Number of words in key
    t = 2 * (r + 1)  # Number of round keys

    # Initialize key array
    L = [0] * c
    for i in range(b - 1, -1, -1):
        L[i // u] = (L[i // u] << 8) + key[i]

    # Initialize S array
    S = [0] * t
    S[0] = RC5_P
    for i in range(1, t):
        S[i] = (S[i - 1] + RC5_Q) & 0xFFFFFFFF

    # Mix key into S
    i = j = 0
    A = B = 0
    for k in range(3 * max(c, t)):
        A = S[i] = _left_rotate(S[i] + A + B, 3)
        B = L[j] = _left_rotate(L[j] + A + B, A + B)
        i = (i + 1) % t
        j = (j + 1) % c

    return S


def _rc5_encrypt_block(plaintext, S):
    """Encrypt a single 8-byte block."""
    A = int.from_bytes(plaintext[0:4], "little")
    B = int.from_bytes(plaintext[4:8], "little")
    A = (A + S[0]) & 0xFFFFFFFF
    B = (B + S[1]) & 0xFFFFFFFF
    for i in range(1, 13):  # r = 12 rounds
        A = _left_rotate(A ^ B, B) + S[2 * i]
        B = _left_rotate(B ^ A, A) + S[2 * i + 1]
    return A.to_bytes(4, "little") + B.to_bytes(4, "little")


def _rc5_decrypt_block(ciphertext, S):
    """Decrypt a single 8-byte block."""
    A = int.from_bytes(ciphertext[0:4], "little")
    B = int.from_bytes(ciphertext[4:8], "little")
    for i in range(12, 0, -1):
        B = _right_rotate(B - S[2 * i + 1], A) ^ A
        A = _right_rotate(A - S[2 * i], B) ^ B
    A = (A - S[0]) & 0xFFFFFFFF
    B = (B - S[1]) & 0xFFFFFFFF
    return A.to_bytes(4, "little") + B.to_bytes(4, "little")


def _rc5_encrypt(plaintext, key):
    """Encrypt plaintext using RC5."""
    # Pad plaintext to 8-byte boundary
    pad_len = 8 - (len(plaintext) % 8)
    if pad_len == 0:
        pad_len = 8
    plaintext = plaintext + b"\x00" * pad_len

    S = _rc5_key_schedule(key)
    result = bytearray()
    for i in range(0, len(plaintext), 8):
        block = plaintext[i:i+8]
        result.extend(_rc5_encrypt_block(block, S))
    return bytes(result)


def _rc5_decrypt(ciphertext, key):
    """Decrypt ciphertext using RC5."""
    S = _rc5_key_schedule(key)
    result = bytearray()
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]
        result.extend(_rc5_decrypt_block(block, S))
    return bytes(result)


# ---------------------------------------------------------------------------
# run_function — the original main() equivalent.
# ---------------------------------------------------------------------------

def run_function(mode, session_key, ciphertext, verbose=False):
    """Run RC5 encryption/decryption.

    Returns 0 on success, non-zero on failure.
    """
    _log("RC5 — RC5 encryption/decryption tool")
    _log("Mode: %s", "Decrypt" if mode == "d" else "Encrypt")
    _log("Session key: %s", session_key)
    _log("Ciphertext: %s", ciphertext)

    # Decode session key from hex
    try:
        key = bytes.fromhex(session_key)
    except ValueError:
        _log("[-] Invalid session key (not hex): %s", session_key)
        return 1

    # Decode ciphertext from hex
    try:
        ciphertext_bytes = bytes.fromhex(ciphertext)
    except ValueError:
        _log("[-] Invalid ciphertext (not hex): %s", ciphertext)
        return 1

    # Decrypt or encrypt
    if mode == "d":
        try:
            result = _rc5_decrypt(ciphertext_bytes, key)
        except Exception as exc:
            _log("[-] Decryption failed: %s", exc)
            return 1
    else:  # "e"
        result = _rc5_encrypt(ciphertext_bytes, key)

    _log("[+] Result: %s", result.hex())
    _log("[+] Result (text): %s", result.decode("latin-1", errors="replace"))
    return 0


def main():
    """CLI driver (standalone testing)."""
    _log("RC5 standalone CLI not implemented — use `nsa-equation-py rc5 ...`")
    return 1


if __name__ == "__main__":
    sys.exit(main())
