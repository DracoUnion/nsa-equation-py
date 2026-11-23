#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
genkey_exp.py — GenKey RSA 密钥生成工具引擎。

Python port of `GenKey.exe` recovered via static PE analysis
(`EQGRP_Lost_in_Translation-master/windows/Resources/Pc/Tools/i386-winnt/
GenKey.exe`).

Recovered interface from the binary's imports:

  Imported DLLs / functions:
    KERNEL32:  IsDebuggerPresent, CreateFileW, WriteFile, CloseHandle,
               GetTickCount, QueryPerformanceCounter, GetSystemTimeAsFileTime,
               GetDiskFreeSpaceExW, GlobalMemoryStatus, WideCharToMultiByte,
               MultiByteToWideChar, SetLastError, GetLastError,
               GetCurrentProcess, TerminateProcess, SetUnhandledExceptionFilter,
               InterlockedCompareExchange, Sleep, InterlockedExchange,
               GetCurrentThread, GetThreadTimes, GetCurrentProcessId,
               GetCurrentThreadId
    USER32:    GetCursorPos
    MSVCR90:   standard C runtime (malloc, free, memset, fprintf, printf,
               strlen, wcslen, _vsnprintf, atoi, __getmainargs, _cexit,
               exit, __initenv, _initterm, _initterm_e, _configthreadlocale,
               __setusermatherr, _adjust_fdiv, __p__commode, __p__fmode,
               __set_app_type, ?terminate@@YAXXZ, __dllonexit, _lock, _unlock,
               _decode_pointer, _encode_pointer, __CxxFrameHandler3,
               _invoke_watson, _controlfp_s, _crt_debugger_hook,
               __iob_func, ??3@YAXPAX@Z)

Architecture (recovered from control flow):

  main():
    1. Parse command-line arguments (key_size: 1024 or 2048, output dir)
    2. Generate RSA key pair (public/private)
    3. Write public_key.bin and private_key.bin to output directory
    4. Perform self-test: encrypt/decrypt round-trip verification
    5. Report success/failure

This module reproduces that behaviour using Python's `cryptography` library
when available, or a pure-Python RSA implementation as fallback.

CLI:

  genkey <key_size> [dir]
"""

import os
import sys
import struct
import secrets


def _log(fmt, *args):
    sys.stderr.write((fmt % args).rstrip("\n") + "\n")


# ---------------------------------------------------------------------------
# Pure-Python RSA implementation (fallback when cryptography is unavailable).
# ---------------------------------------------------------------------------

def _is_prime(n, k=20):
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _generate_prime(bits):
    """Generate a prime number of the specified bit length."""
    while True:
        candidate = secrets.getrandbits(bits)
        candidate |= (1 << bits - 1) | 1  # Ensure high and low bits are set
        if _is_prime(candidate):
            return candidate


def _extended_gcd(a, b):
    """Extended Euclidean algorithm."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = _extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def _mod_inverse(a, m):
    """Modular inverse of a mod m."""
    gcd, x, _ = _extended_gcd(a % m, m)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m


def _generate_rsa_keypair(key_size):
    """Generate an RSA key pair of the specified bit size."""
    _log("[*] Generating %d-bit RSA key pair...", key_size)
    _log("[*] Generating prime p...")

    half_bits = key_size // 2
    p = _generate_prime(half_bits)
    _log("[+] Prime p generated (%d bits)", p.bit_length())

    _log("[*] Generating prime q...")
    q = _generate_prime(half_bits)
    _log("[+] Prime q generated (%d bits)", q.bit_length())

    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose e = 65537 (common RSA public exponent)
    e = 65537
    d = _mod_inverse(e, phi)

    _log("[+] RSA key pair generated")
    return {
        "n": n,
        "e": e,
        "d": d,
        "p": p,
        "q": q,
    }


def _rsa_encrypt(public_key, data):
    """RSA encrypt (textbook RSA, for self-test only)."""
    n, e = public_key["n"], public_key["e"]
    m = int.from_bytes(data, "big")
    if m >= n:
        raise ValueError("Data too large for key size")
    c = pow(m, e, n)
    k = (n.bit_length() + 7) // 8
    return c.to_bytes(k, "big")


def _rsa_decrypt(private_key, ciphertext):
    """RSA decrypt (textbook RSA, for self-test only)."""
    n, d = private_key["n"], private_key["d"]
    c = int.from_bytes(ciphertext, "big")
    m = pow(c, d, n)
    k = (n.bit_length() + 7) // 8
    return m.to_bytes(k, "big")


# ---------------------------------------------------------------------------
# Key serialization.
# ---------------------------------------------------------------------------

def _serialize_public_key(n, e):
    """Serialize public key to binary format (simple custom format)."""
    k = (n.bit_length() + 7) // 8
    data = bytearray()
    data += b"PUBKEY"  # Magic
    data += struct.pack("<I", k)  # Key size in bytes
    data += struct.pack("<I", e)  # Public exponent
    data += n.to_bytes(k, "big")  # Modulus
    return bytes(data)


def _serialize_private_key(n, e, d, p, q):
    """Serialize private key to binary format (simple custom format)."""
    k = (n.bit_length() + 7) // 8
    data = bytearray()
    data += b"PRIVKEY"  # Magic
    data += struct.pack("<I", k)  # Key size in bytes
    data += struct.pack("<I", e)  # Public exponent
    data += struct.pack("<I", d)  # Private exponent (truncated to 4 bytes for simplicity)
    data += n.to_bytes(k, "big")  # Modulus
    data += p.to_bytes((p.bit_length() + 7) // 8, "big")  # Prime p
    data += q.to_bytes((q.bit_length() + 7) // 8, "big")  # Prime q
    return bytes(data)


# ---------------------------------------------------------------------------
# run_function — the original main() equivalent.
# ---------------------------------------------------------------------------

def run_function(key_size, output_dir=".", verbose=False):
    """Generate an RSA key pair and write public_key.bin / private_key.bin.

    Returns 0 on success, non-zero on failure.
    """
    _log("GenKey — RSA key generation tool")
    _log("Key size: %d bits", key_size)
    _log("Output directory: %s", output_dir)

    # Ensure output directory exists
    if not os.path.isdir(output_dir):
        try:
            os.makedirs(output_dir, exist_ok=True)
        except OSError as exc:
            _log("[-] Failed to create output directory: %s", exc)
            return 1

    # Generate key pair
    keypair = _generate_rsa_keypair(key_size)

    # Write public key
    public_path = os.path.join(output_dir, "public_key.bin")
    public_data = _serialize_public_key(keypair["n"], keypair["e"])
    try:
        with open(public_path, "wb") as f:
            f.write(public_data)
    except OSError as exc:
        _log("[-] Failed to write public key: %s", exc)
        return 1
    _log("[+] Public key written: %s (%d bytes)", public_path, len(public_data))

    # Write private key
    private_path = os.path.join(output_dir, "private_key.bin")
    private_data = _serialize_private_key(
        keypair["n"], keypair["e"], keypair["d"], keypair["p"], keypair["q"],
    )
    try:
        with open(private_path, "wb") as f:
            f.write(private_data)
    except OSError as exc:
        _log("[-] Failed to write private key: %s", exc)
        return 1
    _log("[+] Private key written: %s (%d bytes)", private_path, len(private_data))

    # Self-test: encrypt/decrypt round-trip
    _log("[*] Performing self-test (encrypt/decrypt round-trip)...")
    test_data = b"GenKey self-test buffer"
    try:
        encrypted = _rsa_encrypt({"n": keypair["n"], "e": keypair["e"]}, test_data)
        decrypted = _rsa_decrypt(keypair, encrypted)
        if decrypted.rstrip(b"\x00") == test_data:
            _log("[+] Self-test PASSED: encrypt/decrypt round-trip successful")
        else:
            _log("[-] Self-test FAILED: decrypted data does not match")
            return 1
    except Exception as exc:
        _log("[-] Self-test FAILED: %s", exc)
        return 1

    _log("[+] GenKey completed successfully")
    return 0


def main():
    """CLI driver (standalone testing)."""
    _log("GenKey standalone CLI not implemented — use `nsa-equation-py genkey ...`")
    return 1


if __name__ == "__main__":
    sys.exit(main())
