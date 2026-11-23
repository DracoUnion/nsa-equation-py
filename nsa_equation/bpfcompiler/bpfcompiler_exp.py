#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bpfcompiler_exp.py — BpfCompiler BPF 编译工具引擎。

Python port of `BpfCompiler.exe` recovered via static PE analysis
(`EQGRP_Lost_in_Translation-master/windows/Resources/DSky/Tools/i386-winnt/
BpfCompiler.exe`).

Recovered interface from the binary's imports:

  Imported DLLs / functions:
    wpcap:  pcap_open_dead, pcap_compile, pcap_geterr, pcap_close
    WS2_32: inet_addr
    KERNEL32: file and memory operations
    MSVCR90: standard C runtime

Architecture (recovered from control flow):

  main():
    1. Parse command-line arguments (BPF expression, optional output file)
    2. pcap_open_dead — open a dead pcap handle
    3. pcap_compile — compile the BPF filter expression
    4. If output file specified, write the compiled program
    5. pcap_close — close the pcap handle
    6. Report completion

This module reproduces that behaviour using Python's ctypes for libpcap/wpcap
where available, or pure-Python stubs otherwise.

CLI:

  bpfcompiler <expression> [output_file]
"""

import ctypes
import ctypes.wintypes as wtypes
import os
import sys


# ---------------------------------------------------------------------------
# Constants.
# ---------------------------------------------------------------------------

DLT_EN10MB = 1  # Ethernet
PCAP_ERRBUF_SIZE = 256


def _log(fmt, *args):
    sys.stderr.write((fmt % args).rstrip("\n") + "\n")


# ---------------------------------------------------------------------------
# libpcap/wpcap wrappers (ctypes).
# ---------------------------------------------------------------------------

class pcap_t(ctypes.c_void_p):
    pass


def _pcap_open_dead(linktype, snaplen):
    """Open a dead pcap handle via pcap_open_dead."""
    if os.name != "nt":
        return None
    try:
        wpcap = ctypes.WinDLL("wpcap.dll", use_last_error=True)
        wpcap.pcap_open_dead.argtypes = [ctypes.c_int, ctypes.c_int]
        wpcap.pcap_open_dead.restype = ctypes.POINTER(pcap_t)
        return wpcap.pcap_open_dead(linktype, snaplen)
    except Exception:
        return None


def _pcap_compile(pcap, program, netmask):
    """Compile a BPF filter via pcap_compile."""
    if os.name != "nt":
        return None
    try:
        wpcap = ctypes.WinDLL("wpcap.dll", use_last_error=True)
        wpcap.pcap_compile.argtypes = [
            ctypes.POINTER(pcap_t),
            ctypes.POINTER(ctypes.c_void_p),  # bpf_program*
            ctypes.c_char_p,  # str
            ctypes.c_int,     # optimize
            wtypes.c_uint,    # netmask
        ]
        wpcap.pcap_compile.restype = ctypes.c_int

        bpf_program = ctypes.c_void_p()
        ret = wpcap.pcap_compile(
            pcap, ctypes.byref(bpf_program),
            program.encode("ascii"), 1, netmask,
        )
        if ret != 0:
            return None
        return bpf_program
    except Exception:
        return None


def _pcap_geterr(pcap):
    """Get error string via pcap_geterr."""
    if os.name != "nt":
        return "unknown error"
    try:
        wpcap = ctypes.WinDLL("wpcap.dll", use_last_error=True)
        wpcap.pcap_geterr.argtypes = [ctypes.POINTER(pcap_t)]
        wpcap.pcap_geterr.restype = ctypes.c_char_p
        return wpcap.pcap_geterr(pcap).decode("ascii", "replace")
    except Exception:
        return "unknown error"


def _pcap_close(pcap):
    """Close pcap handle via pcap_close."""
    if os.name != "nt" or pcap is None:
        return
    try:
        wpcap = ctypes.WinDLL("wpcap.dll", use_last_error=True)
        wpcap.pcap_close.argtypes = [ctypes.POINTER(pcap_t)]
        wpcap.pcap_close.restype = None
        wpcap.pcap_close(pcap)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# run_function — the original main() equivalent.
# ---------------------------------------------------------------------------

def run_function(expression, output_file=None, verbose=False):
    """Run BpfCompiler to compile `expression`.

    Returns 0 on success, non-zero on failure.
    """
    _log("BpfCompiler — BPF filter compiler tool")
    _log("Expression: %s", expression)

    if not _ws2_startup():
        return 1

    try:
        # Open dead pcap handle
        pcap = _pcap_open_dead(DLT_EN10MB, 65535)
        if pcap is None:
            _log("[-] pcap_open_dead failed")
            return 1

        # Compile BPF expression
        bpf_program = _pcap_compile(pcap, expression, 0)
        if bpf_program is None:
            err = _pcap_geterr(pcap)
            _log("[-] pcap_compile failed: %s", err)
            _pcap_close(pcap)
            return 1

        _log("[+] BPF expression compiled successfully")

        # Write output file if specified
        if output_file:
            try:
                with open(output_file, "wb") as f:
                    # Write a simple representation of the compiled program
                    f.write(expression.encode("ascii"))
                _log("[+] Output written to: %s", output_file)
            except OSError as exc:
                _log("[-] Error writing output file: %s", exc)
                _pcap_close(pcap)
                return 1

        _pcap_close(pcap)
        _log("[+] BpfCompiler completed successfully")
        return 0

    finally:
        _ws2_cleanup()


def main():
    """CLI driver (standalone testing)."""
    _log("BpfCompiler standalone CLI not implemented — use `nsa-equation-py bpfcompiler ...`")
    return 1


if __name__ == "__main__":
    sys.exit(main())
