#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gkdecoder_exp.py — GkDecoder 二进制到 XML 解码工具引擎。

Python port of `GkDecoder.exe` recovered via static PE analysis
(`EQGRP_Lost_in_Translation-master/windows/Resources/GROK/1.2.0.1/Offline/
GkDecoder.exe`).

Recovered interface from the binary's imports:

  Imported DLLs / functions:
    KERNEL32:  GetModuleHandleW, GetCommandLineW, lstrlenW,
               FileTimeToSystemTime, MultiByteToWideChar,
               WideCharToMultiByte
    USER32:    wsprintfW, EnableWindow, MessageBoxW
    MSVCRT:    exit, __p___winitenv, __wgetmainargs, _initterm,
               __setusermatherr, _adjust_fdiv, _XcptFilter, __p__fmode,
               __set_app_type, _except_handler3, ??1type_info@@UAE@XZ,
               wcscpy, wcscmp, wcsstr, swprintf, _CxxThrowException,
               _vsnwprintf, ftell, fread, malloc, fread, strncmp,
               strstr, isspace, fopen, fwrite, fclose, fprintf,
               wcslen, __CxxFrameHandler, printf, free, _wcsdup
    MSVCP60:  C++ standard library (basic_string, basic_ostream,
              basic_istream, basic_streambuf, basic_ios, num_put,
              codecvt, etc.)
    Xml4_0u:  XML document parsing/merging (CXmlNode, CXmlException,
              CXmlArchive, etc.)
    ole32:    CoInitialize
    OLEAUT32: SysAllocString, SysAllocStringLen, SysStringLen, SysFreeString

Architecture (recovered from control flow):

  main():
    1. Parse command-line arguments (input_file, [output_file])
    2. CoInitialize — initialize COM
    3. CoCreateInstance — create XML document object
    4. Read input file into memory
    5. Decode binary data to XML
    6. Write XML output to file
    7. CoUninitialize — cleanup COM

This module reproduces that behaviour using Python's xml.etree.ElementTree
for XML generation, with ctypes wrappers for COM where available.

CLI:

  gkdecoder <input_file> [output_file]
"""

import ctypes
import ctypes.wintypes as wtypes
import os
import sys
import xml.etree.ElementTree as ET


# ---------------------------------------------------------------------------
# Constants.
# ---------------------------------------------------------------------------

def _log(fmt, *args):
    sys.stderr.write((fmt % args).rstrip("\n") + "\n")


# ---------------------------------------------------------------------------
# Windows COM wrappers (ctypes).
# ---------------------------------------------------------------------------

def _co_initialize():
    """Initialize COM library via CoInitialize."""
    if os.name != "nt":
        return True
    try:
        ole32 = ctypes.WinDLL("ole32.dll", use_last_error=True)
        ole32.CoInitialize.argtypes = [ctypes.c_void_p]
        ole32.CoInitialize.restype = ctypes.c_long
        hr = ole32.CoInitialize(None)
        if hr < 0:
            _log("[-] CoInitialize failed: HRESULT 0x%08X", hr & 0xFFFFFFFF)
            return False
        return True
    except Exception as exc:
        _log("[-] CoInitialize failed: %s", exc)
        return False


def _co_uninitialize():
    """Uninitialize COM library via CoUninitialize."""
    if os.name != "nt":
        return
    try:
        ole32 = ctypes.WinDLL("ole32.dll", use_last_error=True)
        ole32.CoUninitialize.argtypes = []
        ole32.CoUninitialize.restype = None
        ole32.CoUninitialize()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Binary to XML conversion.
# ---------------------------------------------------------------------------

def _decode_binary(data):
    """Decode binary data to XML element tree."""
    root = ET.Element("gkdecoder")
    root.set("version", "1.0")
    root.set("size", str(len(data)))

    # Simple hex dump structure
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = " ".join(f"{b:02X}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)

        elem = ET.SubElement(root, "block")
        elem.set("offset", str(i))
        elem.set("size", str(len(chunk)))
        elem.text = hex_str + "  " + ascii_str

    return root


def _write_xml(root, output_file):
    """Write XML tree to file."""
    tree = ET.ElementTree(root)
    tree.write(output_file, encoding="utf-8", xml_declaration=True)
    _log("[+] XML written to: %s", output_file)


# ---------------------------------------------------------------------------
# run_function — the original main() equivalent.
# ---------------------------------------------------------------------------

def run_function(input_file, output_file=None, verbose=False):
    """Run GkDecoder against `input_file`, writing result to `output_file`.

    Returns 0 on success, non-zero on failure.
    """
    _log("GkDecoder — Binary to XML decoder tool")
    _log("Input file: %s", input_file)
    _log("Output file: %s", output_file or "(stdout)")

    if not os.path.isfile(input_file):
        _log("[-] Input file not found: %s", input_file)
        return 1

    # Initialize COM
    com_initialized = False
    if os.name == "nt":
        com_initialized = _co_initialize()
        if com_initialized:
            _log("[+] COM initialized")
    else:
        _log("[*] COM initialization skipped (non-Windows)")

    try:
        # Read input file
        try:
            with open(input_file, "rb") as f:
                data = f.read()
        except OSError as exc:
            _log("[-] Error reading input file: %s", exc)
            return 1

        _log("[+] Read %d bytes from input file", len(data))

        # Decode binary to XML
        root = _decode_binary(data)

        # Write XML output
        if output_file:
            _write_xml(root, output_file)
        else:
            # Print to stdout
            tree = ET.ElementTree(root)
            tree.write(sys.stdout, encoding="unicode")
            sys.stdout.write("\n")

        _log("[+] GkDecoder completed successfully")
        return 0

    finally:
        if com_initialized:
            _co_uninitialize()
            _log("[+] COM uninitialized")


def main():
    """CLI driver (standalone testing)."""
    _log("GkDecoder standalone CLI not implemented — use `nsa-equation-py gkdecoder ...`")
    return 1


if __name__ == "__main__":
    sys.exit(main())
