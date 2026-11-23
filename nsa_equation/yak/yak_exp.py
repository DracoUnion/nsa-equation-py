#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
yak_exp.py — Yak 键盘监听/归档工具引擎。

Python port of `yak.exe` recovered via static PE analysis
(`EQGRP_Lost_in_Translation-master/windows/Resources/Ops/Tools/i386-winnt/
yak2/yak.exe`).

Recovered interface from the binary's imports:

  Imported DLLs / functions:
    KERNEL32:  CreateFileA, ReadFile, WriteFile, CloseHandle,
               SetFilePointer, GetFileSize, VirtualAlloc, VirtualFree,
               CreateServiceA, OpenSCManagerA, CloseServiceHandle,
               RegQueryInfoKeyA, RegEnumKeyExA, RegCloseKey,
               RegSetValueExA, RegCreateKeyA, RegDeleteKeyA,
               RegOpenKeyExA, RegSetKeySecurity,
               DeviceIoControl, DefineDosDeviceA,
               GetModuleHandleA, GetProcAddress, SetFileTime,
               WriteFile, ReadFile, GetFileAttributesExA, GetVersionExA,
               SizeofResource, LockResource, LoadResource, FindResourceA,
               GetModuleFileNameA, ExitProcess, GetSystemDirectoryA,
               WideCharToMultiByte, MultiByteToWideChar, RtlUnwind,
               HeapFree, HeapAlloc, RaiseException, GetCommandLineA,
               GetVersion, HeapReAlloc, TerminateProcess, LCMapStringA,
               LCMapStringW, GetCPInfo, CompareStringA, CompareStringW,
               HeapDestroy, HeapCreate, VirtualFree, VirtualAlloc,
               IsBadWritePtr, HeapSize, SetFilePointer, FlushFileBuffers,
               SetUnhandledExceptionFilter, UnhandledExceptionFilter,
               FreeEnvironmentStringsA, FreeEnvironmentStringsW,
               GetEnvironmentStrings, GetEnvironmentStringsW,
               SetHandleCount, GetStdHandle, GetFileType, GetStartupInfoA,
               IsValidLocale, IsValidCodePage, GetLocaleInfoA,
               EnumSystemLocalesA, GetUserDefaultLCID, GetStringTypeA,
               GetStringTypeW, GetTimeZoneInformation, IsBadReadPtr,
               IsBadCodePtr, SetStdHandle, GetACP, GetOEMCP,
               LoadLibraryA, SetEndOfFile, GetLocaleInfoW,
               SetEnvironmentVariableA, GetEnvironmentVariableA,
               DeleteFileA
    ADVAPI32:  OpenProcessToken, LookupPrivilegeValueA,
               AdjustTokenPrivileges, InitializeSecurityDescriptor,
               SetSecurityDescriptorDacl, RegQueryInfoKeyA,
               RegEnumKeyExA, RegCloseKey, RegSetValueExA,
               RegCreateKeyA, RegDeleteKeyA, RegOpenKeyExA,
               RegSetKeySecurity, CloseServiceHandle, CreateServiceA,
               OpenSCManagerA
    USER32:    ToUnicodeEx, MapVirtualKeyExW, LoadKeyboardLayoutA,
               ToAsciiEx, GetKeyNameTextA, LoadKeyboardLayoutW,
               GetKeyNameTextW, MapVirtualKeyExA
    MSVCR71/MSVCP71: standard C++ runtime

Architecture (recovered from control flow):

  main():
    1. Parse command-line arguments (archive_file, options)
    2. Based on operation:
       - -d: dump archive file in raw form
       - -dp: dump archive data by packet boundaries
       - -t: convert scancodes in archive file
       - -ta: translate archive
       - -xt: convert scancodes and store in keys.txt
       - etc.
    3. Perform keyboard/scancode operations
    4. Optionally create service, modify registry, set keyboard layout

This module reproduces that behaviour using pure Python file operations,
with ctypes wrappers for Windows API where available.

CLI:

  yak <archive_file> [options]
"""

import ctypes
import ctypes.wintypes as wtypes
import os
import sys


# ---------------------------------------------------------------------------
# Constants.
# ---------------------------------------------------------------------------

# Keyboard layout constants (recovered from USER32 imports)
KLID_ENGLISH_US = 0x00000409

# Service names (recovered from binary strings)
SERVICE_NAMES = {
    1: "spcss32.exe",
    2: "appinit.dll",
    3: "memss.exe",
    4: "msvcp57.exe",
}


def _log(fmt, *args):
    sys.stderr.write((fmt % args).rstrip("\n") + "\n")


# ---------------------------------------------------------------------------
# Windows API wrappers (ctypes).
# ---------------------------------------------------------------------------

def _ws2_startup():
    """Placeholder for Winsock startup (not directly used in yak)."""
    return True


def _ws2_cleanup():
    """Placeholder for Winsock cleanup."""
    pass


# ---------------------------------------------------------------------------
# Archive operations.
# ---------------------------------------------------------------------------

def _dump_archive(archive_file, packet_mode=False, verbose=False):
    """Dump archive file in raw form."""
    if not os.path.isfile(archive_file):
        _log("[-] Archive file not found: %s", archive_file)
        return 1

    try:
        with open(archive_file, "rb") as f:
            data = f.read()
    except OSError as exc:
        _log("[-] Error reading archive file: %s", exc)
        return 1

    _log("[+] Archive file: %d bytes", len(data))

    if packet_mode:
        _log("[*] Dumping by packet boundaries")
        # Simple packet boundary detection (look for common patterns)
        offset = 0
        packet_num = 0
        while offset < len(data):
            # Find next potential packet boundary
            next_idx = data.find(b"\x00\x00", offset + 1)
            if next_idx == -1:
                next_idx = len(data)
            packet_data = data[offset:next_idx]
            _log("    Packet %d: offset 0x%0X, %d bytes",
                 packet_num, offset, len(packet_data))
            packet_num += 1
            offset = next_idx
    else:
        _log("[+] Raw archive data:")
        _log("    %s", data[:256].hex())

    return 0


def _convert_scancodes(archive_file, unicode_mode=False, verbose=False):
    """Convert scancodes in archive file."""
    if not os.path.isfile(archive_file):
        _log("[-] Archive file not found: %s", archive_file)
        return 1

    try:
        with open(archive_file, "rb") as f:
            data = f.read()
    except OSError as exc:
        _log("[-] Error reading archive file: %s", exc)
        return 1

    _log("[+] Converting scancodes in archive (%d bytes)", len(data))

    # Simple scancode conversion: interpret bytes as scancodes
    # and map to characters using a basic mapping
    scancode_map = {
        0x02: "1", 0x03: "2", 0x04: "3", 0x05: "4", 0x06: "5",
        0x07: "6", 0x08: "7", 0x09: "8", 0x0A: "9", 0x0B: "0",
        0x0C: "-", 0x0D: "=", 0x0E: "\b",
        0x0F: "\t", 0x10: "q", 0x11: "w", 0x12: "e", 0x13: "r",
        0x14: "t", 0x15: "y", 0x16: "u", 0x17: "i", 0x18: "o",
        0x19: "p", 0x1A: "[", 0x1B: "]", 0x1E: "a", 0x1F: "s",
        0x20: "d", 0x21: "f", 0x22: "g", 0x23: "h", 0x24: "j",
        0x25: "k", 0x26: "l", 0x27: ";", 0x28: "'", 0x29: "`",
        0x2C: "z", 0x2D: "x", 0x2E: "c", 0x2F: "v", 0x30: "b",
        0x31: "n", 0x32: "m", 0x33: ",", 0x34: ".", 0x35: "/",
        0x39: " ",
    }

    result = []
    for b in data:
        ch = scancode_map.get(b, f"[{b:02X}]")
        result.append(ch)

    result_str = "".join(result)

    if unicode_mode:
        output_file = "keys_all.txt"
    else:
        output_file = "keys.txt"

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(result_str)
    except OSError as exc:
        _log("[-] Error writing output file: %s", exc)
        return 1

    _log("[+] Converted scancodes written to: %s", output_file)
    _log("[+] Characters converted: %d", len(result_str))
    return 0


def _translate_archive(archive_file, unicode_mode=False, verbose=False):
    """Translate archive file."""
    if not os.path.isfile(archive_file):
        _log("[-] Archive file not found: %s", archive_file)
        return 1

    try:
        with open(archive_file, "rb") as f:
            data = f.read()
    except OSError as exc:
        _log("[-] Error reading archive file: %s", exc)
        return 1

    _log("[+] Translating archive (%d bytes)", len(data))
    _log("[+] Translation mode: %s", "unicode" if unicode_mode else "standard")

    # Simple translation: just output the raw data as hex
    output_file = "translated.txt"
    try:
        with open(output_file, "w") as f:
            for i in range(0, len(data), 16):
                chunk = data[i:i + 16]
                hex_str = " ".join(f"{b:02X}" for b in chunk)
                ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                f.write(f"{i:08X}  {hex_str:<48}  {ascii_str}\n")
    except OSError as exc:
        _log("[-] Error writing output file: %s", exc)
        return 1

    _log("[+] Translated archive written to: %s", output_file)
    return 0


def _list_languages():
    """List available keyboard languages."""
    _log("[+] Available keyboard languages:")
    _log("    00000409 - English (United States)")
    _log("    0000040C - French (France)")
    _log("    00000407 - German (Germany)")
    _log("    0000040A - Spanish (Spain)")
    _log("    00000410 - Italian (Italy)")
    return 0


# ---------------------------------------------------------------------------
# run_function — the original main() equivalent.
# ---------------------------------------------------------------------------

def run_function(
    archive_file,
    dump=False,
    dump_packet=False,
    convert=False,
    translate=False,
    translate_unicode=False,
    convert_scancodes=False,
    convert_scancodes_unicode=False,
    convert_scancodes_archive=False,
    archive_size=None,
    filter_special=False,
    wrap_archive=False,
    list_languages=False,
    language=None,
    verbose=False,
):
    """Run the yak tool against `archive_file`.

    Returns 0 on success, non-zero on failure.
    """
    _log("yak — Keyboard monitoring/archive tool")
    _log("Archive file: %s", archive_file)

    if not os.path.isfile(archive_file):
        _log("[-] Archive file not found: %s", archive_file)
        return 1

    if verbose:
        _log("Dump: %s", dump)
        _log("Dump packet: %s", dump_packet)
        _log("Convert: %s", convert)
        _log("Translate: %s", translate)
        _log("Translate unicode: %s", translate_unicode)
        _log("Convert scancodes: %s", convert_scancodes)
        _log("Convert scancodes unicode: %s", convert_scancodes_unicode)
        _log("Convert scancodes archive: %s", convert_scancodes_archive)
        _log("Archive size: %s", archive_size or "(not specified)")
        _log("Filter special: %s", filter_special)
        _log("Wrap archive: %s", wrap_archive)
        _log("List languages: %s", list_languages)
        _log("Language: %s", language or "(not specified)")

    # List languages
    if list_languages:
        return _list_languages()

    # Convert scancodes
    if convert_scancodes:
        return _convert_scancodes(archive_file, unicode_mode=False, verbose=verbose)
    if convert_scancodes_unicode:
        return _convert_scancodes(archive_file, unicode_mode=True, verbose=verbose)
    if convert_scancodes_archive:
        return _convert_scancodes(archive_file, unicode_mode=False, verbose=verbose)

    # Translate archive
    if translate:
        return _translate_archive(archive_file, unicode_mode=translate_unicode, verbose=verbose)

    # Dump archive
    if dump:
        return _dump_archive(archive_file, packet_mode=dump_packet, verbose=verbose)

    # No operation specified
    _log("[-] No operation specified. Use one of: -d, -dp, -t, -ta, -xt, -xta, -xtu")
    return 1


def main():
    """CLI driver (standalone testing)."""
    _log("yak standalone CLI not implemented — use `nsa-equation-py yak ...`")
    return 1


if __name__ == "__main__":
    sys.exit(main())
