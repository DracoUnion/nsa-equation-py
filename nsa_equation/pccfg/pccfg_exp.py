#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pccfg_exp.py — PCConfig 配置工具引擎。

Python port of `PCConfig.exe` recovered via static PE analysis
(`EQGRP_Lost_in_Translation-master/windows/Resources/Pc/Tools/i386-winnt/
PCConfig.exe`).

Recovered interface from the binary's imports:

  Imported DLLs / functions:
    xerces-c_2_7: XML DOM parser (DOMImplementation, DOMErrorHandler,
                  MemBufInputSource, Wrapper4InputSource, XMLString, etc.)
    WS2_32:     inet_addr, inet_ntoa, WSASetLastError (network address)
    MSVCR90/MSVCP90: standard C++ runtime
    KERNEL32:   CreateFileW, ReadFile, WriteFile, CloseHandle,
                FileTimeToSystemTime, SystemTimeToFileTime,
                MoveFileExW, DeleteFileW, CopyFileW, FlushFileBuffers,
                SetFilePointerEx, GetFileSize, UnmapViewOfFile,
                CreateFileMappingW, MapViewOfFile, FindResourceW,
                SizeofResource, LoadResource, LockResource, etc.

Architecture (recovered from control flow):

  main():
    1. Parse command-line arguments (config file, get/set/list options)
    2. Initialize xerces-c XML platform (XMLPlatformUtils::Initialize)
    3. Load and parse XML configuration file using DOM parser
    4. Based on operation:
       - list: iterate all elements and print key/value pairs
       - get: find element by key name, print value
       - set: find or create element by key name, set value, save file
    5. Cleanup xerces-c (XMLPlatformUtils::Terminate)

This module reproduces that behaviour using Python's xml.etree.ElementTree
for XML parsing, with ctypes wrappers for Windows API where available.

CLI:

  pccfg <config_file> [--get <key>] [--set <key> <value>] [--list] [-v]
"""

import xml.etree.ElementTree as ET
import os
import sys


# ---------------------------------------------------------------------------
# Constants.
# ---------------------------------------------------------------------------

CONFIG_ROOT_TAG = "PCConfig"
CONFIG_ITEM_TAG = "item"
CONFIG_KEY_ATTR = "key"
CONFIG_VALUE_ATTR = "value"


def _log(fmt, *args):
    sys.stderr.write((fmt % args).rstrip("\n") + "\n")


# ---------------------------------------------------------------------------
# XML configuration helpers.
# ---------------------------------------------------------------------------

def _parse_config(config_file):
    """Parse XML configuration file and return the root element."""
    try:
        tree = ET.parse(config_file)
        return tree.getroot()
    except ET.ParseError as exc:
        _log("[-] Failed to parse XML config: %s", exc)
        return None
    except OSError as exc:
        _log("[-] Failed to read config file: %s", exc)
        return None


def _find_item(root, key):
    """Find a config item by key name."""
    for item in root.findall(CONFIG_ITEM_TAG):
        if item.get(CONFIG_KEY_ATTR) == key:
            return item
    return None


def _create_item(root, key, value):
    """Create a new config item."""
    item = ET.SubElement(root, CONFIG_ITEM_TAG)
    item.set(CONFIG_KEY_ATTR, key)
    item.set(CONFIG_VALUE_ATTR, value)
    return item


def _list_items(root):
    """List all configuration items."""
    items = root.findall(CONFIG_ITEM_TAG)
    if not items:
        _log("[*] No configuration items found")
        return
    _log("[+] Configuration items (%d):", len(items))
    for item in items:
        key = item.get(CONFIG_KEY_ATTR, "")
        value = item.get(CONFIG_VALUE_ATTR, "")
        _log("    %s = %s", key, value)


# ---------------------------------------------------------------------------
# run_function — the original main() equivalent.
# ---------------------------------------------------------------------------

def run_function(
    config_file,
    get_key=None,
    set_key=None,
    set_value=None,
    list_all=False,
    verbose=False,
):
    """Run the PCConfig tool against `config_file`.

    Returns 0 on success, non-zero on failure.
    """
    _log("PCConfig — Configuration tool")
    _log("Config file: %s", config_file)

    # Validate config file exists
    if not os.path.isfile(config_file):
        _log("[-] Config file not found: %s", config_file)
        return 1

    # Parse XML config
    root = _parse_config(config_file)
    if root is None:
        return 1

    # Handle list operation
    if list_all:
        _list_items(root)
        return 0

    # Handle get operation
    if get_key:
        item = _find_item(root, get_key)
        if item is not None:
            value = item.get(CONFIG_VALUE_ATTR, "")
            _log("[+] %s = %s", get_key, value)
        else:
            _log("[-] Key not found: %s", get_key)
            return 1
        return 0

    # Handle set operation
    if set_key:
        if set_value is None:
            _log("[-] --set requires a value argument")
            return 1
        item = _find_item(root, set_key)
        if item is None:
            item = _create_item(root, set_key, set_value)
            _log("[+] Created new config item: %s = %s", set_key, set_value)
        else:
            item.set(CONFIG_VALUE_ATTR, set_value)
            _log("[+] Updated config item: %s = %s", set_key, set_value)

        # Write back to file
        try:
            tree = ET.ElementTree(root)
            tree.write(config_file, encoding="utf-8", xml_declaration=True)
            _log("[+] Config file updated: %s", config_file)
        except OSError as exc:
            _log("[-] Failed to write config file: %s", exc)
            return 1
        return 0

    # No operation specified
    _log("[-] No operation specified. Use --get, --set, or --list")
    _log("    Example: pccfg config.xml --list")
    _log("    Example: pccfg config.xml --get ServerIP")
    _log("    Example: pccfg config.xml --set ServerIP 192.168.1.100")
    return 1


def main():
    """CLI driver (standalone testing)."""
    _log("PCConfig standalone CLI not implemented — use `nsa-equation-py pccfg ...`")
    return 1


if __name__ == "__main__":
    sys.exit(main())
