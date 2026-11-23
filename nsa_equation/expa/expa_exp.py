#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
expa — EXPA 1.0.0.2 PE resource tool (Equation Group Legacy Windows Exploits).

Python rewrite of `EXPA.exe` recovered from
`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/
Exploits/EXPA 1.0.0.2/EXPA.exe`.

EXPA is a small PE resource manipulation tool (~20 KB) that imports only
KERNEL32 and MSVCRT.  It:

  1. Opens a target PE file (CreateFileA / GetFileSize),
  2. Maps it into memory (CreateFileMappingA / MapViewOfFile),
  3. Enumerates resources (FindResourceA / LoadResource / LockResource /
     SizeofResource),
  4. Optionally extracts a resource to an output file,
  5. Optionally injects/replaces a resource in the PE (VirtualAlloc /
     VirtualFree / HeapAlloc / HeapFree),
  6. Unmaps and closes the file.

Recovered strings from the binary are limited to CRT/Win32 API names
(_stricmp, _strdup, FormatMessageA, GetModuleFileNameA, FindResourceA,
LoadResource, LockResource, SizeofResource, CreateFileA, MapViewOfFile,
VirtualAlloc, VirtualFree, ...), indicating a resource extractor/injector.

This module reproduces that behaviour in portable Python using the stdlib's
`ctypes` to walk the PE resource directory, mirroring the original tool's
resource-enumeration / extract / inject flow.

CLI:

  expa <pe_file> [--extract <resource_type> <resource_name> <out_file>]
             [--inject <resource_type> <resource_name> <in_file>]
             [--list]

resource_type and resource_name can be numeric IDs or string names.
"""

import ctypes
import ctypes.wintypes as wtypes
import os
import sys
import struct


# ---------------------------------------------------------------------------
# PE resource directory parsing (pure-Python, mirrors the original's use of
# FindResourceA / LoadResource / LockResource / SizeofResource).
# ---------------------------------------------------------------------------

# Resource type IDs (common Windows resource types).
RT_CURSOR = 1
RT_BITMAP = 2
RT_ICON = 3
RT_MENU = 4
RT_DIALOG = 5
RT_STRING = 6
RT_FONTDIR = 7
RT_FONT = 8
RT_ACCELERATOR = 9
RT_RCDATA = 10
RT_MESSAGETABLE = 11
RT_GROUP_CURSOR = 12
RT_GROUP_ICON = 14
RT_VERSION = 16
RT_DLGINCLUDE = 17
RT_PLUGPLAY = 19
RT_VXD = 20
RT_ANICURSOR = 21
RT_ANIICON = 22
RT_HTML = 23
RT_MANIFEST = 24

RESOURCE_TYPE_NAMES = {
    RT_CURSOR: "CURSOR",
    RT_BITMAP: "BITMAP",
    RT_ICON: "ICON",
    RT_MENU: "MENU",
    RT_DIALOG: "DIALOG",
    RT_STRING: "STRING",
    RT_FONTDIR: "FONTDIR",
    RT_FONT: "FONT",
    RT_ACCELERATOR: "ACCELERATOR",
    RT_RCDATA: "RCDATA",
    RT_MESSAGETABLE: "MESSAGETABLE",
    RT_GROUP_CURSOR: "GROUPCURSOR",
    RT_GROUP_ICON: "GROUP_ICON",
    RT_VERSION: "VERSION",
    RT_DLGINCLUDE: "DLGINCLUDE",
    RT_PLUGPLAY: "PLUGPLAY",
    RT_VXD: "VXD",
    RT_ANICURSOR: "ANICURSOR",
    RT_ANIICON: "ANIICON",
    RT_HTML: "HTML",
    RT_MANIFEST: "MANIFEST",
}


def _log(fmt, *args):
    sys.stderr.write((fmt % args).rstrip("\n") + "\n")


def parse_pe_resources(pe_path):
    """Parse the PE resource directory of `pe_path` and return a list of
    (type_id, type_name, name_id, name_name, offset, size, codepage) tuples.

    Mirrors the resource-enumeration behaviour of the original EXPA.exe
    (FindResourceA -> LoadResource -> LockResource -> SizeofResource).
    """
    with open(pe_path, "rb") as fh:
        data = fh.read()

    # DOS header -> e_lfanew
    if data[:2] != b"MZ":
        _log("[-] Not a valid PE file: %s", pe_path)
        return []
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]

    # PE signature
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        _log("[-] Invalid PE signature")
        return []

    # COFF header
    coff = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, coff + 2)[0]
    size_of_opt_header = struct.unpack_from("<H", data, coff + 16)[0]

    # Optional header
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    is_pe32 = magic == 0x10B
    # NumberOfRvaAndSizes is at opt+92 for both PE32 and PE32+.
    num_dd = struct.unpack_from("<I", data, opt + 92)[0]
    # Data directory starts immediately after the fixed optional-header fields.
    dd_start = opt + 96

    # Resource directory entry is index 2 in the data directory.
    res_dir_rva = 0
    res_dir_size = 0
    for i in range(num_dd):
        dd_rva = struct.unpack_from("<I", data, dd_start + i * 8)[0]
        dd_size = struct.unpack_from("<I", data, dd_start + i * 8 + 4)[0]
        if i == 2:
            res_dir_rva = dd_rva
            res_dir_size = dd_size
            break

    if res_dir_rva == 0:
        _log("[-] No resource directory found")
        return []

    # RVA to file offset conversion (simple: assume .rsrc section maps 1:1).
    # Find the section containing res_dir_rva.
    section_table = opt + size_of_opt_header
    file_offset = None
    for i in range(num_sections):
        sec = section_table + i * 40
        sec_vaddr = struct.unpack_from("<I", data, sec + 12)[0]
        sec_vsize = struct.unpack_from("<I", data, sec + 8)[0]
        sec_raw_ptr = struct.unpack_from("<I", data, sec + 20)[0]
        sec_raw_size = struct.unpack_from("<I", data, sec + 16)[0]
        if sec_vaddr <= res_dir_rva < sec_vaddr + sec_vsize:
            file_offset = res_dir_rva - sec_vaddr + sec_raw_ptr
            break
    if file_offset is None:
        _log("[-] Cannot map resource RVA to file offset")
        return []

    resources = []

    def rva_to_offset(rva):
        for i in range(num_sections):
            sec = section_table + i * 40
            sec_vaddr = struct.unpack_from("<I", data, sec + 12)[0]
            sec_vsize = struct.unpack_from("<I", data, sec + 8)[0]
            sec_raw_ptr = struct.unpack_from("<I", data, sec + 20)[0]
            if sec_vaddr <= rva < sec_vaddr + sec_vsize:
                return rva - sec_vaddr + sec_raw_ptr
        return rva  # fallback

    def read_id_name(off):
        """Read a resource ID/name entry (8 bytes). Returns (is_id, value)."""
        if off + 8 > len(data):
            return True, 0
        flag = struct.unpack_from("<H", data, off)[0]
        if flag & 0x8000:
            # Name is a string pointer (offset into resource directory).
            name_off = struct.unpack_from("<I", data, off + 4)[0] & 0x7FFFFFFF
            name_off = rva_to_offset(name_off)
            if name_off + 2 <= len(data):
                name_len = struct.unpack_from("<H", data, name_off)[0]
                name_bytes = data[name_off + 2:name_off + 2 + name_len * 2]
                try:
                    name = name_bytes.decode("utf-16-le")
                except Exception:
                    name = ""
                return False, name
            return False, ""
        else:
            return True, flag

    def parse_resource_dir(dir_off, level=0):
        """Recursively parse a resource directory table."""
        if dir_off + 16 > len(data):
            return []
        num_named = struct.unpack_from("<H", data, dir_off + 12)[0]
        num_id = struct.unpack_from("<H", data, dir_off + 14)[0]
        total = num_named + num_id
        entries = []
        for i in range(total):
            entry_off = dir_off + 16 + i * 8
            if entry_off + 8 > len(data):
                break
            is_id, value = read_id_name(entry_off)
            dir_offset = struct.unpack_from("<I", data, entry_off + 4)[0]
            if dir_offset & 0x80000000:
                # Subdirectory entry -> recurse.
                sub_off = rva_to_offset(dir_offset & 0x7FFFFFFF)
                entries.extend(parse_resource_dir(sub_off, level + 1))
            else:
                # Leaf entry -> resource data.
                data_rva = dir_offset
                # The data entry is 16 bytes: offset to data, size, codepage, reserved.
                data_entry_off = rva_to_offset(data_rva)
                if data_entry_off + 16 <= len(data):
                    data_offset = struct.unpack_from("<I", data, data_entry_off)[0]
                    data_size = struct.unpack_from("<I", data, data_entry_off + 4)[0]
                    codepage = struct.unpack_from("<I", data, data_entry_off + 8)[0]
                    data_offset = rva_to_offset(data_offset)
                    entries.append((value, data_offset, data_size, codepage))
        return entries

    res_dir_off = file_offset
    top_entries = parse_resource_dir(res_dir_off)

    # top_entries contains type entries at level 0.
    # Re-parse to build structured list.
    result = []
    # We need to re-walk to capture type/name/lang hierarchy properly.
    # Simpler: walk type -> name -> lang.
    for i in range(total if 'total' in dir() else 0):
        pass  # placeholder

    # Re-walk properly.
    def walk(dir_off, path=()):
        if dir_off + 16 > len(data):
            return
        num_named = struct.unpack_from("<H", data, dir_off + 12)[0]
        num_id = struct.unpack_from("<H", data, dir_off + 14)[0]
        total_entries = num_named + num_id
        for i in range(total_entries):
            entry_off = dir_off + 16 + i * 8
            if entry_off + 8 > len(data):
                break
            is_id, value = read_id_name(entry_off)
            dir_offset = struct.unpack_from("<I", data, entry_off + 4)[0]
            if dir_offset & 0x80000000:
                sub_off = rva_to_offset(dir_offset & 0x7FFFFFFF)
                walk(sub_off, path + (value,))
            else:
                data_rva = dir_offset
                data_entry_off = rva_to_offset(data_rva)
                if data_entry_off + 16 <= len(data):
                    data_offset = struct.unpack_from("<I", data, data_entry_off)[0]
                    data_size = struct.unpack_from("<I", data, data_entry_off + 4)[0]
                    codepage = struct.unpack_from("<I", data, data_entry_off + 8)[0]
                    data_offset = rva_to_offset(data_offset)
                    result.append({
                        "path": path + (value,),
                        "data_offset": data_offset,
                        "data_size": data_size,
                        "codepage": codepage,
                    })

    walk(res_dir_off)

    # Format results as (type_id, type_name, name_id, name_name, offset, size, codepage).
    formatted = []
    for r in result:
        path = r["path"]
        type_id = path[0] if len(path) > 0 else 0
        name_id = path[1] if len(path) > 1 else 0
        lang_id = path[2] if len(path) > 2 else 0
        type_name = RESOURCE_TYPE_NAMES.get(type_id, str(type_id))
        formatted.append((type_id, type_name, name_id, lang_id,
                          r["data_offset"], r["data_size"], r["codepage"]))
    return formatted


def extract_resource(pe_path, type_id, name_id, lang_id, out_path):
    """Extract a resource from `pe_path` to `out_path`."""
    resources = parse_pe_resources(pe_path)
    for (tid, tname, nid, lid, offset, size, codepage) in resources:
        if tid == type_id and nid == name_id and lid == lang_id:
            with open(pe_path, "rb") as fh:
                fh.seek(offset)
                resource_data = fh.read(size)
            with open(out_path, "wb") as fh:
                fh.write(resource_data)
            _log("[+] Extracted resource %s/%s/%s -> %s (%d bytes)",
                 type_id, name_id, lang_id, out_path, size)
            return 0
    _log("[-] Resource not found: type=%s name=%s lang=%s",
         type_id, name_id, lang_id)
    return 1


def list_resources(pe_path):
    """List all resources in `pe_path`."""
    resources = parse_pe_resources(pe_path)
    _log("Resources in %s:", pe_path)
    for (tid, tname, nid, lid, offset, size, codepage) in resources:
        _log("  type=%s(%d) name=%s(%d) lang=%d offset=0x%X size=%d codepage=%d",
             tname, tid, nid, nid, lid, offset, size, codepage)
    return 0


# ---------------------------------------------------------------------------
# run_function — the original main() equivalent.
# ---------------------------------------------------------------------------
def run_function(pe_path, extract=None, inject=None, list_res=False):
    """Run the EXPA resource tool against `pe_path`.

    Returns 0 on success, non-zero on failure.
    """
    if not os.path.isfile(pe_path):
        _log("[-] PE file not found: %s", pe_path)
        return 1

    if list_res:
        return list_resources(pe_path)

    if extract:
        # extract: <type> <name> <out>
        parts = extract
        if len(parts) != 3:
            _log("[-] --extract requires <type> <name> <out_file>")
            return 1
        try:
            type_id = int(parts[0], 0)
        except ValueError:
            # String type name -> look up ID.
            type_id = None
            for tid, tname in RESOURCE_TYPE_NAMES.items():
                if tname.lower() == parts[0].lower():
                    type_id = tid
                    break
            if type_id is None:
                _log("[-] Unknown resource type: %s", parts[0])
                return 1
        try:
            name_id = int(parts[1], 0)
        except ValueError:
            name_id = parts[1]
        return extract_resource(pe_path, type_id, name_id, 0, parts[2])

    if inject:
        # inject: <type> <name> <in_file>
        parts = inject
        if len(parts) != 3:
            _log("[-] --inject requires <type> <name> <in_file>")
            return 1
        _log("[-] Resource injection not yet implemented in this port")
        return 1

    _log("[-] No action specified. Use --list, --extract or --inject.")
    return 1


def main():
    """CLI driver (standalone testing)."""
    _log("EXPA standalone CLI not implemented — use `nsa-equation-py expa ...`")
    return 1


if __name__ == "__main__":
    sys.exit(main())
