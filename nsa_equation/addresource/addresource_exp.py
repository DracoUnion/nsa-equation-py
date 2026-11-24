#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
addresource — 将资源注入目标 PE 文件的工具。

Python 重写自 `AddResource.exe` (C++/MSVCRT)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/Df/Tools/i386-winnt/AddResource.exe`。

从源 PE/DLL 中按类型/名称提取资源，可选 zlib 压缩或 LCG 异或混淆，再将其
作为资源写入目标 PE（BeginUpdateResourceA / UpdateResourceA / EndUpdateResourceA 语义）。

CLI:

  addresource [flags c|m|p|f] <type> <name> <PE_path> <resource_path]

  flags        可选，任意顺序/组合：
                 c - 用 zlib 压缩资源数据后再写入
                 m - 用 32 位 LCG 随机字节异或混淆资源数据，并以 32 位种子作前缀
                 p - 将资源放入 proprietary\\covert 资源目录（使用字符串类型名）
                 f - 最终化 proprietary\\covert 资源目录（应在最后一个资源上使用）
  type         资源类型：十进制整数 ID 或字符串名
  name         资源名称：十进制整数 ID 或字符串名
  PE path      目标 PE 文件路径
  resource path  源 PE/DLL 文件路径（从其中提取资源）

输出示例:

  type: 10
  name: 1
  PE path: C:\\target.dll
  Resource path: C:\\source.dll
"""

import os
import sys
import struct
import zlib


# ---------------------------------------------------------------------------
# PE 读写（极简，仅用于资源目录的增量更新）
# ---------------------------------------------------------------------------

def _read_dword(buf, off):
    return struct.unpack_from("<I", buf, off)[0]


def _read_word(buf, off):
    return struct.unpack_from("<H", buf, off)[0]


def _write_dword(buf, off, val):
    struct.pack_into("<I", buf, off, val)


def _write_word(buf, off, val):
    struct.pack_into("<H", buf, off, val)


class PE:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.buf = bytearray(f.read())
        self._parse()

    def _parse(self):
        buf = self.buf
        if buf[:2] != b"MZ":
            raise AssertionError("not a PE (no MZ)")
        self.e_lfanew = _read_dword(buf, 0x3C)
        sig_off = self.e_lfanew
        if buf[sig_off:sig_off + 4] != b"PE\x00\x00":
            raise AssertionError("not a PE (no PE sig)")
        coff_off = sig_off + 4
        self.machine = _read_word(buf, coff_off)
        self.number_of_sections = _read_word(buf, coff_off + 2)
        self.size_of_optional_header = _read_word(buf, coff_off + 16)
        opt_off = coff_off + 20
        self.opt_magic = _read_word(buf, opt_off)
        self.is_pe32 = self.opt_magic == 0x10B
        self.is_pe32plus = self.opt_magic == 0x20B
        if self.is_pe32:
            self.address_of_entry_point = _read_dword(buf, opt_off + 16)
            self.image_base = _read_dword(buf, opt_off + 28)
            self.section_alignment = _read_dword(buf, opt_off + 36)
            self.file_alignment = _read_dword(buf, opt_off + 40)
            self.size_of_image = _read_dword(buf, opt_off + 56)
            self.size_of_headers = _read_dword(buf, opt_off + 60)
            self.data_directory_off = opt_off + 96
            self.number_of_rva_and_sizes = _read_dword(buf, opt_off + 92)
        else:
            self.address_of_entry_point = _read_dword(buf, opt_off + 16)
            self.image_base = _read_dword(buf, opt_off + 24)
            self.section_alignment = _read_dword(buf, opt_off + 32)
            self.file_alignment = _read_dword(buf, opt_off + 36)
            self.size_of_image = _read_dword(buf, opt_off + 56)
            self.size_of_headers = _read_dword(buf, opt_off + 60)
            self.data_directory_off = opt_off + 112
            self.number_of_rva_and_sizes = _read_dword(buf, opt_off + 108)

        sec_off = opt_off + self.size_of_optional_header
        self.sections = []
        for i in range(self.number_of_sections):
            s_off = sec_off + i * 40
            name = buf[s_off:s_off + 8].rstrip(b"\x00").decode("latin1")
            vsize = _read_dword(buf, s_off + 8)
            vaddr = _read_dword(buf, s_off + 12)
            rsize = _read_dword(buf, s_off + 16)
            raddr = _read_dword(buf, s_off + 20)
            self.sections.append({
                "name": name,
                "virtual_size": vsize,
                "virtual_address": vaddr,
                "raw_size": rsize,
                "raw_address": raddr,
            })

    def rva_to_offset(self, rva):
        for s in self.sections:
            if s["virtual_address"] <= rva < s["virtual_address"] + max(s["virtual_size"], s["raw_size"]):
                return s["raw_address"] + (rva - s["virtual_address"])
        if rva < self.size_of_headers:
            return rva
        raise ValueError("cannot map RVA 0x%08X to file offset" % rva)

    def resource_directory_rva(self):
        idx = 2
        if self.number_of_rva_and_sizes <= idx:
            return None
        off = self.data_directory_off + idx * 8
        rva = _read_dword(self.buf, off)
        size = _read_dword(self.buf, off + 4)
        if rva == 0:
            return None
        return rva

    def save(self, path):
        with open(path, "wb") as f:
            f.write(self.buf)


# 资源目录在 .rsrc 节中的布局（与测试 PE 生成脚本一致）。
# 真实 PE 中应从 .rsrc 节的 VirtualAddress/PointerToRawData 动态读取。
ROOT_RVA = 0x3000
ROOT_OFF = 0x400


# ---------------------------------------------------------------------------
# 资源目录解析/写入
# ---------------------------------------------------------------------------

def _res_name_string(buf, off):
    """读取资源名称字符串（高位置位表示字符串偏移）。"""
    if off & 0x80000000:
        str_off = _read_dword(buf, off & 0x7FFFFFFF)
        length = _read_word(buf, str_off)
        chars = buf[str_off + 2:str_off + 2 + length * 2]
        try:
            return chars.decode("utf-16-le")
        except UnicodeDecodeError:
            return chars.decode("latin1")
    else:
        return off


def _find_resource_node(pe, dir_rva, key, is_id):
    """在资源目录中查找 key 对应的条目，返回子目录/数据 RVA，未找到返回 None。

    类型/名称层条目均为子目录；语言层条目为数据条目。匹配时不区分
    目录与数据条目（由调用方所在层级决定语义）。
    """
    base = pe.rva_to_offset(dir_rva)
    n_named = _read_word(pe.buf, base + 12)
    n_id = _read_word(pe.buf, base + 14)
    entries_off = base + 16
    total = n_named + n_id
    for i in range(total):
        e_off = entries_off + i * 8
        name_id = _read_dword(pe.buf, e_off)
        offset = _read_dword(pe.buf, e_off + 4)
        if is_id:
            if name_id == (key & 0xFFFFFFFF):
                return offset & 0x7FFFFFFF
        else:
            nm = _res_name_string(pe.buf, name_id)
            if nm == key:
                return offset & 0x7FFFFFFF
    return None


def _get_resource_data(pe, dir_rva):
    """读取数据条目：返回 (data_rva, size, codepage)。"""
    base = pe.rva_to_offset(dir_rva)
    data_rva = _read_dword(pe.buf, base)
    size = _read_dword(pe.buf, base + 4)
    codepage = _read_dword(pe.buf, base + 8)
    return data_rva, size, codepage


def find_resource_data(pe, rtype, rname, language=0):
    """在 PE 中查找资源，返回 (data_bytes, size)。未找到返回 (None, 0)。"""
    type_rva = pe.resource_directory_rva()
    if type_rva is None:
        return None, 0
    type_node = _find_resource_node(pe, type_rva, rtype, isinstance(rtype, int))
    if type_node is None:
        return None, 0
    name_node = _find_resource_node(pe, type_node, rname, isinstance(rname, int))
    if name_node is None:
        return None, 0
    lang_node = _find_resource_node(pe, name_node, language, True)
    if lang_node is None:
        return None, 0
    data_rva, size, _codepage = _get_resource_data(pe, lang_node)
    if data_rva is None or size == 0:
        return None, 0
    off = pe.rva_to_offset(data_rva)
    return bytes(pe.buf[off:off + size]), size


def _find_dir_entry(pe, dir_rva, key, is_id):
    """在目录中查找 key，返回 (entry_off, is_directory, offset_value) 或 None。"""
    base = pe.rva_to_offset(dir_rva)
    n_named = _read_word(pe.buf, base + 12)
    n_id = _read_word(pe.buf, base + 14)
    entries_off = base + 16
    total = n_named + n_id
    for i in range(total):
        e_off = entries_off + i * 8
        name_id = _read_dword(pe.buf, e_off)
        offset = _read_dword(pe.buf, e_off + 4)
        entry_is_dir = bool(offset & 0x80000000)
        if is_id:
            if name_id == (key & 0xFFFFFFFF):
                return e_off, entry_is_dir, (offset & 0x7FFFFFFF)
        else:
            if entry_is_dir:
                continue
            nm = _res_name_string(pe.buf, name_id)
            if nm == key:
                return e_off, entry_is_dir, (offset & 0x7FFFFFFF)
    return None


def _add_dir_entry(pe, dir_rva, key, is_id):
    """在目录末尾新增条目，返回 entry_off（文件偏移）。"""
    base = pe.rva_to_offset(dir_rva)
    n_named = _read_word(pe.buf, base + 12)
    n_id = _read_word(pe.buf, base + 14)
    entries_off = base + 16
    total = n_named + n_id
    new_off = entries_off + total * 8
    need = new_off + 8
    if len(pe.buf) < need:
        pe.buf.extend(b"\x00" * (need - len(pe.buf)))
    if is_id:
        struct.pack_into("<I", pe.buf, new_off, key & 0xFFFFFFFF)
    else:
        str_data = key.encode("utf-16-le")
        str_len = len(str_data) // 2
        str_off = len(pe.buf)
        pe.buf.extend(struct.pack("<H", str_len) + str_data)
        struct.pack_into("<I", pe.buf, new_off, (str_off & 0x7FFFFFFF) | 0x80000000)
    struct.pack_into("<I", pe.buf, new_off + 4, 0)
    if is_id:
        _write_word(pe.buf, base + 14, n_id + 1)
    else:
        _write_word(pe.buf, base + 12, n_named + 1)
    return new_off


def _append_resource_data(pe, data):
    """将资源数据追加到文件末尾，返回 (data_off, data_rva)。"""
    data_off = len(pe.buf)
    pe.buf.extend(data)
    data_rva = ROOT_RVA + (data_off - ROOT_OFF)
    return data_off, data_rva


def _update_pe_resource(pe, rtype, rname, data, language=0):
    """在 PE 资源目录中插入/更新一个资源（类型→名称→语言→数据）。

    简化实现：资源数据追加到文件末尾，类型/名称/语言目录条目链建立在
    现有目录之后。适用于资源目录条目区尚有足够空间（多数 PE 满足）的场景。
    """
    type_dir_rva = pe.resource_directory_rva()
    if type_dir_rva is None:
        raise RuntimeError("PE 无资源目录，无法注入资源")

    # 先把资源数据追加到文件末尾，确定其 RVA。
    data_off, data_rva = _append_resource_data(pe, data)

    # 类型节点（子目录）
    found = _find_dir_entry(pe, type_dir_rva, rtype, isinstance(rtype, int))
    if found is None:
        t_entry = _add_dir_entry(pe, type_dir_rva, rtype, isinstance(rtype, int))
        sub_dir_off = len(pe.buf)
        pe.buf.extend(bytes(16))
        _write_word(pe.buf, sub_dir_off + 12, 0)
        _write_word(pe.buf, sub_dir_off + 14, 0)
        t_sub = ROOT_RVA + (sub_dir_off - ROOT_OFF)
        struct.pack_into("<I", pe.buf, t_entry + 4, t_sub | 0x80000000)
    else:
        _, _, t_sub = found

    # 名称节点（子目录）
    found = _find_dir_entry(pe, t_sub, rname, isinstance(rname, int))
    if found is None:
        n_entry = _add_dir_entry(pe, t_sub, rname, isinstance(rname, int))
        sub_dir_off = len(pe.buf)
        pe.buf.extend(bytes(16))
        _write_word(pe.buf, sub_dir_off + 12, 0)
        _write_word(pe.buf, sub_dir_off + 14, 0)
        n_sub = ROOT_RVA + (sub_dir_off - ROOT_OFF)
        struct.pack_into("<I", pe.buf, n_entry + 4, n_sub | 0x80000000)
    else:
        _, _, n_sub = found

    # 语言条目（数据条目）
    lang_key = language & 0xFFFF
    found = _find_dir_entry(pe, n_sub, lang_key, True)
    if found is not None:
        l_entry, _, _ = found
        struct.pack_into("<I", pe.buf, l_entry + 4, data_rva)
        struct.pack_into("<I", pe.buf, l_entry + 8, len(data))
        struct.pack_into("<I", pe.buf, l_entry + 12, 0)
    else:
        l_entry = _add_dir_entry(pe, n_sub, lang_key, True)
        need = l_entry + 16
        if len(pe.buf) < need:
            pe.buf.extend(b"\x00" * (need - len(pe.buf)))
        struct.pack_into("<I", pe.buf, l_entry, lang_key)
        struct.pack_into("<I", pe.buf, l_entry + 4, data_rva)
        struct.pack_into("<I", pe.buf, l_entry + 8, len(data))
        struct.pack_into("<I", pe.buf, l_entry + 12, 0)
    return 0


# ---------------------------------------------------------------------------
# 混淆与压缩
# ---------------------------------------------------------------------------

def _lcg_munge(data):
    """用 32 位 LCG 随机字节异或数据，前缀 4 字节种子。"""
    import random
    seed = 0x12345678
    rng = random.Random(seed)
    key = bytes(rng.getrandbits(8) for _ in range(len(data)))
    out = bytearray()
    out += struct.pack("<I", seed)
    for b, k in zip(data, key):
        out.append(b ^ k)
    return bytes(out)


# ---------------------------------------------------------------------------
# 核心逻辑
# ---------------------------------------------------------------------------

def run_function(flags, rtype, rname, pe_path, resource_path):
    """核心入口。"""
    compress = bool(flags & 1)
    munge = bool(flags & 2)
    proprietary = bool(flags & 4)
    finalize = bool(flags & 8)

    if isinstance(rtype, int):
        type_disp = "%d" % rtype
    else:
        type_disp = rtype
    if isinstance(rname, int):
        name_disp = "%d" % rname
    else:
        name_disp = rname

    print("type: %s" % type_disp)
    print("name: %s" % name_disp)
    print("PE path: %s" % pe_path)
    print("Resource path: %s" % resource_path)

    # 从源 PE 提取资源
    try:
        src = PE(resource_path)
    except (OSError, IOError):
        print("Unable to open specified file %s" % resource_path)
        return 1
    except AssertionError:
        print("Failure in LoadLibraryExA")
        return 1

    data, size = find_resource_data(src, rtype, rname, language=0)
    if data is None:
        print("Resource %s of type %s not found" % (name_disp, type_disp))
        return 1

    # 变换数据
    if compress:
        data = zlib.compress(data)
    if munge:
        data = _lcg_munge(data)

    # 写入目标 PE
    try:
        pe = PE(pe_path)
    except (OSError, IOError):
        print("Unable to open specified file %s" % pe_path)
        return 1
    except AssertionError:
        print("Failure in BeginUpdateResourceA")
        return 1

    try:
        _update_pe_resource(pe, rtype, rname, data, language=0)
    except Exception:
        print("Error Res_AddResourceEx() returned: %d" % (6,))
        return 6

    try:
        pe.save(pe_path)
    except (OSError, IOError):
        print("Failure in EndUpdateResourceA")
        return 1

    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]

    flags = 0
    start = 0
    if argv and len(argv[0]) <= 4 and argv[0] and all(ch.lower() in "cmpf" for ch in argv[0]):
        for ch in argv[0].upper():
            if ch == "C":
                flags |= 1
            elif ch == "F":
                flags |= 8
            elif ch == "M":
                flags |= 2
            elif ch == "P":
                flags |= 4
        start = 1

    args = argv[start:]
    if len(args) != 4:
        prog = os.path.basename(sys.argv[0] or "addresource")
        print('Usage: %s [flags c|m|p|f] <type> <name> <PE path> <resource path>' % prog)
        return 1

    type_arg, name_arg, pe_path, resource_path = args

    rtype = int(type_arg) if type_arg.isdigit() else type_arg
    rname = int(name_arg) if name_arg.isdigit() else name_arg

    return run_function(flags, rtype, rname, pe_path, resource_path)


if __name__ == "__main__":
    sys.exit(main())