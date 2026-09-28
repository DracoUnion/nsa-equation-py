#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dns_tool.py — Python rewrite of the DNS payload-builder logic
reverse-engineered from `dns.exe` via IDA Pro.

Original addresses for reference:
    sub_403A53   copy_blob            (deep-copy a {size, data} blob)
    sub_403AD7   build_payload        (pick + patch a payload)
    sub_4034DA   parse_options        (CLI option parser / "main")
    sub_403C4A   lookup_payload       (look up a payload record by name)
    sub_40294E   log                  (printf-style logger to an output stream)

The binary is a small Win32 console tool that:
  1. parses a set of command-line options (-R ip, -p port, -y payload, -s src,
     -t target, -z overflow-len, -l/--list, -h host, ...),
  2. resolves a payload by name,
  3. builds an (optionally patched) binary payload blob,
  4. then hands it to the attacker-supplied network layer (DNS tunneling).

This file reproduces that behavior in portable Python.
"""

import socket
import struct
import sys
from ctypes import c_ubyte  # only used for status codes below

# ---------------------------------------------------------------------------
# Payload record layout (native, matches the on-disk table at off_40B340).
#
# The C table is an array of fixed-size records.  Each record is 24 bytes
# (0x18) and `lookup_payload` walks it in steps of 6 DWORDs (= 24 bytes):
#
#   struct payload_record {
#       char *name;   /* offset 0x00 – short name, e.g. "bind", "conn", ... */
#       char *desc;   /* offset 0x04 – human description, e.g. "bind shell" */
#       int   size;   /* offset 0x08 – number of bytes the blob compiler can
#                                    produce (0 → payload requires a real IP) */
#       int   key;    /* offset 0x0C – selector key             */
#       int   data_off;/* offset 0x10 – patch offset used by build_payload   */
#       int   data_off2;/*offset 0x14 – secondary patch offset                */
#   }
# ---------------------------------------------------------------------------
PAYLOAD_SIZE = 0x18          # 24 bytes per record
PAYLOAD_STRIDE = 6           # 6 DWORDs in native stepping

# The beginning of the in-file table (parsed from .rdata @ 0x40B4A4).
# name / desc are the only fields we need for listing; the numeric fields
# are filled in at build time from the real scanner.
PAYLOAD_TABLE = [
    ("bind",      "bind shell"),
    ("conn",      "connect shell"),
    ("2000all",   "Windows 2000 +SP4"),
    ("2003eng",   "EN Windows 2003 Std Ed +SP1"),
    ("2003chs",   "CN Windows 2003 Std Ed +SP1"),
    ("2003cht",   "TW Windows 2003 Std Ed +SP1"),
    ("2003jpn",   "JP Windows 2003 Std Ed +SP1"),
    # ... additional Windows / service-specific payloads follow in the table
]


# ---------------------------------------------------------------------------
# Context / options struct — mirrors the layout the binary pokes via an
# int*(a3).  Field index = byte offset / 4.
#
#   +0   domain/destination (char*)   -> ctx.domain
#   +4   source (char*)               -> ctx.source
#   +8   port (int, default 1100)     -> ctx.port
#   +12  ip4 address (uint32)         -> ctx.ip
#   +16  reserved (0)                 -> ctx.reserved
#   +20  payload list (ptr)           -> ctx.payload_list
#   +24  overflow length ('-z')       -> ctx.overflow_len
#   +28  option 2000                  -> ctx.opt_2000
#   +32  option 2003                  -> ctx.opt_2003
#   +36  option 3003                  -> ctx.opt_3003
#   +52  error counter                -> ctx.errors
# ---------------------------------------------------------------------------
class Context:
    def __init__(self):
        self.domain = None        # +0 destination / C2 fqdn
        self.source = None        # +4 source host
        self.port = 1100          # +8 default port
        self.ip = 0               # +12 IPv4 (network order uint32)
        self.reserved = 0         # +16
        self.payload_list = PAYLOAD_TABLE  # +20
        self.overflow_len = 0     # +24 '-z'
        self.opt_2000 = 0         # +28 option 2000
        self.opt_2003 = 0         # +32 option 2003
        self.opt_3003 = 0         # +36 option 3003
        self.errors = 0           # +52
        # parser-only flags (mirror the C globals dword_40C970..40C97C)
        self.list_flag = False    # '-l'
        self.f_flag = False       # '-f'
        self.r_flag = False       # '-r'
    # --- raw int* accessors to mirror the C code ---------------------------
    def set_dword(self, idx, val):
        fields = {
            0: lambda: setattr(self, 'domain', val),
            1: lambda: setattr(self, 'source', val),
            2: lambda: setattr(self, 'port', val),
            3: lambda: setattr(self, 'ip', val),
            4: lambda: setattr(self, 'reserved', val),
            5: lambda: setattr(self, 'payload_list', val),
            6: lambda: setattr(self, 'overflow_len', val),
            7: lambda: setattr(self, 'opt_2000', val),
            8: lambda: setattr(self, 'opt_2003', val),
            9: lambda: setattr(self, 'opt_3003', val),
            13: lambda: setattr(self, 'errors', val),
        }
        fields[idx]()


# ---------------------------------------------------------------------------
# Pure "algorithmic" timing/config constants that the C code hard-codes or
# reads from its payload table.
# ---------------------------------------------------------------------------
DEFAULT_PORT = 1100
OVERRUN_LIMIT = 32784          # '-z' overflow length upper bound checked in C
BMASK = 0xFFFFFFFF             # emulate the C (unsigned) 32-bit always-on


def log(fmt, *args):
    """sub_40294E — printf-style logger used by the original everywhere."""
    sys.stderr.write((fmt % args).rstrip("\n") + "\n")


# ---------------------------------------------------------------------------
# sub_403A53 — deep-copy a {size, data} blob.
#
#   C:  int sub_403A53(int src, void **dst)
#   src = pointer to  { size_dword; data_ptr }
#   dst = pointer to  8-byte storage to receive a fresh heap copy.
#   Returns 0 on success / no-op, never fails.
#
# Python currently represents a blob as a (size, bytearray) tuple — a
# faithful, GC-safe replacement for the malloc'd C pair.
# ---------------------------------------------------------------------------
def copy_blob(src_size, src_data):
    """Return (size, data) where `data` is a fresh copy of src_data.

    In the C code this allocated a new 8-byte struct and a fresh heap buffer
    and copied the payload bytes into it.  A bytearray copy is the direct
    equivalent and is what the higher-level builders mutate.
    """
    if src_size is None or src_size < 0:
        return (0, bytearray())
    if src_data is None:
        return (src_size, bytearray(src_size))
    return (src_size, bytearray(src_data))


# ---------------------------------------------------------------------------
# sub_403C4A — walk the payload table looking for a record by *name*.
#
#   C: const char **sub_403C4A(const char **a1, char *Str2)
#      while (a1 && *a1 && strcmp(*a1, Str2)) a1 += 6;   // 6 = 24 bytes / 4
#      return (*a1) ? a1 : NULL;                          // also matches
# ---------------------------------------------------------------------------
def lookup_payload(payload_list, name):
    """Return the payload record whose name == `name`, else None."""
    if not payload_list:
        return None
    for rec in payload_list:
        if rec[0] == name:          # strcmp(*a1, Str2) == 0
            return rec
    return None


# ---------------------------------------------------------------------------
# sub_4034DA — command-line / option parser (the "main" of the tool).
#
#   C: char *sub_4034DA(int a1, const char **a2, char *a3)
#      a1 = argc, a2 = argv, a3 = the Context (int*)
#   Parses "-s -t -y -v -R -f -h -l -p -r -z -2000 -2003 -3003",
#   optionally lists payloads/targets, then dispatches to build_payload().
# ---------------------------------------------------------------------------
DEST_SIZE = 8                      # as in the C malloc(strlen + 8)


def parse_options(argv):
    """Parse argv (excluding program name) into a Context, return it."""
    ctx = Context()
    ctx.domain = None
    ctx.source = None
    i = 0
    n = len(argv)

    while i < n:
        opt = argv[i]
        arg = argv[i + 1] if i + 1 < n else None

        # --- option keys map onto the switch() in sub_4034DA --------------
        # (the C ranges: <115 and >115; 115 = 's' verbose-flag path)
        key = opt
        if key in ("-z",):
            # '-z' overflow length, parsed as *hex* (strtoul(., 16))
            seen = arg
            if seen:
                v = int(seen, 16) & BMASK
                if v == 0 or v > OVERRUN_LIMIT:
                    log("[!] - %.8x doesnt seem to be a valid overflow length",
                        v)
                ctx.overflow_len = v
        elif key == "-t":
            # '-t' target name -> select a target record by name
            targ = lookup_payload(PAYLOAD_TABLE, arg or "")
            if arg and targ:
                build_payload(ctx, targ)
            else:
                log("[/] - Unknown target name. Try with %s --list", argv[0])
        elif key == "-v" or key == "-s":
            # verbose counter / 'option:... arg:...' debug echo
            if key == "-v":
                ctx.set_dword(14, ctx.errors + 1)   # verbose count
            log("option:%s", opt)
            if arg:
                log("arg:%s", arg)
        elif key == "-y":
            # '-y' payload name selection
            if arg:
                rec = lookup_payload(ctx.payload_list, arg)
                if rec:
                    ctx.payload_list = rec
                else:
                    log("[/] - Unknown payload name. Try with %s --list",
                        argv[0])
        elif key == "-R":
            # '-R' remote IP address (required for bind-shell payloads)
            if arg:
                try:
                    ip = socket.inet_aton(arg)
                    ctx.ip = struct.unpack(">I", ip)[0]
                except OSError:
                    log("[/] - the selected payload requires an ip address. "
                        "Use the -R option")
                    ctx.errors += 1
            else:
                log("[/] - ivalid payload address")
                ctx.errors += 1
        elif key == "-f":
            ctx.f_flag = True       # undocumented but present in the switch
        elif key == "-h":
            # '-h' host/domain (Destination)
            if arg:
                buf = bytearray(len(arg) + DEST_SIZE)
                buf[:len(arg)] = arg.encode("latin1")
                ctx.domain = bytes(buf).rstrip(b"\x00").decode("latin1")
        elif key == "-l":
            # '-l' list available payloads
            ctx.list_flag = True
        elif key == "-p":
            # '-p' port
            if arg:
                p = int(arg, 10)
                ctx.port = p
                if p >= 0x10000:
                    log("[/] - ivalid payload port")
            else:
                log("[/] - ivalid payload port")
        elif key == "-r":
            ctx.r_flag = True
        elif key in ("2000", "2003", "3003"):
            # numeric service selectors, parsed as hex
            v = int(arg or "0", 16) & BMASK
            if key == "2000":
                ctx.opt_2000 = v
            elif key == "2003":
                ctx.opt_2003 = v
            elif key == "3003":
                ctx.opt_3003 = v
        else:
            log("[/] - Unknown option -%s", opt.strip("-"))
        i += 1

        # consume the argument token for options that take a value
        if opt in ("-z", "-t", "-y", "-R", "-h", "-p", "2000", "2003", "3003"):
            if arg is not None:
                i += 1
            else:
                # missing value -> back off so the next real token is still read
                pass

    # ---- optional listing (the '-l' path) --------------------------------
    if ctx.list_flag:
        log("[.] - List of available payloads to use with -y option")
        for name, desc in ctx.payload_list:
            log("[*] - %-8s %s", name, desc)

    # Build the payload only when a concrete record was actually selected
    # via '-y' (the list itself is not a payload).  Mirrors the C guard
    # `if (ctx.ip || payload[+20]) build_payload(...)`.
    if isinstance(ctx.payload_list, tuple) and ctx.payload_list[0]:
        build_payload(ctx, ctx.payload_list)

    return ctx


# ---------------------------------------------------------------------------
# sub_403AD7 — select + patch the binary payload.
#
#   C: int sub_403AD7(int a1)   // a1 = Context
#   - validates the payload data blob
#   - allocates a fresh 0x18-byte payload record, copies the raw blob via
#     copy_blob
#   - patches the destination port (htons) at data_off and the IP address
#     at data_off2 into the blob, if those offsets are in range.
#   - logs "payload selected"
# ---------------------------------------------------------------------------
def build_payload(ctx, record):
    """Return the patched payload blob (bytearray), logging selection."""
    if not isinstance(record, tuple):
        record = (None, None, 0, 0, 0, 0)
    name, desc, blob_size, key, off_port, off_ip = (record + (0,)*6)[:6]

    # raw payload bytes: produced by a scanner; here we synthesize a zeroed
    # blob of `blob_size` bytes (matching the C fresh alloc + memcpy).
    if not blob_size:
        log("[/] - ivalid payload data for '%s'", name)
        ctx.errors += 1
        return None

    blob = bytearray(blob_size)          # sub_403A53 fresh copy
    patched = copy_blob(blob_size, blob)[1]

    # patch destination port (network order) into the blob at off_port
    if 0 < off_port < blob_size:
        struct.pack_into(">H", patched, off_port,
                         socket.htons(ctx.port & 0xFFFF))
    # patch the IPv4 destination address into the blob at off_ip
    if 0 < off_ip < blob_size - 3:
        struct.pack_into(">I", patched, off_ip, ctx.ip)

    # inet_ntoa + log (sub_40294E("payload  selected (...) port:%d addr:%s"))
    try:
        addr = socket.inet_ntoa(struct.pack(">I", ctx.ip)) if ctx.ip else "0.0.0.0"
    except (OSError, struct.error):
        addr = "0.0.0.0"
    log("[*] - %s payload selected (%d bytes) port:%d addr:%s",
        name, blob_size, ctx.port, addr)
    return bytes(patched)


# ---------------------------------------------------------------------------
# Driver.
# ---------------------------------------------------------------------------
def main():
    argv = sys.argv[1:]
    ctx = parse_options(argv)
    log("[.] - done parsing; errors=%d", ctx.errors)


if __name__ == "__main__":
    main()