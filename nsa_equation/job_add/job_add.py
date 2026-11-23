"""job_add — JOBADD AT 作业添加核心逻辑。

Python 重写的 `Jobadd-1.1.1.exe` (C++ / DAVE framework)。
通过 IDA Pro / x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其 AT 作业调度添加流程。

参数定义来源：Jobadd-1.1.1.0.xml
"""

import socket
import struct
import sys

# ---------------------------------------------------------------------------
# 常量（来自 XML config 的 <inputparameters>）
# ---------------------------------------------------------------------------

DEFAULT_PORT = 445
DEFAULT_TIMEOUT = 60
DEFAULT_HOUR = 0
DEFAULT_MINUTE = 1

PROTOCOL_VALUES = {
    "SMB": 0,
    "NBT": 1,
}

CREDENTIAL_TYPE_VALUES = {
    "UnicodeCreds": 0,
    "PasswordHash": 1,
    "MachineHash":  2,
    "KerberosTicket": 3,
    "KerberosFile":   4,
}

AUTH_LEVEL_VALUES = {
    "Default":   0,
    "None":      1,
    "Connect":   2,
    "Call":      3,
    "Packet":    4,
    "Integrity": 5,
    "Privacy":   6,
}

MODE_VALUES = {
    "Offset":   0,
    "Absolute": 1,
}


class JobAddError(Exception):
    pass


def _parse_hex_buffer(value):
    """将十六进制字符串解析为字节串。空字符串返回 b""。"""
    if not value:
        return b""
    value = value.strip()
    if len(value) % 2 != 0:
        raise JobAddError(f"十六进制缓冲区长度必须为偶数: {value!r}")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise JobAddError(f"无效的十六进制缓冲区: {value!r}") from exc


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
    command=None,
    hour=DEFAULT_HOUR,
    minute=DEFAULT_MINUTE,
    mode="Offset",
    auth_level="None",
    credential_type="UnicodeCreds",
    username=None,
    credential=None,
    password=None,
    domain_dns=None,
    kerberos_ticket=None,
    session_key=None,
    ticket_file=None,
    verbose=False,
):
    """执行 JOBADD 作业调度序列。

    当前阶段：完成参数解析、SMB 连接与协商。
    具体 AT 作业添加逻辑（会话设置、树连接、ATSVC RPC 调用、
    NetJobAdd 等）的二进制结构尚需通过 capstone/x32dbg 进一步逆向后
    填充。
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] Command: {command}")
        print(f"[*] Hour: {hour}")
        print(f"[*] Minute: {minute}")
        print(f"[*] Mode: {mode}")
        print(f"[*] Auth level: {auth_level}")
        print(f"[*] Credential type: {credential_type}")
        if username:
            print(f"[*] Username: {username}")
        if credential:
            print(f"[*] Credential: {credential}")

    # 解析常量
    protocol_value = 0  # SMB
    credential_type_value = CREDENTIAL_TYPE_VALUES[credential_type]
    auth_level_value = AUTH_LEVEL_VALUES[auth_level]
    mode_value = MODE_VALUES[mode]

    # 解析十六进制缓冲区
    username_bytes = _parse_hex_buffer(username)
    credential_bytes = _parse_hex_buffer(credential)
    domain_dns_bytes = _parse_hex_buffer(domain_dns)
    kerberos_ticket_bytes = _parse_hex_buffer(kerberos_ticket)
    session_key_bytes = _parse_hex_buffer(session_key)

    if verbose:
        print(f"[*] Protocol value: {protocol_value}")
        print(f"[*] Credential type value: {credential_type_value}")
        print(f"[*] Auth level value: {auth_level_value}")
        print(f"[*] Mode value: {mode_value}")
        print(f"[*] Username: {len(username_bytes)} bytes")
        print(f"[*] Credential: {len(credential_bytes)} bytes")
        print(f"[*] Domain DNS: {len(domain_dns_bytes)} bytes")
        print(f"[*] Kerberos ticket: {len(kerberos_ticket_bytes)} bytes")
        print(f"[*] Session key: {len(session_key_bytes)} bytes")
        if ticket_file:
            print(f"[*] Ticket file: {ticket_file}")

    # 建立 TCP 连接（SMB 445 / NBT 139）
    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise JobAddError(f"无法连接到 {target}:{port}: {exc}") from exc

    # 发送 SMB 协商请求（探测阶段）
    negotiate = build_smb_negotiate_request()
    try:
        sock.sendall(negotiate)
        resp = sock.recv(4096)
    except OSError as exc:
        sock.close()
        raise JobAddError(f"SMB 协商失败: {exc}") from exc

    if verbose:
        print(f"[*] SMB 协商应答: {resp.hex()[:128]}...")

    sock.close()

    # TODO: 以下 AT 作业添加逻辑需通过 IDA/x32dbg 逆向后填充：
    #   - 会话设置 (SESSION_SETUP_ANDX) 与凭证验证
    #   - 树连接 (TREE_CONNECT_ANDX) 到 IPC$
    #   - ATSVC RPC 接口绑定
    #   - NetJobAdd RPC 调用（添加定时任务）
    #   - 支持 Kerberos 票据认证（TicketFile）

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
