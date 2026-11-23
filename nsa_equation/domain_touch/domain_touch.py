"""domain_touch — Domaintouch 域控制器探测核心逻辑。

Python 重写的 `Domaintouch-1.1.1.exe` (C++ / DAVE framework)。
通过 IDA Pro / x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其域控制器 Netlogon 探测流程。

参数定义来源：Domaintouch-1.1.1.0.xml
"""

import socket
import struct
import sys

# ---------------------------------------------------------------------------
# 常量（来自 XML config 的 <inputparameters>）
# ---------------------------------------------------------------------------

DEFAULT_PORT = 445
DEFAULT_TIMEOUT = 60

CREDENTIAL_TYPE_VALUES = {
    "Ticket":       0,
    "UnicodeCreds": 1,
    "MachineHash":  2,
    "PasswordHash": 3,
}


class DomainTouchError(Exception):
    pass


def _parse_hex_buffer(value):
    """将十六进制字符串解析为字节串。空字符串返回 b""。"""
    if not value:
        return b""
    value = value.strip()
    if len(value) % 2 != 0:
        raise DomainTouchError(f"十六进制缓冲区长度必须为偶数: {value!r}")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise DomainTouchError(f"无效的十六进制缓冲区: {value!r}") from exc


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
    credential_type="Ticket",
    username=None,
    credential=None,
    verbose=False,
):
    """执行 DOMINIONTOUCH 探测序列。

    当前阶段：完成参数解析、SMB 连接与协商。
    具体 Netlogon 探测逻辑（域信息查询、SID/GUID 提取等）的
    二进制结构尚需通过 capstone/x32dbg 进一步逆向后填充。
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] Credential type: {credential_type}")
        if username:
            print(f"[*] Username: {username}")
        if credential:
            print(f"[*] Credential: {credential}")

    # 解析常量
    credential_type_value = CREDENTIAL_TYPE_VALUES[credential_type]

    # 解析十六进制缓冲区
    username_bytes = _parse_hex_buffer(username)
    credential_bytes = _parse_hex_buffer(credential)

    if verbose:
        print(f"[*] Credential type value: {credential_type_value}")
        print(f"[*] Username: {len(username_bytes)} bytes")
        print(f"[*] Credential: {len(credential_bytes)} bytes")

    # 建立 TCP 连接（SMB 445，Netlogon 服务）
    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise DomainTouchError(f"无法连接到 {target}:{port}: {exc}") from exc

    # 发送 SMB 协商请求（探测阶段）
    negotiate = build_smb_negotiate_request()
    try:
        sock.sendall(negotiate)
        resp = sock.recv(4096)
    except OSError as exc:
        sock.close()
        raise DomainTouchError(f"SMB 协商失败: {exc}") from exc

    if verbose:
        print(f"[*] SMB 协商应答: {resp.hex()[:128]}...")

    sock.close()

    # TODO: 以下 Netlogon 探测逻辑需通过 IDA/x32dbg 逆向后填充：
    #   - 会话设置 (SESSION_SETUP_ANDX) 与凭证验证
    #   - Netlogon 样例请求 (NetrLogonSamLogon 等)
    #   - 域信息查询（DomainNetbios, DomainDns, DomainSid, DomainGuid）
    #   - 输出域控制器信息

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
