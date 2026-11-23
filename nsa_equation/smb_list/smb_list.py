"""smb_list — SMBLIST SMB 目录列表核心逻辑。

Python 重写的 `Smblist-1.1.1.exe` (C++ / DAVE framework)。
通过 IDA Pro / x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其 SMB 目录列表流程。

参数定义来源：Smblist-1.1.1.0.xml
"""

import socket
import struct
import sys

# ---------------------------------------------------------------------------
# 常量（来自 XML config 的 <inputparameters>）
# ---------------------------------------------------------------------------

DEFAULT_PORT = 445
DEFAULT_TIMEOUT = 60
DEFAULT_FILTER = "*"
DEFAULT_LOG_FILE = "smblist.txt"

CREDENTIAL_TYPE_VALUES = {
    "UnicodeCreds": 0,
    "PasswordHash": 1,
    "MachineHash":  2,
    "KerberosTicket": 3,
    "KerberosFile":   4,
}


class SmbListError(Exception):
    pass


def _parse_hex_buffer(value):
    """将十六进制字符串解析为字节串。空字符串返回 b""。"""
    if not value:
        return b""
    value = value.strip()
    if len(value) % 2 != 0:
        raise SmbListError(f"十六进制缓冲区长度必须为偶数: {value!r}")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise SmbListError(f"无效的十六进制缓冲区: {value!r}") from exc


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
    share=None,
    path=None,
    filter=DEFAULT_FILTER,
    recursive=False,
    log_file=DEFAULT_LOG_FILE,
    credential_type="UnicodeCreds",
    username=None,
    credential=None,
    domain_dns=None,
    kerberos_ticket=None,
    session_key=None,
    ticket_file=None,
    verbose=False,
):
    """执行 SMBLIST 列表序列。

    当前阶段：完成参数解析、SMB 连接与协商。
    具体目录列表逻辑（会话设置、树连接、NTCreateAndX 打开目录、
    FindFirst2/FindNext2 枚举文件等）的二进制结构尚需通过 capstone/x32dbg
    进一步逆向后填充。
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] Share: {share}")
        print(f"[*] Path: {path}")
        print(f"[*] Filter: {filter}")
        print(f"[*] Recursive: {recursive}")
        print(f"[*] Log file: {log_file}")
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
    domain_dns_bytes = _parse_hex_buffer(domain_dns)
    kerberos_ticket_bytes = _parse_hex_buffer(kerberos_ticket)
    session_key_bytes = _parse_hex_buffer(session_key)

    if verbose:
        print(f"[*] Credential type value: {credential_type_value}")
        print(f"[*] Username: {len(username_bytes)} bytes")
        print(f"[*] Credential: {len(credential_bytes)} bytes")
        print(f"[*] Domain DNS: {len(domain_dns_bytes)} bytes")
        print(f"[*] Kerberos ticket: {len(kerberos_ticket_bytes)} bytes")
        print(f"[*] Session key: {len(session_key_bytes)} bytes")
        if ticket_file:
            print(f"[*] Ticket file: {ticket_file}")

    # 建立 TCP 连接（SMB 445）
    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise SmbListError(f"无法连接到 {target}:{port}: {exc}") from exc

    # 发送 SMB 协商请求（探测阶段）
    negotiate = build_smb_negotiate_request()
    try:
        sock.sendall(negotiate)
        resp = sock.recv(4096)
    except OSError as exc:
        sock.close()
        raise SmbListError(f"SMB 协商失败: {exc}") from exc

    if verbose:
        print(f"[*] SMB 协商应答: {resp.hex()[:128]}...")

    sock.close()

    # TODO: 以下目录列表逻辑需通过 IDA/x32dbg 逆向后填充：
    #   - 会话设置 (SESSION_SETUP_ANDX) 与凭证验证
    #   - 树连接 (TREE_CONNECT_ANDX) 到指定共享
    #   - NTCreateAndX 打开目录
    #   - FindFirst2 / FindNext2 枚举文件（按 Filter 过滤）
    #   - 递归子目录（Recursive 标志）
    #   - 输出结果到屏幕或 LogFile
    #   - 支持 Kerberos 票据认证（TicketFile）

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
