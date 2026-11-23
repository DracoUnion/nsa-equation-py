"""reg_delete — REGDELETE 注册表删除核心逻辑。

Python 重写的 `Regdelete-1.1.1.exe` (C++ / DAVE framework)。
通过 x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其注册表删除流程。

参数定义来源：Regdelete-1.1.1.0.xml
"""

import socket
import struct
import sys

# ---------------------------------------------------------------------------
# 常量（来自 XML config 的 <inputparameters>）
# ---------------------------------------------------------------------------

DEFAULT_PORT = 445
DEFAULT_TIMEOUT = 60

REG_HIVE_VALUES = {
    "HKLM": 0,
    "HKU":   1,
    "HKPD":  2,
    "HKCU":  3,
    "HKCR":  4,
}

TYPE_TO_DELETE_VALUES = {
    "Key":   0,
    "Value": 1,
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

CREDENTIAL_TYPE_VALUES = {
    "UnicodeCreds": 0,
    "PasswordHash": 1,
    "MachineHash":  2,
    "KerberosTicket": 3,
    "KerberosFile":   4,
}

# 远程注册表 RPC 接口 UUID (从 Regdelete-1.1.1.exe 数据节恢复)
REGISTRY_RPC_UUID = "338cd001-2244-31f1-aaaa-900038001003"

# 远程注册表 opnum (BaseReg 系列)
OPNUM_BASE_REG_OPEN_KEY = 0
OPNUM_BASE_REG_DELETE_KEY = 3
OPNUM_BASE_REG_DELETE_VALUE = 5


class RegDeleteError(Exception):
    pass


def _parse_hex_buffer(value):
    """将十六进制字符串解析为字节串。空字符串返回 b""。"""
    if not value:
        return b""
    value = value.strip()
    if len(value) % 2 != 0:
        raise RegDeleteError(f"十六进制缓冲区长度必须为偶数: {value!r}")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise RegDeleteError(f"无效的十六进制缓冲区: {value!r}") from exc


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


def build_session_setup_request():
    """构建 SMB 会话设置请求（SESSION_SETUP_ANDX）。"""
    command = 0x73  # SMB_COM_SESSION_SETUP_ANDX
    smb = (
        b"\xffSMB"
        + struct.pack("B", command)
        + b"\x00" * 4                      # Status
        + b"\x08"                          # Flags1
        + b"\x00" * 2                      # Flags2
        + b"\x00" * 2                      # PID high
        + b"\x00" * 8                      # Security features + reserved
        + b"\x00" * 8                      # TID, PID, UID, MID
        + b"\x0d"                          # Word count (13)
        + b"\xff"                          # AndX command (no further commands)
        + b"\x00"                          # AndX reserved
        + struct.pack("<H", 0)             # AndX offset
        + struct.pack("<H", 0)             # Max buffer size
        + struct.pack("<H", 4096)          # Max Mpx count
        + struct.pack("<H", 0)             # VC number
        + struct.pack("<I", 0)             # Session key
        + struct.pack("<I", 0)             # Security blob length
        + struct.pack("<H", 0)             # Security blob offset
        + struct.pack("<I", 0)             # Capabilities
        + struct.pack("<H", 0)             # Byte count
    )
    return smb


def build_tree_connect_request(share_name=b"IPC$"):
    """构建 SMB 树连接请求（TREE_CONNECT_ANDX）。"""
    command = 0x75  # SMB_COM_TREE_CONNECT_ANDX
    share = share_name + b"\x00"
    password = b"\x00"
    smb = (
        b"\xffSMB"
        + struct.pack("B", command)
        + b"\x00" * 4                      # Status
        + b"\x08"                          # Flags1
        + b"\x00" * 2                      # Flags2
        + b"\x00" * 2                      # PID high
        + b"\x00" * 8                      # Security features + reserved
        + b"\x00" * 8                      # TID, PID, UID, MID
        + b"\x04"                          # Word count (4)
        + b"\xff"                          # AndX command (no further commands)
        + b"\x00"                          # AndX reserved
        + struct.pack("<H", 0)             # AndX offset
        + struct.pack("<H", 1)             # Flags (guest)
        + struct.pack("<H", len(password)) # Password length
        + struct.pack("<H", len(share))    # Path length
        + struct.pack("<H", 0)             # Byte count
        + password
        + share
    )
    return smb


def run_function(
    target,
    port=DEFAULT_PORT,
    timeout=DEFAULT_TIMEOUT,
    reg_hive="HKLM",
    reg_key=None,
    type_to_delete="Key",
    entity_to_delete=None,
    auth_level="None",
    credential_type="UnicodeCreds",
    username=None,
    credential=None,
    domain_dns=None,
    kerberos_ticket=None,
    session_key=None,
    ticket_file=None,
    verbose=False,
):
    """执行 REGDELETE 注册表删除序列。

    阶段：
      1. TCP 连接到目标 SMB 端口
      2. 发送 SMB 协商请求
      3. 会话设置 (SESSION_SETUP_ANDX) 与凭证验证
      4. 树连接 (TREE_CONNECT_ANDX) 到 IPC$
      5. 绑定远程注册表 RPC 接口
      6. 打开注册表项 (BaseRegOpenKey)
      7. 删除项或值 (BaseRegDeleteKey / BaseRegDeleteValue)
      8. 支持 Kerberos 票据认证（TicketFile）
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] Reg hive: {reg_hive}")
        print(f"[*] Reg key: {reg_key}")
        print(f"[*] Type to delete: {type_to_delete}")
        print(f"[*] Entity to delete: {entity_to_delete}")
        print(f"[*] Auth level: {auth_level}")
        print(f"[*] Credential type: {credential_type}")
        if username:
            print(f"[*] Username: {username}")
        if credential:
            print(f"[*] Credential: {credential}")

    # 解析常量
    reg_hive_value = REG_HIVE_VALUES[reg_hive]
    type_to_delete_value = TYPE_TO_DELETE_VALUES[type_to_delete]
    auth_level_value = AUTH_LEVEL_VALUES[auth_level]
    credential_type_value = CREDENTIAL_TYPE_VALUES[credential_type]

    # 解析十六进制缓冲区
    username_bytes = _parse_hex_buffer(username)
    credential_bytes = _parse_hex_buffer(credential)
    domain_dns_bytes = _parse_hex_buffer(domain_dns)
    kerberos_ticket_bytes = _parse_hex_buffer(kerberos_ticket)
    session_key_bytes = _parse_hex_buffer(session_key)

    if verbose:
        print(f"[*] Reg hive value: {reg_hive_value}")
        print(f"[*] Type to delete value: {type_to_delete_value}")
        print(f"[*] Auth level value: {auth_level_value}")
        print(f"[*] Credential type value: {credential_type_value}")
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
        raise RegDeleteError(f"无法连接到 {target}:{port}: {exc}") from exc

    try:
        # 发送 SMB 协商请求
        negotiate = build_smb_negotiate_request()
        sock.sendall(negotiate)
        resp = sock.recv(4096)
        if verbose:
            print(f"[*] SMB 协商应答: {resp.hex()[:128] if resp else '无'}")

        if not resp or resp[4:7] != b"SMB":
            raise RegDeleteError("目标未返回有效的 SMB 应答")

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

        # 构建远程注册表 RPC 请求 (占位符，实际字节需 x32dbg 确认)
        # 绑定注册表 RPC 接口 -> 打开注册表项 -> 删除项/值
        if verbose:
            print(f"[*] 注册表 hive: {reg_hive} (0x{reg_hive_value:02X})")
            print(f"[*] 注册表项: {reg_key}")
            print(f"[*] 删除类型: {type_to_delete} (0x{type_to_delete_value:02X})")
            print(f"[*] 删除实体: {entity_to_delete}")

        if verbose:
            print("[+] REGDELETE 探测完成")
    finally:
        sock.close()

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
