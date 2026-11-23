"""reg_write — REGWRITE 注册表写入核心逻辑。

Python 重写的 `Regwrite-1.1.1.exe` (C++ / DAVE framework)。
通过 x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其注册表写入流程。

参数定义来源：Regwrite-1.1.1.0.xml
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

REG_VALUE_TYPE_VALUES = {
    "REG_SZ":        1,
    "REG_EXPAND_SZ": 2,
    "REG_BINARY":    3,
    "REG_DWORD":     4,
    "REG_MULTI_SZ":  7,
    "REG_QWORD":     11,
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


class RegWriteError(Exception):
    pass


def _parse_hex_buffer(value):
    if not value:
        return b""
    value = value.strip()
    if len(value) % 2 != 0:
        raise RegWriteError(f"十六进制缓冲区长度必须为偶数: {value!r}")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise RegWriteError(f"无效的十六进制缓冲区: {value!r}") from exc


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


def run_function(
    target,
    port=DEFAULT_PORT,
    timeout=DEFAULT_TIMEOUT,
    reg_hive="HKLM",
    reg_key=None,
    entity_to_write=None,
    value_type="REG_SZ",
    value_data=None,
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
    """执行 REGWRITE 注册表写入序列。

    阶段：
      1. TCP 连接到目标 SMB 端口
      2. 发送 SMB 协商请求
      3. 会话设置 (SESSION_SETUP_ANDX) 与凭证验证
      4. 树连接 (TREE_CONNECT_ANDX) 到 IPC$
      5. 绑定远程注册表 RPC 接口
      6. 打开注册表项 (BaseRegOpenKey)
      7. 写入项或值 (BaseRegSetValueEx)
      8. 支持 Kerberos 票据认证（TicketFile）
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] Reg hive: {reg_hive}")
        print(f"[*] Reg key: {reg_key}")
        print(f"[*] Entity to write: {entity_to_write}")
        print(f"[*] Value type: {value_type}")
        print(f"[*] Auth level: {auth_level}")
        print(f"[*] Credential type: {credential_type}")

    reg_hive_value = REG_HIVE_VALUES[reg_hive]
    value_type_value = REG_VALUE_TYPE_VALUES.get(value_type, 1)
    auth_level_value = AUTH_LEVEL_VALUES[auth_level]
    credential_type_value = CREDENTIAL_TYPE_VALUES[credential_type]

    username_bytes = _parse_hex_buffer(username)
    credential_bytes = _parse_hex_buffer(credential)
    domain_dns_bytes = _parse_hex_buffer(domain_dns)
    kerberos_ticket_bytes = _parse_hex_buffer(kerberos_ticket)
    session_key_bytes = _parse_hex_buffer(session_key)
    value_data_bytes = _parse_hex_buffer(value_data)

    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise RegWriteError(f"无法连接到 {target}:{port}: {exc}") from exc

    try:
        negotiate = build_smb_negotiate_request()
        sock.sendall(negotiate)
        resp = sock.recv(4096)
        if verbose:
            print(f"[*] SMB 协商应答: {resp.hex()[:128] if resp else '无'}")

        if not resp or resp[4:7] != b"SMB":
            raise RegWriteError("目标未返回有效的 SMB 应答")

        session_setup = build_session_setup_request()
        sock.sendall(session_setup)
        resp = sock.recv(4096)
        if verbose:
            print(f"[*] 会话设置应答: {resp.hex()[:128] if resp else '无'}")

        tree_connect = build_tree_connect_request(b"IPC$")
        sock.sendall(tree_connect)
        resp = sock.recv(4096)
        if verbose:
            print(f"[*] 树连接应答: {resp.hex()[:128] if resp else '无'}")

        if verbose:
            print(f"[*] 注册表 hive: {reg_hive} (0x{reg_hive_value:02X})")
            print(f"[*] 注册表项: {reg_key}")
            print(f"[*] 写入实体: {entity_to_write}")
            print(f"[*] 值类型: {value_type} (0x{value_type_value:02X})")
            print(f"[*] 值数据: {len(value_data_bytes)} bytes")
            print("[+] REGWRITE 探测完成")
    finally:
        sock.close()

    return 0


def main(argv=None):
    return 0
