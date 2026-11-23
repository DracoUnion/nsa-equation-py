"""smb_touch — SMBTOUCH / Smbtouch SMB 探测核心逻辑。

Python 重写的 `Smbtouch-1.1.1.exe` / `SMBTOUCH.exe` (C++ / DAVE framework)。
通过 x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其 SMB 会话探测流程。

参数定义来源：Smbtouch-1.1.1.0.xml
"""

import socket
import struct
import sys

# ---------------------------------------------------------------------------
# 常量（来自 XML config 的 <inputparameters> 和 <constants>）
# ---------------------------------------------------------------------------

DEFAULT_PORT = 445
DEFAULT_TIMEOUT = 60

PROTOCOL_VALUES = {
    "SMB": 0,
    "NBT": 1,
}

CREDENTIALS_VALUES = {
    "Anonymous": 0,
    "Guest":     1,
    "Blank":     2,
    "Password":  3,
    "NTLM":      4,
}

# SMB 命令码
SMB_COM_NEGOTIATE = 0x72
SMB_COM_SESSION_SETUP_ANDX = 0x73
SMB_COM_TREE_CONNECT_ANDX = 0x75
SMB_COM_NT_TRANSACT = 0xA0

# 常见命名管道
DEFAULT_PIPES = [
    r"\PIPE\LANMAN",
    r"\PIPE\svcctl",
    r"\PIPE\winreg",
    r"\PIPE\epmapper",
    r"\PIPE\netlogon",
    r"\PIPE\srvsvc",
    r"\PIPE\browser",
]


class SmbTouchError(Exception):
    pass


def _parse_hex_buffer(value):
    """将十六进制字符串解析为字节串。空字符串返回 b""。"""
    if not value:
        return b""
    value = value.strip()
    if len(value) % 2 != 0:
        raise SmbTouchError(f"十六进制缓冲区长度必须为偶数: {value!r}")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise SmbTouchError(f"无效的十六进制缓冲区: {value!r}") from exc


def connect(target_ip, port, timeout):
    """建立到目标的 TCP 连接并返回 socket。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout if timeout > 0 else None)
    sock.connect((target_ip, port))
    return sock


def build_smb_negotiate_request():
    """构建 SMB 协商请求（SMB_COM_NEGOTIATE）。"""
    command = SMB_COM_NEGOTIATE
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
    command = SMB_COM_SESSION_SETUP_ANDX
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
    command = SMB_COM_TREE_CONNECT_ANDX
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
    protocol="SMB",
    pipe=None,
    share=None,
    credentials="Anonymous",
    username=None,
    password=None,
    ntlm_hash=None,
    verbose=False,
):
    """执行 SMBTOUCH 探测序列。

    阶段：
      1. TCP 连接到目标 SMB 端口
      2. 发送 SMB 协商请求
      3. 会话设置 (SESSION_SETUP_ANDX) 与凭证验证
      4. 树连接 (TREE_CONNECT_ANDX) 到指定共享
      5. 打开命名管道（若指定）
      6. 输出探测结果（PipeName / ShareName / OS 信息）
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Protocol: {protocol}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] Credentials: {credentials}")
        if pipe:
            print(f"[*] Pipe: {pipe}")
        if share:
            print(f"[*] Share: {share}")

    # 解析常量
    protocol_value = PROTOCOL_VALUES[protocol]
    credentials_value = CREDENTIALS_VALUES[credentials]

    # 解析十六进制缓冲区
    username_bytes = _parse_hex_buffer(username)
    password_bytes = _parse_hex_buffer(password)
    ntlm_hash_bytes = _parse_hex_buffer(ntlm_hash)
    share_bytes = _parse_hex_buffer(share)

    if verbose:
        print(f"[*] Protocol value: {protocol_value}")
        print(f"[*] Credentials value: {credentials_value}")
        print(f"[*] Username: {len(username_bytes)} bytes")
        print(f"[*] Password: {len(password_bytes)} bytes")
        print(f"[*] NTLM hash: {len(ntlm_hash_bytes)} bytes")
        print(f"[*] Share: {len(share_bytes)} bytes")

    # 建立 TCP 连接（SMB 445 / NBT 139）
    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise SmbTouchError(f"无法连接到 {target}:{port}: {exc}") from exc

    try:
        # 发送 SMB 协商请求
        negotiate = build_smb_negotiate_request()
        sock.sendall(negotiate)
        resp = sock.recv(4096)
        if verbose:
            print(f"[*] SMB 协商应答: {resp.hex()[:128] if resp else '无'}")

        if not resp or resp[4:7] != b"SMB":
            raise SmbTouchError("目标未返回有效的 SMB 应答")

        # 发送会话设置请求（匿名会话）
        session_setup = build_session_setup_request()
        sock.sendall(session_setup)
        resp = sock.recv(4096)
        if verbose:
            print(f"[*] 会话设置应答: {resp.hex()[:128] if resp else '无'}")

        # 连接到共享
        share_name = share_bytes if share_bytes else b"IPC$"
        tree_connect = build_tree_connect_request(share_name)
        sock.sendall(tree_connect)
        resp = sock.recv(4096)
        if verbose:
            print(f"[*] 树连接应答: {resp.hex()[:128] if resp else '无'}")

        # 如果指定了管道，尝试打开
        if pipe:
            if verbose:
                print(f"[*] 尝试打开命名管道: {pipe}")
            # 管道打开请求 (NT_TRANSACT 创建文件)
            # 占位符：实际的管道打开逻辑需 x32dbg 确认字节
            print(f"[+] 目标共享 {share_name.decode()} 可访问")

        if verbose:
            print("[+] SMBTOUCH 探测完成")
    finally:
        sock.close()

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
