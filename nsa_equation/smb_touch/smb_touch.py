"""smb_touch — SMBTOUCH / Smbtouch SMB 探测核心逻辑。

Python 重写的 `Smbtouch-1.1.1.exe` / `SMBTOUCH.exe` (C++ / DAVE framework)。
通过 IDA Pro / x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
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
    pipe=None,
    share=None,
    credentials="Anonymous",
    username=None,
    password=None,
    ntlm_hash=None,
    verbose=False,
):
    """执行 SMBTOUCH 探测序列。

    当前阶段：完成参数解析、SMB/NBT 连接与协商。
    具体探测逻辑（管道访问、共享访问、会话设置与 OS 架构识别等）的
    二进制结构尚需通过 capstone/x32dbg 进一步逆向后填充。
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Protocol: {protocol}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] Credentials: {credentials}")
        if pipe:
            print(f"[*] Pipe: {pipe}")
        if share:
            print(f"[*] Share: {share.hex()}")

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

    # 发送 SMB 协商请求（探测阶段）
    negotiate = build_smb_negotiate_request()
    try:
        sock.sendall(negotiate)
        resp = sock.recv(4096)
    except OSError as exc:
        sock.close()
        raise SmbTouchError(f"SMB 协商失败: {exc}") from exc

    if verbose:
        print(f"[*] SMB 协商应答: {resp.hex()[:128]}...")

    sock.close()

    # TODO: 以下探测逻辑需通过 IDA/x32dbg 逆向后填充：
    #   - 会话设置 (SESSION_SETUP_ANDX) 与凭证验证
    #   - 树连接 (TREE_CONNECT_ANDX) 到 IPC$ 管道
    #   - 管道访问测试 (Pipe 参数)
    #   - 共享访问测试 (Share 参数)
    #   - OS 版本与架构识别 (Target, TargetOsArchitecture)
    #   - 输出 PipeName / ShareName / Protocol / Credentials 等

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
