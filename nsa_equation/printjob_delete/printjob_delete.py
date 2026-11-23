"""printjob_delete — PRINTJOBDELETE 打印作业删除核心逻辑。

Python 重写的 `Printjobdelete-1.0.0.exe` (C++ / DAVE framework)。
通过 IDA Pro / x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其打印作业删除流程。

参数定义来源：Printjobdelete-1.0.0.0.xml
"""

import socket
import struct
import sys

# ---------------------------------------------------------------------------
# 常量（来自 XML config 的 <inputparameters>）
# ---------------------------------------------------------------------------

DEFAULT_PORT = 445
DEFAULT_TIMEOUT = 60

PROTOCOL_VALUES = {
    "SMB": 0,
    "NBT": 1,
}

CREDENTIAL_TYPE_VALUES = {
    "Anonymous":    0,
    "Guest":        1,
    "No password":  2,
    "Password":     3,
    "NTLM hash":    4,
    "Both hashes":  5,
}


class PrintJobDeleteError(Exception):
    pass


def _parse_hex_buffer(value):
    """将十六进制字符串解析为字节串。空字符串返回 b""。"""
    if not value:
        return b""
    value = value.strip()
    if len(value) % 2 != 0:
        raise PrintJobDeleteError(f"十六进制缓冲区长度必须为偶数: {value!r}")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise PrintJobDeleteError(f"无效的十六进制缓冲区: {value!r}") from exc


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
    credentials="Anonymous",
    username=None,
    password=None,
    ntlm_hash=None,
    lanman_hash=None,
    printer_name=None,
    job_id=None,
    verbose=False,
):
    """执行 PRINTJOBDELETE 删除序列。

    当前阶段：完成参数解析、SMB/NBT 连接与协商。
    具体打印作业删除逻辑（会话设置、树连接、打印机句柄获取、
    作业删除等）的二进制结构尚需通过 capstone/x32dbg 进一步逆向后
    填充。
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Protocol: {protocol}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] Credentials: {credentials}")
        print(f"[*] Printer name: {printer_name}")
        print(f"[*] Job ID: {job_id}")

    # 解析常量
    protocol_value = PROTOCOL_VALUES[protocol]
    credentials_value = CREDENTIAL_TYPE_VALUES[credentials]

    # 解析十六进制缓冲区
    username_bytes = _parse_hex_buffer(username)
    password_bytes = _parse_hex_buffer(password)
    ntlm_hash_bytes = _parse_hex_buffer(ntlm_hash)
    lanman_hash_bytes = _parse_hex_buffer(lanman_hash)

    if verbose:
        print(f"[*] Protocol value: {protocol_value}")
        print(f"[*] Credentials value: {credentials_value}")
        print(f"[*] Username: {len(username_bytes)} bytes")
        print(f"[*] Password: {len(password_bytes)} bytes")
        print(f"[*] NTLM hash: {len(ntlm_hash_bytes)} bytes")
        print(f"[*] LANMAN hash: {len(lanman_hash_bytes)} bytes")

    # 建立 TCP 连接（SMB 445 / NBT 139）
    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise PrintJobDeleteError(f"无法连接到 {target}:{port}: {exc}") from exc

    # 发送 SMB 协商请求（探测阶段）
    negotiate = build_smb_negotiate_request()
    try:
        sock.sendall(negotiate)
        resp = sock.recv(4096)
    except OSError as exc:
        sock.close()
        raise PrintJobDeleteError(f"SMB 协商失败: {exc}") from exc

    if verbose:
        print(f"[*] SMB 协商应答: {resp.hex()[:128]}...")

    sock.close()

    # TODO: 以下打印作业删除逻辑需通过 IDA/x32dbg 逆向后填充：
    #   - 会话设置 (SESSION_SETUP_ANDX) 与凭证验证
    #   - 树连接 (TREE_CONNECT_ANDX) 到 IPC$
    #   - 打印机句柄获取 (OpenPrinter / GetPrinter)
    #   - 打印作业删除 (DeleteJob / SetJob with JOB_CONTROL_DELETE)
    #   - 输出删除结果

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
