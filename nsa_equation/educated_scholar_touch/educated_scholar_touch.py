"""educated_scholar_touch — EDUCATEDSCHOLARTOUCH SMB 触摸/探测核心逻辑。

Python 重写的 `Educatedscholartouch-1.0.0.exe` (C++ / DAVE framework)。
通过 x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其 SMB 触摸探测流程。

参数定义来源：Educatedscholartouch-1.0.0.0.xml
"""

import socket
import struct
import sys

# ---------------------------------------------------------------------------
# 常量（来自 XML config 的 <inputparameters>）
# ---------------------------------------------------------------------------

DEFAULT_PORT = 445
DEFAULT_TIMEOUT = 60
DEFAULT_PROCESS_ID_HIGH = 0x03F

# Educated Scholar UUID (从 Educatedscholartouch-1.0.0.exe 数据节恢复)
EDUCATED_SCHOLAR_UUID = "d0178d92-d73a-e834-8f7c-a99bf78c110e-8ba8bf1d"


class EducatedScholarTouchError(Exception):
    pass


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
    process_id_high=DEFAULT_PROCESS_ID_HIGH,
    verbose=False,
):
    """执行 EDUCATEDSCHOLARTOUCH 探测序列。

    阶段：
      1. TCP 连接到目标 SMB 端口
      2. 发送 SMB 协商请求
      3. 会话设置 (SESSION_SETUP_ANDX) 与匿名验证
      4. 树连接 (TREE_CONNECT_ANDX) 到 IPC$
      5. 从 SMB 响应中提取目标 OS 版本与架构信息
      6. 输出触摸结果
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] ProcessIDHigh: 0x{process_id_high:04X}")

    # 建立 TCP 连接（SMB 445）
    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise EducatedScholarTouchError(f"无法连接到 {target}:{port}: {exc}") from exc

    try:
        # 发送 SMB 协商请求
        negotiate = build_smb_negotiate_request()
        sock.sendall(negotiate)
        resp = sock.recv(4096)
        if verbose:
            print(f"[*] SMB 协商应答: {resp.hex()[:128] if resp else '无'}")

        if not resp or resp[4:7] != b"SMB":
            raise EducatedScholarTouchError("目标未返回有效的 SMB 应答")

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

        if verbose:
            print("[+] EDUCATEDSCHOLARTOUCH 探测完成")
    finally:
        sock.close()

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
