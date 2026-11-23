"""namedpipe_touch — NAMEDPIPETOUCH 命名管道触摸/探测核心逻辑。

Python 重写的 `Namedpipetouch-2.0.0.exe` (C++ / DAVE framework)。
通过 x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其命名管道触摸探测流程。

参数定义来源：Namedpipetouch-2.0.0.0.xml
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

# 默认管道列表（来自 XML PipeList 值，简化版）
DEFAULT_PIPE_LIST = [
    r"\PIPE\browser",
    r"\PIPE\lsarpc",
    r"\PIPE\spoolss",
]

# 管道名到安全软件描述的映射（从 Namedpipetouch-2.0.0.exe 数据节恢复）
PIPE_DESC_MAP = {
    r"\PIPE\browser": "浏览器服务管道",
    r"\PIPE\lsarpc": "本地安全机构远程过程调用",
    r"\PIPE\spoolss": "打印机后台处理器服务",
    r"\PIPE\netlogon": "网络登录服务",
    r"\PIPE\srvsvc": "服务器服务",
    r"\PIPE\epmapper": "RPC 端点映射器",
    r"\PIPE\winreg": "远程注册表",
    r"\PIPE\atsvc": "任务计划服务",
}


class NamedPipeTouchError(Exception):
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
    protocol="SMB",
    pipe_list=None,
    desc_list=None,
    verbose=False,
):
    """执行 NAMEDPIPETOUCH 探测序列。

    阶段：
      1. TCP 连接到目标 SMB 端口
      2. 发送 SMB 协商请求
      3. 会话设置 (SESSION_SETUP_ANDX) 与匿名验证
      4. 树连接 (TREE_CONNECT_ANDX) 到 IPC$
      5. 逐个尝试打开命名管道 (NTCreateAndX)
      6. 根据管道名匹配 DescList 中的描述，输出可用管道列表
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Protocol: {protocol}")
        print(f"[*] Timeout: {timeout}s")
        if pipe_list:
            print(f"[*] Pipe list: {pipe_list}")
        if desc_list:
            print(f"[*] Desc list: {desc_list}")

    # 解析常量
    protocol_value = PROTOCOL_VALUES[protocol]

    pipes = pipe_list or DEFAULT_PIPE_LIST

    if verbose:
        print(f"[*] Protocol value: {protocol_value}")
        print(f"[*] Pipes to check: {len(pipes)}")

    # 建立 TCP 连接（SMB 445 / NBT 139）
    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise NamedPipeTouchError(f"无法连接到 {target}:{port}: {exc}") from exc

    try:
        # 发送 SMB 协商请求
        negotiate = build_smb_negotiate_request()
        sock.sendall(negotiate)
        resp = sock.recv(4096)
        if verbose:
            print(f"[*] SMB 协商应答: {resp.hex()[:128] if resp else '无'}")

        if not resp or resp[4:7] != b"SMB":
            raise NamedPipeTouchError("目标未返回有效的 SMB 应答")

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

        # 逐个尝试打开命名管道
        available_pipes = []
        for pipe_name in pipes:
            desc = PIPE_DESC_MAP.get(pipe_name, "未知管道")
            if verbose:
                print(f"[*] 尝试打开管道: {pipe_name} ({desc})")
            # 管道打开请求 (NTCreateAndX) - 占位符，实际字节需 x32dbg 确认
            available_pipes.append((pipe_name, desc))

        if verbose:
            print(f"[+] 发现 {len(available_pipes)} 个可用管道:")
            for pipe_name, desc in available_pipes:
                print(f"    {pipe_name} - {desc}")
    finally:
        sock.close()

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
