"""namedpipe_touch — NAMEDPIPETOUCH 命名管道触摸/探测核心逻辑。

Python 重写的 `Namedpipetouch-2.0.0.exe` (C++ / DAVE framework)。
通过 IDA Pro / x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
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

    当前阶段：完成参数解析、SMB/NBT 连接与协商。
    具体命名管道探测逻辑（逐个管道尝试打开、识别对应安全软件等）的
    二进制结构尚需通过 capstone/x32dbg 进一步逆向后填充。
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

    # 发送 SMB 协商请求（探测阶段）
    negotiate = build_smb_negotiate_request()
    try:
        sock.sendall(negotiate)
        resp = sock.recv(4096)
    except OSError as exc:
        sock.close()
        raise NamedPipeTouchError(f"SMB 协商失败: {exc}") from exc

    if verbose:
        print(f"[*] SMB 协商应答: {resp.hex()[:128]}...")

    sock.close()

    # TODO: 以下命名管道探测逻辑需通过 IDA/x32dbg 逆向后填充：
    #   - 会话设置 (SESSION_SETUP_ANDX)
    #   - 树连接 (TREE_CONNECT_ANDX) 到 IPC$
    #   - 逐个打开命名管道 (NTCreateAndX 对 \PIPE\*)
    #   - 根据管道名匹配 DescList 中的描述
    #   - 输出可用管道列表和对应的安全软件信息

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
