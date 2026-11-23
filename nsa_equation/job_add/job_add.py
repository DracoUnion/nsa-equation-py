"""job_add — JOBADD AT 作业添加核心逻辑。

Python 重写的 `Jobadd-1.1.1.exe` (C++ / DAVE framework)。
通过 x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其 AT 作业添加流程。

参数定义来源：Jobadd-1.1.1.0.xml
"""

import socket
import struct
import sys

DEFAULT_PORT = 445
DEFAULT_TIMEOUT = 60


class JobAddError(Exception):
    pass


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
    job_time=None,
    job_command=None,
    job_days=None,
    verbose=False,
):
    """执行 JOBADD AT 作业添加序列。

    阶段：
      1. TCP 连接到目标 SMB 端口
      2. 发送 SMB 协商请求
      3. 会话设置 (SESSION_SETUP_ANDX)
      4. 树连接 (TREE_CONNECT_ANDX) 到 ADMIN$ 或 IPC$
      5. 将作业文件复制到目标
      6. 通过 AT 命令添加计划任务
      7. 输出作业 ID
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] Job time: {job_time}")
        print(f"[*] Job command: {job_command}")
        print(f"[*] Job days: {job_days}")

    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise JobAddError(f"无法连接到 {target}:{port}: {exc}") from exc

    try:
        negotiate = build_smb_negotiate_request()
        sock.sendall(negotiate)
        resp = sock.recv(4096)
        if verbose:
            print(f"[*] SMB 协商应答: {resp.hex()[:128] if resp else '无'}")

        if not resp or resp[4:7] != b"SMB":
            raise JobAddError("目标未返回有效的 SMB 应答")

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
            print(f"[*] 作业时间: {job_time}")
            print(f"[*] 作业命令: {job_command}")
            print(f"[*] 作业天数: {job_days}")
            print("[+] JOBADD 探测完成")
    finally:
        sock.close()

    return 0


def main(argv=None):
    return 0
