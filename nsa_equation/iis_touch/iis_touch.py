"""iis_touch — IISTOUCH / Iistouch IIS 触摸/探测核心逻辑。

Python 重写的 `Iistouch-1.2.2.exe` (C++ / DAVE framework)。
通过 IDA Pro / x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其 IIS 触摸探测流程。

参数定义来源：Iistouch-1.2.2.0.xml
"""

import socket
import struct
import sys

# ---------------------------------------------------------------------------
# 常量（来自 XML config 的 <inputparameters>）
# ---------------------------------------------------------------------------

DEFAULT_PORT = 80
DEFAULT_TIMEOUT = 60
DEFAULT_HOST_STRING = "localhost"


class IisTouchError(Exception):
    pass


def connect(target_ip, port, timeout, enable_ssl=False):
    """建立到目标的 TCP 连接并返回 socket。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout if timeout > 0 else None)
    sock.connect((target_ip, port))
    return sock


def build_http_request(host_string, port, path, enable_ssl=False):
    """构建 HTTP 请求（GET）。"""
    scheme = "https" if enable_ssl else "http"
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_string}:{port}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )
    return request.encode("ascii")


def run_function(
    target,
    port=DEFAULT_PORT,
    timeout=DEFAULT_TIMEOUT,
    enable_ssl=False,
    host_string=DEFAULT_HOST_STRING,
    verbose=False,
):
    """执行 IISTOUCH 探测序列。

    当前阶段：完成参数解析、HTTP 连接与请求。
    具体 IIS 信息识别逻辑（基于 HTTP 响应头解析 IIS 版本、OS、语言、
    服务包、WebDAV 等信息）的二进制结构尚需通过 capstone/x32dbg 进一步
    逆向后填充。
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] SSL: {enable_ssl}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] Host string: {host_string}")

    # 建立 TCP 连接（HTTP 80 / HTTPS 443）
    try:
        sock = connect(target, port, timeout, enable_ssl=enable_ssl)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise IisTouchError(f"无法连接到 {target}:{port}: {exc}") from exc

    # 发送 HTTP 请求（探测阶段）
    path = "/"
    request = build_http_request(host_string, port, path, enable_ssl=enable_ssl)
    try:
        sock.sendall(request)
        resp = sock.recv(4096)
    except OSError as exc:
        sock.close()
        raise IisTouchError(f"HTTP 请求失败: {exc}") from exc

    if verbose:
        first_line = resp.split(b"\r\n")[0] if resp else b"<empty>"
        print(f"[*] HTTP 应答首行: {first_line}")

    sock.close()

    # TODO: 以下 IIS 信息识别逻辑需通过 IDA/x32dbg 逆向后填充：
    #   - 解析 HTTP 响应头（Server: Microsoft-IIS/x.y）
    #   - 提取 verMajor、verMinor（IIS 主版本、次版本）
    #   - 提取 OperatingSystem、Language、ServicePack
    #   - 提取 Path（IIS 目标路径名）
    #   - 提取 webdavFlag（WebDAV 是否启用）
    #   - 输出 IIS 信息

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
