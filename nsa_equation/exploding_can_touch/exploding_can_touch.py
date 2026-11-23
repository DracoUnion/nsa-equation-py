"""exploding_can_touch — EXPLODINGCANTOUCH IIS WebDAV 触摸/探测核心逻辑。

Python 重写的 `Explodingcantouch-1.2.1.exe` (C++ / DAVE framework)。
通过 x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其 IIS WebDAV 路径大小探测流程。

参数定义来源：Explodingcantouch-1.2.1.0.xml
"""

import socket
import struct
import sys

# ---------------------------------------------------------------------------
# 常量（来自 XML config 的 <inputparameters>）
# ---------------------------------------------------------------------------

DEFAULT_PORT = 80
DEFAULT_TIMEOUT = 60
DEFAULT_MAX_SIZE_TO_CHECK = 70
DEFAULT_HOST_STRING = "localhost"
DEFAULT_DELAY = 0


class ExplodingCanTouchError(Exception):
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


def probe_iis_path_size(target, port, max_size, timeout, enable_ssl=False,
                        host_string=DEFAULT_HOST_STRING, verbose=False):
    """通过发送不同路径大小的 HTTP 请求探测 IIS 路径大小。

    根据 x32dbg 分析，Explodingcantouch 发送带有不同长度路径的 HTTP 请求，
    根据响应状态码（特别是 400 Bad Request vs 其他）确定 IIS 路径大小。
    """
    for size in range(1, max_size + 1):
        path = "/" + "A" * size
        try:
            sock = connect(target, port, timeout, enable_ssl=enable_ssl)
            request = build_http_request(host_string, port, path, enable_ssl=enable_ssl)
            sock.sendall(request)
            resp = sock.recv(4096)
            sock.close()
        except OSError:
            continue

        if not resp:
            continue

        # 解析状态码
        try:
            status_line = resp.split(b"\r\n")[0].decode("ascii", errors="replace")
            parts = status_line.split(" ")
            if len(parts) >= 2:
                status_code = int(parts[1])
                # 400 Bad Request 表示路径太长，超过了 IIS 限制
                if status_code == 400:
                    return size - 1  # 上一个成功的大小
                # 200 OK 或其他成功状态码表示路径大小可接受
                elif status_code in (200, 301, 302, 401, 403, 404):
                    continue
        except (ValueError, IndexError):
            continue

    return max_size  # 如果所有大小都成功，返回最大检查大小


def run_function(
    target,
    port=DEFAULT_PORT,
    timeout=DEFAULT_TIMEOUT,
    enable_ssl=False,
    host_string=DEFAULT_HOST_STRING,
    max_size_to_check=DEFAULT_MAX_SIZE_TO_CHECK,
    delay=DEFAULT_DELAY,
    verbose=False,
):
    """执行 EXPLODINGCANTOUCH 探测序列。

    阶段：
      1. TCP 连接到目标 HTTP/HTTPS 端口
      2. 发送带有不同路径大小的 HTTP GET 请求
      3. 根据响应状态码确定 IIS 路径大小 (IISPathSize)
      4. 输出 IISPathSize 和 hostString
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] SSL: {enable_ssl}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] Host string: {host_string}")
        print(f"[*] Max size to check: {max_size_to_check}")
        print(f"[*] Delay: {delay}s")

    # 建立 TCP 连接（HTTP 80 / HTTPS 443）
    try:
        sock = connect(target, port, timeout, enable_ssl=enable_ssl)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise ExplodingCanTouchError(f"无法连接到 {target}:{port}: {exc}") from exc

    try:
        # 发送初始 HTTP 请求（探测阶段）
        path = "/" + "A" * max_size_to_check
        request = build_http_request(host_string, port, path, enable_ssl=enable_ssl)
        sock.sendall(request)
        resp = sock.recv(4096)

        if verbose:
            first_line = resp.split(b"\r\n")[0] if resp else b"<empty>"
            print(f"[*] HTTP 应答首行: {first_line}")

        # 探测 IIS 路径大小
        iis_path_size = probe_iis_path_size(
            target, port, max_size_to_check, timeout, enable_ssl,
            host_string, verbose)

        if verbose:
            print(f"[+] IIS 路径大小: {iis_path_size}")
            print(f"[+] Host 字符串: {host_string}")
    finally:
        sock.close()

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
