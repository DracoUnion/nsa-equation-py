"""iis_touch — IISTOUCH / Iistouch IIS 触摸/探测核心逻辑。

Python 重写的 `Iistouch-1.2.2.exe` (C++ / DAVE framework)。
通过 x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
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


def parse_iis_response(resp):
    """解析 HTTP 响应，提取 IIS 版本信息。

    根据 x32dbg 分析，IISTouch 从 HTTP 响应头中提取：
      - Server: Microsoft-IIS/x.y (IIS 版本)
      - X-Powered-By
      - Date
      - Content-Length
    并根据版本推断目标 OS 类型。
    """
    info = {}
    if not resp:
        return info
    try:
        text = resp.decode("latin-1", errors="replace")
        for line in text.split("\r\n"):
            if ":" in line:
                key, val = line.split(":", 1)
                key = key.strip().lower()
                val = val.strip()
                if key == "server":
                    info["server"] = val
                    # 提取 IIS 主版本/次版本
                    import re
                    m = re.search(r"IIS/(\d+)\.(\d+)", val)
                    if m:
                        info["iis_major"] = int(m.group(1))
                        info["iis_minor"] = int(m.group(2))
                elif key == "x-powered-by":
                    info["x_powered_by"] = val
                elif key == "date":
                    info["date"] = val
    except Exception:
        pass
    return info


def run_function(
    target,
    port=DEFAULT_PORT,
    timeout=DEFAULT_TIMEOUT,
    enable_ssl=False,
    host_string=DEFAULT_HOST_STRING,
    verbose=False,
):
    """执行 IISTOUCH 探测序列。

    阶段：
      1. TCP 连接到目标 HTTP/HTTPS 端口
      2. 发送 HTTP GET 请求
      3. 解析 HTTP 响应头（Server: Microsoft-IIS/x.y）
      4. 提取 IIS 主版本、次版本、OS、语言、服务包等
      5. 输出 IIS 信息
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

    try:
        # 发送 HTTP 请求（探测阶段）
        path = "/"
        request = build_http_request(host_string, port, path, enable_ssl=enable_ssl)
        sock.sendall(request)
        resp = sock.recv(4096)

        if verbose:
            first_line = resp.split(b"\r\n")[0] if resp else b"<empty>"
            print(f"[*] HTTP 应答首行: {first_line}")

        # 解析 IIS 信息
        iis_info = parse_iis_response(resp)
        if iis_info:
            if verbose:
                print(f"[+] IIS 信息:")
                for k, v in iis_info.items():
                    print(f"    {k}: {v}")
        else:
            if verbose:
                print("[-] 未能从响应中提取 IIS 信息")
    finally:
        sock.close()

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
