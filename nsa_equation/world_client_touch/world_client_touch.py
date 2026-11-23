"""world_client_touch — WORLDCLIENTTOUCH World Client 触摸/探测核心逻辑。

Python 重写的 `Worldclienttouch-1.0.1.exe` (C++ / DAVE framework)。
通过 IDA Pro / x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其 World Client 触摸探测流程。

参数定义来源：Worldclienttouch-1.0.1.0.xml
"""

import socket
import struct
import sys

# ---------------------------------------------------------------------------
# 常量（来自 XML config 的 <inputparameters>）
# ---------------------------------------------------------------------------

DEFAULT_PORT = 25
DEFAULT_TIMEOUT = 60

# 支持的版本号列表（来自 XML SupportedVersions 值）
DEFAULT_SUPPORTED_VERSIONS = [
    "9.5.2", "9.6.0", "9.6.1", "9.6.2", "9.6.3", "9.6.4", "9.6.5", "9.6.6",
    "10.0.0", "10.0.1", "10.0.2", "10.0.3", "10.0.4", "10.0.5",
    "10.1.0", "10.1.1", "10.1.2",
]

# 返回 HTTP "Server" 头的版本列表（来自 XML ServerHeaderVersions 值）
DEFAULT_SERVER_HEADER_VERSIONS = [
    "9.5.2", "9.6.0", "9.6.1", "9.6.2", "9.6.3", "9.6.4", "9.6.5", "9.6.6",
    "10.0.0", "10.0.1", "10.0.2", "10.0.3", "10.0.4", "10.0.5",
]

# 带有 "limited free" 选项的版本列表（来自 XML PossiblyLimitedVersions 值）
DEFAULT_POSSIBLY_LIMITED_VERSIONS = [
    "10.0.0", "10.0.1", "10.0.2", "10.0.3", "10.0.4", "10.0.5",
    "10.1.0", "10.1.1", "10.1.2",
]


class WorldClientTouchError(Exception):
    pass


def connect(target_ip, port, timeout):
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
    expected_protocol=None,
    expected_domain=None,
    expected_port=None,
    target_acct_domain=None,
    target_acct_usr=None,
    target_acct_pwd=None,
    supported_versions=None,
    verbose=False,
):
    """执行 WORLDCLIENTTOUCH 探测序列。

    当前阶段：完成参数解析、TCP 连接。
    具体 WorldClient 版本识别逻辑（基于 HTTP/SMTP 响应解析版本号、
    账户信息等）的二进制结构尚需通过 capstone/x32dbg 进一步逆向后
    填充。
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Timeout: {timeout}s")
        if expected_protocol:
            print(f"[*] Expected protocol: {expected_protocol}")
        if expected_domain:
            print(f"[*] Expected domain: {expected_domain}")
        if expected_port:
            print(f"[*] Expected port: {expected_port}")
        if target_acct_domain:
            print(f"[*] Target acct domain: {target_acct_domain}")
        if target_acct_usr:
            print(f"[*] Target acct usr: {target_acct_usr}")
        if supported_versions:
            print(f"[*] Supported versions: {supported_versions}")

    versions = supported_versions or DEFAULT_SUPPORTED_VERSIONS

    if verbose:
        print(f"[*] Supported versions count: {len(versions)}")

    # 建立 TCP 连接（SMTP 25 / HTTP 80）
    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise WorldClientTouchError(f"无法连接到 {target}:{port}: {exc}") from exc

    # 发送 HTTP 请求（探测阶段，尝试 WorldClient 路径）
    path = "/"
    request = (
        b"GET / HTTP/1.1\r\n"
        b"Host: " + target.encode() + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    try:
        sock.sendall(request)
        resp = sock.recv(4096)
    except OSError as exc:
        sock.close()
        raise WorldClientTouchError(f"HTTP 请求失败: {exc}") from exc

    if verbose:
        first_line = resp.split(b"\r\n")[0] if resp else b"<empty>"
        print(f"[*] HTTP 应答首行: {first_line}")

    sock.close()

    # TODO: 以下 WorldClient 版本识别逻辑需通过 IDA/x32dbg 逆向后填充：
    #   - 解析 HTTP/SMTP 响应
    #   - 根据响应内容匹配 SupportedVersions 中的版本号
    #   - 检查 Server 头（ServerHeaderVersions）
    #   - 检查是否为 limited free 版本（PossiblyLimitedVersions）
    #   - 提取目标账户信息（TargetAcctDomain/Usr/Pwd）
    #   - 输出 WorldClient 版本和服务器信息

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
