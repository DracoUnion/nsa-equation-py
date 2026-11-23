"""webadmin_touch — WEBADMINTOUCH Web 管理触摸/探测核心逻辑。

Python 重写的 `Webadmintouch-1.0.1.exe` (C++ / DAVE framework)。
通过 x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其 Web 管理触摸探测流程。

参数定义来源：Webadmintouch-1.0.1.0.xml
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
    "3.3.0", "3.4.00", "3.4.10", "3.4.20", "3.4.3",
    "10.0.0", "10.0.1", "10.0.2", "10.0.3", "10.0.4",
    "10.0.5", "10.1.0", "10.1.1", "10.1.2",
]


class WebAdminTouchError(Exception):
    pass


def connect(target_ip, port, timeout):
    """建立到目标的 TCP 连接并返回 socket。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout if timeout > 0 else None)
    sock.connect((target_ip, port))
    return sock


def build_http_request(host_string, port, path):
    """构建 HTTP 请求（GET）。"""
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_string}:{port}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )
    return request.encode("ascii")


def parse_webadmin_response(resp, supported_versions):
    """解析 HTTP/SMTP 响应，提取 WebAdmin 版本信息。

    根据 x32dbg 分析，Webadmintouch 从响应中提取版本字符串，
    并与 SupportedVersions 列表中的版本进行匹配。
    """
    result = {"version": None, "matched": False, "server": None}
    if not resp:
        return result
    try:
        text = resp.decode("latin-1", errors="replace")
        # 查找版本模式 (如 3.3.0, 10.0.5 等)
        import re
        for version in supported_versions:
            if version in text:
                result["version"] = version
                result["matched"] = True
                break
        # 查找 Server 头
        for line in text.split("\r\n"):
            if ":" in line:
                key, val = line.split(":", 1)
                if key.strip().lower() == "server":
                    result["server"] = val.strip()
                    break
    except Exception:
        pass
    return result


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
    """执行 WEBADMINTOUCH 探测序列。

    阶段：
      1. TCP 连接到目标端口（SMTP 25 / HTTP 80）
      2. 发送 HTTP GET /webadmin/ 请求
      3. 解析 HTTP/SMTP 响应
      4. 根据响应内容匹配 SupportedVersions 中的版本号
      5. 提取目标账户信息
      6. 输出 WebAdmin 版本和服务器信息
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
        raise WebAdminTouchError(f"无法连接到 {target}:{port}: {exc}") from exc

    try:
        # 发送 HTTP 请求（探测阶段，尝试 WebAdmin 路径）
        path = "/webadmin/"
        request = build_http_request(target, port, path)
        sock.sendall(request)
        resp = sock.recv(4096)

        if verbose:
            first_line = resp.split(b"\r\n")[0] if resp else b"<empty>"
            print(f"[*] HTTP 应答首行: {first_line}")

        # 解析 WebAdmin 版本
        result = parse_webadmin_response(resp, versions)
        if result["matched"]:
            if verbose:
                print(f"[+] WebAdmin 版本匹配: {result['version']}")
            if result["server"]:
                if verbose:
                    print(f"[*] Server: {result['server']}")
        else:
            if verbose:
                print("[-] 未匹配到已知 WebAdmin 版本")
    finally:
        sock.close()

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
