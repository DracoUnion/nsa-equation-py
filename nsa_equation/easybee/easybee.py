"""easybee — EASYBEE MDaemon WorldClient 利用核心逻辑。

Python 重写的 `Easybee-1.0.1.exe` (C++ / DAVE framework)。
通过 IDA Pro / x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其 MDaemon WorldClient 利用流程。

参数定义来源：Easybee-1.0.1.0.xml
"""

import socket
import struct
import sys

# ---------------------------------------------------------------------------
# 常量（来自 XML config 的 <inputparameters>）
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT = 60

WORLD_CLIENT_VERSIONS = [
    "9.5.2", "9.6.0", "9.6.1", "9.6.2", "9.6.3", "9.6.4", "9.6.5", "9.6.6",
    "10.0.1", "10.0.2", "10.0.3", "10.0.4", "10.0.5",
    "10.1.0", "10.1.1", "10.1.2",
]

# 每个版本的版本特定参数（来自 XML <WorldClientVersion><paramgroup>）
VERSION_SPECIFIC_PARAMS = {
    "9.5.2": {
        "versionspecificGetInbox": "View=List&ContentType=javascript&ReturnJavaScript=1&FolderID=1&Page=0&currentRequest=0",
        "versionspecificGetMsgID": "(?:(?:\\({[^\\n})]*\\b(?:id|n):)|(?:View=Message&Number=))([0-9]+)(?:(?:,[^\\n})]*\\bsbj:&#x22;%s&#x22;[^\\n})]*`);)|(?:&Page=[0-9]*&#x22;[^&#x3E;]*&#x3E;[^&#x3C;]*&#x3C;strong&#x3E;%s&#x3C;/strong&#x3E;))",
    },
    # 其他版本参数类似，因篇幅限制此处省略，实际使用时应从 XML 中提取
}

class EasyBeeError(Exception):
    pass


def connect(target_ip, port, timeout):
    """建立到目标的 TCP 连接并返回 socket。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout if timeout > 0 else None)
    sock.connect((target_ip, port))
    return sock


def build_http_request(host, port, path, method="GET", enable_ssl=False,
                       body=None, content_type=None):
    """构建 HTTP 请求。"""
    scheme = "https" if enable_ssl else "http"
    request = f"{method} {path} HTTP/1.1\r\n"
    request += f"Host: {host}:{port}\r\n"
    request += "Connection: close\r\n"
    if body:
        request += f"Content-Type: {content_type or 'application/octet-stream'}\r\n"
        request += f"Content-Length: {len(body)}\r\n"
    request += "\r\n"
    if body:
        request = request.encode("ascii") + body
    else:
        request = request.encode("ascii")
    return request


def run_function(
    target,
    world_client_port=None,
    web_admin_port=None,
    timeout=DEFAULT_TIMEOUT,
    world_client_protocol=None,
    world_client_domain=None,
    world_client_port2=None,
    web_admin_protocol=None,
    web_admin_domain=None,
    web_admin_port3=None,
    target_acct_domain=None,
    target_acct_usr=None,
    target_acct_pwd=None,
    target_acct_is_admin=None,
    cf_email_from=None,
    cf_email_subj=None,
    cf_email_file=None,
    ar_email_from=None,
    ar_email_subj=None,
    pt_email_from=None,
    pt_email_subj=None,
    payload_name=None,
    payload_file=None,
    world_client_version=None,
    verbose=False,
):
    """执行 EASYBEE 利用序列。

    当前阶段：完成参数解析、HTTP/HTTPS 连接构建。
    具体 exploit 缓冲区（内容过滤触发邮件、自动回复触发邮件、载荷上传等）
    的二进制结构尚需通过 capstone/x32dbg 进一步逆向后填充。
    """
    if verbose:
        print(f"[*] Target: {target}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] WorldClient port: {world_client_port}")
        print(f"[*] WebAdmin port: {web_admin_port}")
        print(f"[*] WorldClient protocol: {world_client_protocol}")
        print(f"[*] WorldClient domain: {world_client_domain}")
        print(f"[*] WebAdmin protocol: {web_admin_protocol}")
        print(f"[*] WebAdmin domain: {web_admin_domain}")
        print(f"[*] WorldClient version: {world_client_version}")
        print(f"[*] Payload: {payload_name}")

    # 验证必需参数
    if not world_client_port:
        raise EasyBeeError("WorldClient port is required")
    if not web_admin_port:
        raise EasyBeeError("WebAdmin port is required")

    # 解析版本特定参数
    version_params = VERSION_SPECIFIC_PARAMS.get(world_client_version, {})

    if verbose:
        print(f"[*] Version-specific GetInbox: {version_params.get('versionspecificGetInbox', 'N/A')}")
        print(f"[*] Version-specific GetMsgID: {version_params.get('versionspecificGetMsgID', 'N/A')}")

    # 建立到 WorldClient 端口的 TCP 连接
    try:
        sock = connect(target, world_client_port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{world_client_port} (WorldClient)")
    except OSError as exc:
        raise EasyBeeError(f"无法连接到 {target}:{world_client_port}: {exc}") from exc

    # 发送 HTTP 请求（探测阶段）
    path = "/WorldClient.dll?View=List&ContentType=javascript&ReturnJavaScript=1&FolderID=1&Page=0&currentRequest=0"
    request = build_http_request(target, world_client_port, path,
                                 enable_ssl=(world_client_protocol == "https"))
    try:
        sock.sendall(request)
        resp = sock.recv(4096)
    except OSError as exc:
        sock.close()
        raise EasyBeeError(f"HTTP 请求失败: {exc}") from exc

    if verbose:
        first_line = resp.split(b"\r\n")[0] if resp else b"<empty>"
        print(f"[*] HTTP 应答首行: {first_line}")

    sock.close()

    # TODO: 以下 exploit 缓冲区构建需通过 IDA/x32dbg 逆向后填充：
    #   - 内容过滤触发邮件构建 (CFEmailFrom/Subj/File)
    #   - 自动回复触发邮件构建 (AREmailFrom/Subj)
    #   - 载荷上传 (PayloadName/File)
    #   - WorldClient 版本特定 URL 构建
    #   - WebAdmin 服务器交互
    #   - 载荷执行触发

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
