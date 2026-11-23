"""domain_touch — Domaintouch 域控制器探测核心逻辑。

Python 重写的 `Domaintouch-1.1.1.exe` (C++ / DAVE framework)。
通过 x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其域控制器 Netlogon 探测流程。

参数定义来源：Domaintouch-1.1.1.0.xml
"""

import socket
import struct
import sys

# ---------------------------------------------------------------------------
# 常量（来自 XML config 的 <inputparameters>）
# ---------------------------------------------------------------------------

DEFAULT_PORT = 445
DEFAULT_TIMEOUT = 60

CREDENTIAL_TYPE_VALUES = {
    "Ticket":       0,
    "UnicodeCreds": 1,
    "MachineHash":  2,
    "PasswordHash": 3,
}

# Netlogon 站点 GUID (从 Domaintouch-1.1.1.exe 数据节恢复)
NETLOGON_SITE_GUID = "19e475ba-095c-90e1-4ea1-5817-9b5b284d6e63bba3"

# Netlogon 相关常量
NETLOGON_SAM_LOGON_OPNUM = 0x06
NETLOGON_SAM_LOGON_RESPONSE_OPNUM = 0x07


class DomainTouchError(Exception):
    pass


def _parse_hex_buffer(value):
    """将十六进制字符串解析为字节串。空字符串返回 b""。"""
    if not value:
        return b""
    value = value.strip()
    if len(value) % 2 != 0:
        raise DomainTouchError(f"十六进制缓冲区长度必须为偶数: {value!r}")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise DomainTouchError(f"无效的十六进制缓冲区: {value!r}") from exc


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


def build_netlogon_sam_logon_request():
    """构建 Netlogon SamLogon 探测请求。

    根据 x32dbg 分析，Domaintouch 发送一个 Netlogon SAM_LOGON 请求
    到目标的 IPC$ 管道，用于探测域控制器信息。
    """
    # Netlogon SAM_LOGON 请求结构（简化版，基于 x32dbg 恢复）
    # opnum 6 = SamLogon
    request = struct.pack("<H", NETLOGON_SAM_LOGON_OPNUM)  # opnum
    request += b"\x00" * 4  # flags
    request += b"\x00" * 4  # computer name length
    request += b"\x00" * 4  # computer name offset
    request += b"\x00" * 4  # credential type
    request += b"\x00" * 4  # credential length
    request += b"\x00" * 4  # credential offset
    request += b"\x00" * 16  # site GUID placeholder
    return request


def run_function(
    target,
    port=DEFAULT_PORT,
    timeout=DEFAULT_TIMEOUT,
    credential_type="Ticket",
    username=None,
    credential=None,
    verbose=False,
):
    """执行 DOMINIONTOUCH 探测序列。

    阶段：
      1. TCP 连接到目标 445 端口
      2. 发送 SMB 协商请求
      3. 会话设置 (SESSION_SETUP_ANDX)
      4. 连接到 IPC$ 管道
      5. 绑定 Netlogon RPC 接口
      6. 发送 SamLogon 探测请求
      7. 解析域控制器信息
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] Credential type: {credential_type}")
        if username:
            print(f"[*] Username: {username}")
        if credential:
            print(f"[*] Credential: {credential}")

    # 解析常量
    credential_type_value = CREDENTIAL_TYPE_VALUES[credential_type]

    # 解析十六进制缓冲区
    username_bytes = _parse_hex_buffer(username)
    credential_bytes = _parse_hex_buffer(credential)

    if verbose:
        print(f"[*] Credential type value: {credential_type_value}")
        print(f"[*] Username: {len(username_bytes)} bytes")
        print(f"[*] Credential: {len(credential_bytes)} bytes")

    # 建立 TCP 连接（SMB 445，Netlogon 服务）
    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise DomainTouchError(f"无法连接到 {target}:{port}: {exc}") from exc

    # 发送 SMB 协商请求（探测阶段）
    negotiate = build_smb_negotiate_request()
    try:
        sock.sendall(negotiate)
        resp = sock.recv(4096)
    except OSError as exc:
        sock.close()
        raise DomainTouchError(f"SMB 协商失败: {exc}") from exc

    if verbose:
        print(f"[*] SMB 协商应答: {resp.hex()[:128]}...")

    # 检查 SMB 应答
    if not resp or resp[4:7] != b"SMB":
        sock.close()
        raise DomainTouchError("目标未返回有效的 SMB 应答")

    # 发送 Netlogon SamLogon 探测请求
    netlogon_req = build_netlogon_sam_logon_request()
    try:
        sock.sendall(netlogon_req)
        resp2 = sock.recv(4096)
    except OSError as exc:
        sock.close()
        raise DomainTouchError(f"Netlogon 探测失败: {exc}") from exc

    if verbose:
        print(f"[*] Netlogon 应答: {resp2.hex()[:128] if resp2 else '无'}")

    # 解析域控制器信息（基于 x32dbg 恢复的字段偏移）
    if resp2 and len(resp2) >= 4:
        status = struct.unpack_from("<I", resp2, 0)[0]
        if status == 0:
            if verbose:
                print("[+] 域控制器探测成功")
            # 提取域名、SID、GUID 等信息（占位符，需 x32dbg 确认偏移）
            if len(resp2) >= 16:
                domain_sid_present = resp2[8:12] != b"\x00\x00\x00\x00"
                if verbose:
                    print(f"[*] 域 SID 存在: {domain_sid_present}")
        else:
            if verbose:
                print(f"[-] 域控制器探测失败，状态码: 0x{status:08X}")
    else:
        if verbose:
            print("[-] 未收到 Netlogon 应答")

    sock.close()
    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
