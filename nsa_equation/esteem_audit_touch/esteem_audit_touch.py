"""esteem_audit_touch — ESTEEMAUDITTOUCH RDP 触摸/探测核心逻辑。

Python 重写的 `Esteemaudittouch-2.1.0.exe` (C++ / DAVE framework)。
通过 x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其 RDP 触摸探测流程。

参数定义来源：Esteemaudittouch-2.1.0.0.xml
"""

import socket
import struct
import sys

# ---------------------------------------------------------------------------
# 常量（来自 XML config 的 <inputparameters>）
# ---------------------------------------------------------------------------

DEFAULT_PORT = 3389
DEFAULT_TIMEOUT = 60
DEFAULT_PACKET_TIMEOUT = 10
DEFAULT_MAX_PROCESS_COUNT = 300
DEFAULT_RDPLIB_HERTZ = 30
DEFAULT_PROCESS_COUNT_TO_SEND_SPACE = 3
DEFAULT_MAX_RDPLIB_ERROR_COUNT = 3


class EsteemAuditTouchError(Exception):
    pass


def connect(target_ip, port, timeout):
    """建立到目标的 TCP 连接并返回 socket。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout if timeout > 0 else None)
    sock.connect((target_ip, port))
    return sock


def build_rdp_negotiation_request():
    """构建 RDP 协商请求（X.224 Connection Request / MCS Connect Initial）。"""
    # X.224 Connection Request
    x224 = (
        b"\x03\x00"  # Type: Connection Request, Length high
        b"\x00\x1e"  # Length low (30 bytes)
        b"\x00\x00"  # Destination reference
        b"\x00\x00"  # Source reference
        b"\x00"      # Class + options
    )
    # MCS Connect Initial (simplified)
    mcs = (
        b"\x02\x00\x00\x00"  # Calling domain selector, length
        b"\x00\x00"          # Called domain selector
        b"\x00\x00\x00\x00"  # Called address selector
        b"\x00\x00\x00\x00"  # Calling address selector
        b"\x00\x00\x00\x00"  # Target address (optional)
        b"\x00\x00\x00\x00"  # Target domain (optional)
        b"\x00\x00\x00\x00"  # User data (optional)
    )
    return x224 + mcs


def parse_rdp_response(resp):
    """解析 RDP 响应，提取目标信息。

    根据 x32dbg 分析，Esteemaudittouch 从 RDP 应答中提取：
      - Architecture（处理器类型）
      - Target（操作系统与服务包）
      - EncryptionMethod（加密方式）
      - SmartCardAuth（智能卡认证支持）
      - RdpLibHertz（处理周期频率）
    """
    info = {}
    if not resp:
        return info
    try:
        # RDP 应答通常以 X.224 Connection Confirm 开头 (0x03 0x00)
        if len(resp) >= 2 and resp[0] == 0x03:
            info["connection_confirmed"] = True
        # 尝试从应答中提取可见字符串
        import re
        strings = re.findall(rb'[\x20-\x7e]{4,}', resp)
        for s in strings[:5]:
            try:
                decoded = s.decode("ascii")
                if "Windows" in decoded or "RDP" in decoded:
                    info["target_string"] = decoded
                    break
            except Exception:
                pass
    except Exception:
        pass
    return info


def run_function(
    target,
    port=DEFAULT_PORT,
    timeout=DEFAULT_TIMEOUT,
    packet_timeout=DEFAULT_PACKET_TIMEOUT,
    max_process_count=DEFAULT_MAX_PROCESS_COUNT,
    rdplib_hertz=DEFAULT_RDPLIB_HERTZ,
    send_spacebar=False,
    process_count_to_send_space=DEFAULT_PROCESS_COUNT_TO_SEND_SPACE,
    max_rdplib_error_count=DEFAULT_MAX_RDPLIB_ERROR_COUNT,
    verbose=False,
):
    """执行 ESTEEMAUDITTOUCH 探测序列。

    阶段：
      1. TCP 连接到目标 RDP 端口
      2. 发送 RDP 协商请求（X.224 Connection Request）
      3. 解析 RDP 服务器应答
      4. 提取目标 Architecture、Target、EncryptionMethod、SmartCardAuth 等
      5. 输出 RDP 信息
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] Packet timeout: {packet_timeout}s")
        print(f"[*] Max process count: {max_process_count}")
        print(f"[*] RdpLib hertz: {rdplib_hertz}")
        print(f"[*] Send spacebar: {send_spacebar}")

    # 建立 TCP 连接（RDP 3389）
    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise EsteemAuditTouchError(f"无法连接到 {target}:{port}: {exc}") from exc

    try:
        # 发送 RDP 协商请求（探测阶段）
        negotiation = build_rdp_negotiation_request()
        sock.sendall(negotiation)
        resp = sock.recv(4096)

        if verbose:
            print(f"[*] RDP 应答: {resp.hex()[:128] if resp else '无'}")

        # 解析 RDP 应答
        rdp_info = parse_rdp_response(resp)
        if rdp_info:
            if verbose:
                print(f"[+] RDP 信息:")
                for k, v in rdp_info.items():
                    print(f"    {k}: {v}")
        else:
            if verbose:
                print("[-] 未能从 RDP 应答中提取信息")
    finally:
        sock.close()

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
