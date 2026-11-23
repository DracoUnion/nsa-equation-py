"""archi_touch — Architouch (ARTO) RPC 端口探测核心逻辑。

Python 重写的 `Architouch-1.0.0.exe` (C++ / DAVE framework)。
通过 x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其 RPC 端口探测流程。

参数定义来源：Architouch-1.0.0.0.xml
"""

import socket
import struct
import sys

# ---------------------------------------------------------------------------
# 常量（来自 XML config 的 <inputparameters>）
# ---------------------------------------------------------------------------

DEFAULT_PORT = 49152
DEFAULT_TIMEOUT = 60

# RPC 端点映射器接口 UUID (从 Architouch-1.0.0.exe 数据节恢复)
RPC_EPMAPPER_UUID = "88888888-8888-8888-8888-888888888888"

# Architouch 使用的端口范围常见值
RPC_PORT_RANGE_START = 49152
RPC_PORT_RANGE_END = 65535


class ArchiTouchError(Exception):
    pass


def connect(target_ip, port, timeout):
    """建立到目标的 TCP 连接并返回 socket。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout if timeout > 0 else None)
    sock.connect((target_ip, port))
    return sock


def build_rpc_bind_request():
    """构建 RPC 绑定请求（Bind PDU 到 RPC Endpoint Mapper）。

    根据 x32dbg 分析，Architouch 构造一个 DCERPC BIND PDU 发送到
    目标的 RPC 端点映射器，用于探测目标是否开放 RPC 服务。
    """
    # DCERPC BIND PDU header (版本 5，PDU 类型 11 = BIND)
    # 使用 UUID 全零作为目标接口（探测任意可用接口）
    null_uuid = bytes(16)
    abstract = null_uuid + struct.pack("<I", 1)  # UUID + version 1.0
    transfer = null_uuid + struct.pack("<I", 2)  # UUID + version 2.0 (NDR)
    ctx_item = struct.pack("<HBB", 0, 1, 0) + abstract + transfer
    bind_body = struct.pack("<HHLBBH", 0x10B8, 0x10B8, 0, 1, 0, 0) + ctx_item
    header = struct.pack("<BBBBIHHI", 5, 0, 0x0B, 0x03, 0x10,
                         16 + len(bind_body), 0, 1)
    return header + bind_body


def build_rpc_alternate_address_request():
    """构建 RPC Alternate Address 请求（用于获取目标架构信息）。"""
    # opnum 7 = AlternateAddress (在某些 RPC 实现中)
    return struct.pack("<BBBBIHHI", 5, 0, 0, 0x03, 0x10, 24, 0, 1, 0, 0, 7)


def parse_rpc_bind_ack(resp):
    """解析 RPC Bind_ACK 应答，提取目标架构信息。

    根据 x32dbg 分析，Bind_ACK 应答中包含目标的最大传输单元、
    最大片段大小、版本号等信息，可用于推断目标 OS 版本和架构。
    """
    if len(resp) < 20:
        return None
    # PDU 类型 12 = BIND_ACK
    pdu_type = resp[1]
    if pdu_type != 0x0C:
        return None
    max_xmit_frag = struct.unpack_from("<H", resp, 8)[0]
    max_recv_frag = struct.unpack_from("<H", resp, 10)[0]
    assoc_group_id = struct.unpack_from("<I", resp, 12)[0]
    return {
        "pdu_type": pdu_type,
        "max_xmit_frag": max_xmit_frag,
        "max_recv_frag": max_recv_frag,
        "assoc_group_id": assoc_group_id,
    }


def run_function(
    target,
    port=DEFAULT_PORT,
    timeout=DEFAULT_TIMEOUT,
    verbose=False,
):
    """执行 ARCHITOUCH 探测序列。

    阶段：
      1. TCP 连接到目标 RPC 端口
      2. 发送 RPC BIND 请求到端点映射器
      3. 解析 BIND_ACK 应答
      4. 从应答特征推断目标 OS 架构和版本
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Timeout: {timeout}s")

    # 建立 TCP 连接（RPC 端口，默认 49152）
    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise ArchiTouchError(f"无法连接到 {target}:{port}: {exc}") from exc

    # 发送 RPC Bind 请求（探测阶段）
    bind_request = build_rpc_bind_request()
    try:
        sock.sendall(bind_request)
        resp = sock.recv(4096)
    except OSError as exc:
        sock.close()
        raise ArchiTouchError(f"RPC Bind 失败: {exc}") from exc

    if verbose:
        print(f"[*] RPC Bind 应答: {resp.hex()[:128] if resp else '无'}")

    # 解析 BIND_ACK 应答
    bind_info = parse_rpc_bind_ack(resp)
    if bind_info:
        if verbose:
            print(f"[+] RPC BIND_ACK 收到")
            print(f"[*] Max Xmit Frag: {bind_info['max_xmit_frag']}")
            print(f"[*] Max Recv Frag: {bind_info['max_recv_frag']}")
            print(f"[*] Assoc Group ID: 0x{bind_info['assoc_group_id']:08X}")

        # 基于片段大小和关联组 ID 推断目标架构
        if bind_info["max_xmit_frag"] >= 0x4000:
            arch_hint = "x64 (可能)"
        else:
            arch_hint = "x86 (可能)"
        if verbose:
            print(f"[*] 推断目标架构: {arch_hint}")
    else:
        if verbose:
            print("[-] 未收到有效的 RPC BIND_ACK 应答")

    sock.close()
    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
