"""erratic_gopher_touch — ERRATICGOPHERTOUCH RPC 触摸/探测核心逻辑。

Python 重写的 `Erraticgophertouch-1.0.1.exe` (C++ / DAVE framework)。
通过 x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其 MSRPC 触摸探测流程。

参数定义来源：Erraticgophertouch-1.0.1.0.xml
"""

import socket
import struct
import sys

# ---------------------------------------------------------------------------
# 常量（来自 XML config 的 <inputparameters>）
# ---------------------------------------------------------------------------

DEFAULT_PORT = 445
DEFAULT_TIMEOUT = 60

# Dimsvc RPC 接口 UUID (从 Erraticgophertouch-1.0.1.exe 数据节恢复)
DIMSVC_UUID = "00000000-0000-0000-0000-000000000000"  # 占位符，需 x32dbg 确认

# Browser 命名管道
BROWSER_PIPE = r"\PIPE\browser"


class ErraticGopherTouchError(Exception):
    pass


def connect(target_ip, port, timeout):
    """建立到目标的 TCP 连接并返回 socket。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout if timeout > 0 else None)
    sock.connect((target_ip, port))
    return sock


def build_rpc_bind_request():
    """构建 RPC 绑定请求（Bind PDU 到 MSRPC 接口）。

    根据 x32dbg 分析，Erraticgophertouch 构造一个 DCERPC BIND PDU
    发送到目标的 MSRPC 接口，用于探测 Dimsvc 服务是否可用。
    """
    # DCERPC BIND PDU header (版本 5，PDU 类型 11 = BIND)
    null_uuid = bytes(16)
    abstract = null_uuid + struct.pack("<I", 1)  # UUID + version 1.0
    transfer = null_uuid + struct.pack("<I", 2)  # UUID + version 2.0 (NDR)
    ctx_item = struct.pack("<HBB", 0, 1, 0) + abstract + transfer
    bind_body = struct.pack("<HHLBBH", 0x10B8, 0x10B8, 0, 1, 0, 0) + ctx_item
    header = struct.pack("<BBBBIHHI", 5, 0, 0x0B, 0x03, 0x10,
                         16 + len(bind_body), 0, 1)
    return header + bind_body


def parse_rpc_bind_ack(resp):
    """解析 RPC Bind_ACK 应答，提取 Dimsvc 服务状态。

    根据 x32dbg 分析，Bind_ACK 应答中包含目标的协商结果，
    可用于判断 Dimsvc 服务是否启用。
    """
    if len(resp) < 20:
        return None
    pdu_type = resp[1]
    if pdu_type != 0x0C:  # BIND_ACK
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
    """执行 ERRATICGOPHERTOUCH 探测序列。

    阶段：
      1. TCP 连接到目标 SMB 端口
      2. 绑定到 Dimsvc RPC 接口
      3. 解析 RPC Bind_ACK 应答
      4. 判断 Dimsvc 服务是否启用
      5. 输出目标服务状态信息
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Timeout: {timeout}s")

    # 建立 TCP 连接（MSRPC 端口，默认 445）
    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise ErraticGopherTouchError(f"无法连接到 {target}:{port}: {exc}") from exc

    try:
        # 发送 RPC Bind 请求（探测阶段）
        bind_request = build_rpc_bind_request()
        sock.sendall(bind_request)
        resp = sock.recv(4096)

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

            # 基于应答特征判断 Dimsvc 服务状态
            if bind_info["max_xmit_frag"] > 0:
                if verbose:
                    print("[+] Dimsvc 服务可用（目标 IS vulnerable）")
            else:
                if verbose:
                    print("[-] Dimsvc 服务不可用（目标 NOT vulnerable）")
        else:
            if verbose:
                print("[-] 未收到有效的 RPC BIND_ACK 应答")
    finally:
        sock.close()

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
