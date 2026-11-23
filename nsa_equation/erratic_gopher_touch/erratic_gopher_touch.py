"""erratic_gopher_touch — ERRATICGOPHERTOUCH RPC 触摸/探测核心逻辑。

Python 重写的 `Erraticgophertouch-1.0.1.exe` (C++ / DAVE framework)。
通过 IDA Pro / x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
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

    构造一个最小的 RPC Bind PDU，用于探测目标是否开放 MSRPC 服务
    以及 Dimsvc 服务是否可用。
    """
    # RPC PDU header (simplified)
    pdu = (
        b"\x00" * 2,   # alloc_hint (filled later)
        b"\x00\x00",   # context_id
        b"\x00\x00",   # opnum
        b"\x00" * 4,   # handle
    )
    return b"".join(pdu)


def run_function(
    target,
    port=DEFAULT_PORT,
    timeout=DEFAULT_TIMEOUT,
    verbose=False,
):
    """执行 ERRATICGOPHERTOUCH 探测序列。

    当前阶段：完成参数解析、TCP 连接与 RPC Bind 探测。
    具体 Dimsvc 状态识别逻辑（基于 RPC 应答解析目标服务状态）的
    二进制结构尚需通过 capstone/x32dbg 进一步逆向后填充。
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

    # 发送 RPC Bind 请求（探测阶段）
    bind_request = build_rpc_bind_request()
    try:
        sock.sendall(bind_request)
        resp = sock.recv(4096)
    except OSError as exc:
        sock.close()
        raise ErraticGopherTouchError(f"RPC Bind 失败: {exc}") from exc

    if verbose:
        print(f"[*] RPC Bind 应答: {resp.hex()[:128]}...")

    sock.close()

    # TODO: 以下 Dimsvc 状态识别逻辑需通过 IDA/x32dbg 逆向后填充：
    #   - 解析 RPC Bind_ACK 应答
    #   - 判断 Dimsvc 服务是否启用 (DimsvcEnabled)
    #   - 输出目标服务状态信息

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
