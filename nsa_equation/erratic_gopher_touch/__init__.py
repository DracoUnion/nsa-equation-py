"""erratic-gopher-touch — ERRATICGOPHERTOUCH RPC 触摸/探测工具。

Python 重写的 NSA Erraticgophertouch 探测工具
`Erraticgophertouch-1.0.1.exe` (C++ / DAVE framework)，通过 IDA Pro /
x32dbg 逆向恢复。实现了该工具的 key=value 参数接口及其 MSRPC 触摸
探测流程。
"""

from . import erratic_gopher_touch


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def erratic_gopher_touch_handle(args):
    """Run the ERRATICGOPHERTOUCH probing sequence against the supplied host."""
    return erratic_gopher_touch.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `erratic-gopher-touch` subcommand on an argparse
    subparsers group."""
    p = subparsers.add_parser(
        "erratic-gopher-touch",
        help="ERRATICGOPHERTOUCH RPC 触摸/探测工具",
        description="Python 重写的 NSA Erraticgophertouch (ERRATICGOPHER "
                    "Touch) RPC 触摸/探测工具 Erraticgophertouch-1.0.1。通过"
                    " MSRPC 协议探测目标主机的 Dimsvc 服务可达性。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP",
    )
    p.add_argument(
        "-p", "--port", type=int, default=445,
        help="目标 MSRPC 端口（通常为 445 / SMB，139 不可用，默认 445）",
    )
    p.add_argument(
        "--timeout", type=int, default=60,
        help="阻塞网络调用超时秒（-1 表示无超时，默认 60）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=erratic_gopher_touch_handle)
