"""archi-touch — Architouch RPC 端口探测工具。

Python 重写的 NSA Architouch 探测工具 `Architouch-1.0.0.exe`
(C++ / DAVE framework)，通过 IDA Pro / x32dbg 逆向恢复。
实现了该工具的 key=value 参数接口及其 RPC 端口探测流程。
"""

from . import archi_touch


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def archi_touch_handle(args):
    """Run the ARCHITOUCH probing sequence against the supplied host."""
    return archi_touch.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `archi-touch` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "archi-touch",
        help="Architouch RPC 端口探测工具",
        description="Python 重写的 NSA Architouch (ARTO) RPC 端口探测工具 "
                    "Architouch-1.0.0。连接到目标 TCP RPC 服务端口，"
                    "探测目标架构信息。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP",
    )
    p.add_argument(
        "-p", "--port", type=int, default=49152,
        help="目标 RPC 端口（默认 49152）",
    )
    p.add_argument(
        "--timeout", type=int, default=60,
        help="阻塞网络调用超时秒（-1 表示无超时，默认 60）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=archi_touch_handle)
