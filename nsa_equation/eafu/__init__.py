"""eafu — EAFU (Equation AFU) 远程利用。

Python 重写的 NSA EAFU 工具 `EAFU.exe`
(C++ / DAVE framework)，通过 IDA Pro / x32dbg 逆向恢复。
实现了该工具的 key=value 参数接口及其远程利用流程。
"""

from . import eafu


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def eafu_handle(args):
    """Run the EAFU exploitation sequence against the supplied host."""
    return eafu.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `eafu` subcommand on an argparse
    subparsers group."""
    p = subparsers.add_parser(
        "eafu",
        help="EAFU (Equation AFU) 远程利用",
        description="Python 重写的 NSA EAFU (Equation AFU) 远程利用工具 "
                    "EAFU.exe。通过 TCP 连接执行远程利用。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP",
    )
    p.add_argument(
        "-p", "--port", type=int, default=445,
        help="目标端口（默认 445）",
    )
    p.add_argument(
        "--timeout", type=int, default=60,
        help="阻塞网络调用超时秒（-1 表示无超时，默认 60）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=eafu_handle)
