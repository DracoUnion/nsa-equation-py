"""educated-scholar-touch — EDUCATEDSCHOLARTOUCH SMB 触摸/探测工具。

Python 重写的 NSA Educatedscholartouch 探测工具
`Educatedscholartouch-1.0.0.exe` (C++ / DAVE framework)，通过 IDA Pro /
x32dbg 逆向恢复。实现了该工具的 key=value 参数接口及其 SMB 触摸
探测流程。
"""

from . import educated_scholar_touch


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def educated_scholar_touch_handle(args):
    """Run the EDUCATEDSCHOLARTOUCH probing sequence against the supplied host."""
    return educated_scholar_touch.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        process_id_high=args.process_id_high,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `educated-scholar-touch` subcommand on an argparse
    subparsers group."""
    p = subparsers.add_parser(
        "educated-scholar-touch",
        help="EDUCATEDSCHOLARTOUCH SMB 触摸/探测工具",
        description="Python 重写的 NSA Educatedscholartouch (EDU Touch) SMB "
                    "触摸/探测工具 Educatedscholartouch-1.0.0。通过 SMB 协议"
                    "探测目标主机的可达性与架构信息。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP",
    )
    p.add_argument(
        "-p", "--port", type=int, default=445,
        help="目标 SMB 端口（默认 445）",
    )
    p.add_argument(
        "--timeout", type=int, default=60,
        help="阻塞网络调用超时秒（-1 表示无超时，默认 60）",
    )
    p.add_argument(
        "--process-id-high", type=lambda x: int(x, 0), default=0x03F,
        help="ProcessIDHigh（默认 0x03F）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=educated_scholar_touch_handle)
