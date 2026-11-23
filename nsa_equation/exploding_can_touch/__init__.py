"""exploding-can-touch — EXPLODINGCANTOUCH IIS WebDAV 触摸/探测工具。

Python 重写的 NSA Explodingcantouch 探测工具
`Explodingcantouch-1.2.1.exe` (C++ / DAVE framework)，通过 IDA Pro /
x32dbg 逆向恢复。实现了该工具的 key=value 参数接口及其 IIS WebDAV
路径大小探测流程。
"""

from . import exploding_can_touch


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def exploding_can_touch_handle(args):
    """Run the EXPLODINGCANTOUCH probing sequence against the supplied host."""
    return exploding_can_touch.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        enable_ssl=args.enable_ssl,
        host_string=args.host_string,
        max_size_to_check=args.max_size_to_check,
        delay=args.delay,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `exploding-can-touch` subcommand on an argparse
    subparsers group."""
    p = subparsers.add_parser(
        "exploding-can-touch",
        help="EXPLODINGCANTOUCH IIS WebDAV 触摸/探测工具",
        description="Python 重写的 NSA Explodingcantouch (EXCA Touch) IIS "
                    "WebDAV 触摸/探测工具 Explodingcantouch-1.2.1。通过"
                    " HTTP 请求探测目标 IIS 6.0 WebDAV 路径大小。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP",
    )
    p.add_argument(
        "-p", "--port", type=int, default=80,
        help="目标 HTTP 端口（默认 80，HTTPS 为 443）",
    )
    p.add_argument(
        "--timeout", type=int, default=60,
        help="阻塞网络调用超时秒（-1 表示无超时，默认 60）",
    )
    p.add_argument(
        "--enable-ssl", action="store_true",
        help="为 HTTPS 目标启用 SSL",
    )
    p.add_argument(
        "--host-string", metavar="STR", default="localhost",
        help="HTTP 请求中使用的 Host 字符串（默认 localhost）",
    )
    p.add_argument(
        "--max-size-to-check", type=int, default=70,
        help="路径大小检测最大值（70 覆盖所有可利用大小，130 确保路径大小判定，默认 70）",
    )
    p.add_argument(
        "--delay", type=int, default=0,
        help="每个请求之间等待的秒数（默认 0）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=exploding_can_touch_handle)
