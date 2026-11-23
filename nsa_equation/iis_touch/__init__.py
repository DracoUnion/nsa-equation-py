"""iis-touch — IISTOUCH / Iistouch IIS 触摸/探测工具。

Python 重写的 NSA Iistouch 探测工具 `Iistouch-1.2.2.exe`
(C++ / DAVE framework)，通过 IDA Pro / x32dbg 逆向恢复。
实现了该工具的 key=value 参数接口及其 IIS 触摸探测流程。
"""

from . import iis_touch


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def iis_touch_handle(args):
    """Run the IISTOUCH probing sequence against the supplied host."""
    return iis_touch.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        enable_ssl=args.enable_ssl,
        host_string=args.host_string,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `iis-touch` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "iis-touch",
        help="IISTOUCH / Iistouch IIS 触摸/探测工具",
        description="Python 重写的 NSA Iistouch (IISTOUCH) IIS 触摸/探测工具 "
                    "Iistouch-1.2.2。通过 HTTP 协议探测目标 IIS 版本、操作系统、"
                    "语言、服务包、WebDAV 等信息。",
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
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=iis_touch_handle)
