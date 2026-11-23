"""world-client-touch — WORLDCLIENTTOUCH World Client 触摸/探测工具。

Python 重写的 NSA Worldclienttouch 探测工具
`Worldclienttouch-1.0.1.exe` (C++ / DAVE framework)，通过 IDA Pro /
x32dbg 逆向恢复。实现了该工具的 key=value 参数接口及其 World Client
触摸探测流程。
"""

from . import world_client_touch


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def world_client_touch_handle(args):
    """Run the WORLDCLIENTTOUCH probing sequence against the supplied host."""
    return world_client_touch.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        expected_protocol=args.expected_protocol,
        expected_domain=args.expected_domain,
        expected_port=args.expected_port,
        target_acct_domain=args.target_acct_domain,
        target_acct_usr=args.target_acct_usr,
        target_acct_pwd=args.target_acct_pwd,
        supported_versions=args.supported_versions,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `world-client-touch` subcommand on an argparse
    subparsers group."""
    p = subparsers.add_parser(
        "world-client-touch",
        help="WORLDCLIENTTOUCH World Client 触摸/探测工具",
        description="Python 重写的 NSA Worldclienttouch (WorldClientTouch) World "
                    "Client 触摸/探测工具 Worldclienttouch-1.0.1。通过 HTTP/SMTP"
                    "协议探测目标 WorldClient 服务器版本和账户信息。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP",
    )
    p.add_argument(
        "-p", "--port", type=int, default=25,
        help="目标端口（SMTP 默认 25，HTTP 默认 80）",
    )
    p.add_argument(
        "--timeout", type=int, default=60,
        help="阻塞网络调用超时秒（0 表示无超时，默认 60）",
    )
    p.add_argument(
        "--expected-protocol", metavar="PROTO",
        help="WorldClient 协议（http / https）",
    )
    p.add_argument(
        "--expected-domain", metavar="DOMAIN",
        help="WorldClient IPv4 地址",
    )
    p.add_argument(
        "--expected-port", type=int, metavar="PORT",
        help="WorldClient 端口号",
    )
    p.add_argument(
        "--target-acct-domain", metavar="DOMAIN",
        help="目标邮件域",
    )
    p.add_argument(
        "--target-acct-usr", metavar="USER",
        help="目标账户用户名",
    )
    p.add_argument(
        "--target-acct-pwd", metavar="PASS",
        help="目标账户密码",
    )
    p.add_argument(
        "--supported-versions", metavar="VERSIONS",
        help="支持的 WorldClient 版本号列表（Python 列表格式字符串）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=world_client_touch_handle)
