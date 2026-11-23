"""domain-touch — Domaintouch 域控制器探测工具。

Python 重写的 NSA Domaintouch 探测工具 `Domaintouch-1.1.1.exe`
(C++ / DAVE framework)，通过 IDA Pro / x32dbg 逆向恢复。
实现了该工具的 key=value 参数接口及其域控制器 Netlogon 探测流程。
"""

from . import domain_touch


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def domain_touch_handle(args):
    """Run the DOMINIONTOUCH probing sequence against the supplied host."""
    return domain_touch.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        credential_type=args.credential_type,
        username=args.username,
        credential=args.credential,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `domain-touch` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "domain-touch",
        help="Domaintouch 域控制器 Netlogon 探测工具",
        description="Python 重写的 NSA Domaintouch 域控制器探测工具 "
                    "Domaintouch-1.1.1。通过 SMB/Netlogon 协议探测目标域控制器，"
                    "获取域 NetBIOS 名、DNS 名、SID 和 GUID 等信息。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="域控制器主机名或 IP",
    )
    p.add_argument(
        "-p", "--port", type=int, default=445,
        help="目标 Netlogon/SMB 端口（默认 445）",
    )
    p.add_argument(
        "--timeout", type=int, default=60,
        help="阻塞网络调用超时秒（-1 表示无超时，默认 60）",
    )
    p.add_argument(
        "--credential-type",
        choices=["Ticket", "UnicodeCreds", "MachineHash", "PasswordHash"],
        default="Ticket",
        help="凭证类型（默认 Ticket）",
    )
    p.add_argument(
        "--username", metavar="HEX",
        help="用户名（十六进制字节，Unicode）",
    )
    p.add_argument(
        "--credential", metavar="HEX",
        help="凭证/密码哈希（十六进制字节，Unicode）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=domain_touch_handle)
