"""smb-list — SMBLIST SMB 目录列表工具。

Python 重写的 NSA Smblist 工具 `Smblist-1.1.1.exe`
(C++ / DAVE framework)，通过 IDA Pro / x32dbg 逆向恢复。
实现了该工具的 key=value 参数接口及其 SMB 目录列表流程。
"""

from . import smb_list


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def smb_list_handle(args):
    """Run the SMBLIST listing sequence against the supplied host."""
    return smb_list.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        share=args.share,
        path=args.path,
        filter=args.filter,
        recursive=args.recursive,
        log_file=args.log_file,
        credential_type=args.credential_type,
        username=args.username,
        credential=args.credential,
        domain_dns=args.domain_dns,
        kerberos_ticket=args.kerberos_ticket,
        session_key=args.session_key,
        ticket_file=args.ticket_file,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `smb-list` subcommand on an argparse
    subparsers group."""
    p = subparsers.add_parser(
        "smb-list",
        help="SMBLIST SMB 目录列表工具",
        description="Python 重写的 NSA Smblist (SMBLIST) SMB 目录列表工具 "
                    "Smblist-1.1.1。通过 SMB 协议列出目标主机共享目录中的"
                    "文件。",
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
        "--share", metavar="SHARE",
        help="目标共享名（如 admin$），字符串或十六进制字节",
    )
    p.add_argument(
        "--path", metavar="PATH",
        help="要列出的路径（如 system32），字符串或十六进制字节",
    )
    p.add_argument(
        "--filter", metavar="FILTER",
        help="文件类型过滤器（如 *.dll / *.exe / *），默认 *",
    )
    p.add_argument(
        "--recursive", action="store_true", default=False,
        help="是否递归列出（默认禁用）",
    )
    p.add_argument(
        "--no-recursive", action="store_false", dest="recursive",
        help="禁用递归列出",
    )
    p.add_argument(
        "--log-file", metavar="FILE",
        help="目录列表日志文件（留空仅输出到屏幕，默认 smblist.txt）",
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
        "--domain-dns", metavar="DOMAIN",
        help="Kerberos 域 DNS 名",
    )
    p.add_argument(
        "--kerberos-ticket", metavar="HEX",
        help="Kerberos 票据（十六进制字节）",
    )
    p.add_argument(
        "--session-key", metavar="HEX",
        help="Kerberos 会话密钥（十六进制字节）",
    )
    p.add_argument(
        "--ticket-file", metavar="FILE",
        help="本地 Kerberos 票据文件",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=smb_list_handle)
