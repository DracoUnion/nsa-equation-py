"""smb-write — SMBWRITE SMB 文件写入工具。

Python 重写的 NSA Smbwrite 工具 `Smbwrite-1.1.1.exe`
(C++ / DAVE framework)，通过 IDA Pro / x32dbg 逆向恢复。
实现了该工具的 key=value 参数接口及其 SMB 文件写入流程。
"""

from . import smb_write


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def smb_write_handle(args):
    """Run the SMBWRITE write sequence against the supplied host."""
    return smb_write.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        share=args.share,
        path=args.path,
        source=args.source,
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
    """Register the `smb-write` subcommand on an argparse
    subparsers group."""
    p = subparsers.add_parser(
        "smb-write",
        help="SMBWRITE SMB 文件写入工具",
        description="Python 重写的 NSA Smbwrite (SMBWRITE) SMB 文件写入工具 "
                    "Smbwrite-1.1.1。通过 SMB 协议上传本地文件到目标主机。",
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
        help="目标共享名（如 c$），字符串或十六进制字节",
    )
    p.add_argument(
        "--path", metavar="PATH",
        help="要写入的文件路径（如 windows\\notepad.exe），字符串或十六进制字节",
    )
    p.add_argument(
        "--source", metavar="SOURCE",
        help="本地要上传的文件路径（字符串）",
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
    p.set_defaults(func=smb_write_handle)
