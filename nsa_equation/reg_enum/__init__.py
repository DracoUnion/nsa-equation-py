"""reg-enum — REGENUM 注册表枚举工具。

Python 重写的 NSA Regenum 工具 `Regenum-1.1.1.exe`
(C++ / DAVE framework)，通过 IDA Pro / x32dbg 逆向恢复。
实现了该工具的 key=value 参数接口及其注册表枚举流程。
"""

from . import reg_enum


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def reg_enum_handle(args):
    """Run the REGENUM registry enumeration sequence against the supplied host."""
    return reg_enum.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        reg_hive=args.reg_hive,
        reg_key=args.reg_key,
        recursive=args.recursive,
        auth_level=args.auth_level,
        credential_type=args.credential_type,
        username=args.username,
        credential=args.credential,
        domain_dns=args.domain_dns,
        kerberos_ticket=args.kerberos_ticket,
        session_key=args.session_key,
        ticket_file=args.ticket_file,
        log_file=args.log_file,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `reg-enum` subcommand on an argparse
    subparsers group."""
    p = subparsers.add_parser(
        "reg-enum",
        help="REGENUM 注册表枚举工具",
        description="Python 重写的 NSA Regenum (REGENUM) 注册表枚举工具 "
                    "Regenum-1.1.1。通过 SMB/远程注册表 RPC 协议枚举目标主机"
                    "注册表项和值。",
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
        "--reg-hive",
        choices=["HKLM", "HKU", "HKPD", "HKCU", "HKCR"],
        default="HKLM",
        help="注册表蜂巢（默认 HKLM）",
    )
    p.add_argument(
        "--reg-key", metavar="KEY",
        help="要枚举的注册表项",
    )
    p.add_argument(
        "--recursive", action="store_true", default=False,
        help="是否递归枚举（默认禁用）",
    )
    p.add_argument(
        "--no-recursive", action="store_false", dest="recursive",
        help="禁用递归枚举",
    )
    p.add_argument(
        "--auth-level",
        choices=["Default", "None", "Connect", "Call", "Packet", "Integrity", "Privacy"],
        default="None",
        help="RPC 认证级别（默认 None）",
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
        "--log-file", metavar="FILE",
        help="注册表枚举日志文件（默认 regenum.txt）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=reg_enum_handle)
