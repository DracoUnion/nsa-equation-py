"""job-add — JOBADD AT 作业添加工具。

Python 重写的 NSA Jobadd 工具 `Jobadd-1.1.1.exe`
(C++ / DAVE framework)，通过 IDA Pro / x32dbg 逆向恢复。
实现了该工具的 key=value 参数接口及其 AT 作业调度添加流程。
"""

from . import job_add


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def job_add_handle(args):
    """Run the JOBADD job scheduling sequence against the supplied host."""
    return job_add.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        command=args.command,
        hour=args.hour,
        minute=args.minute,
        mode=args.mode,
        auth_level=args.auth_level,
        credential_type=args.credential_type,
        username=args.username,
        credential=args.credential,
        password=args.password,
        domain_dns=args.domain_dns,
        kerberos_ticket=args.kerberos_ticket,
        session_key=args.session_key,
        ticket_file=args.ticket_file,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `job-add` subcommand on an argparse
    subparsers group."""
    p = subparsers.add_parser(
        "job-add",
        help="JOBADD AT 作业添加工具",
        description="Python 重写的 NSA Jobadd (JOBADD) AT 作业添加工具 "
                    "Jobadd-1.1.1。通过 SMB/ATSVC 协议在目标主机上添加"
                    "定时任务。",
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
        "--command", metavar="CMD",
        help="要在目标机上调度执行的命令",
    )
    p.add_argument(
        "--hour", type=int, default=0,
        help="调度执行小时（默认 0）",
    )
    p.add_argument(
        "--minute", type=int, default=1,
        help="调度执行分钟（默认 1）",
    )
    p.add_argument(
        "--mode",
        choices=["Offset", "Absolute"],
        default="Offset",
        help="AT 调度类型：Offset（相对当前时间）/Absolute（本地时区时间点）",
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
        "--password", metavar="PASS",
        help="MachineHash 模式：机器哈希密码",
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
    p.set_defaults(func=job_add_handle)
