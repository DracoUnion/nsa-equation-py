"""printjob-delete — PRINTJOBDELETE 打印作业删除触摸工具。

Python 重写的 NSA Printjobdelete 探测工具
`Printjobdelete-1.0.0.exe` (C++ / DAVE framework)，通过 IDA Pro /
x32dbg 逆向恢复。实现了该工具的 key=value 参数接口及其打印作业
删除流程。
"""

from . import printjob_delete


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def printjob_delete_handle(args):
    """Run the PRINTJOBDELETE deletion sequence against the supplied host."""
    return printjob_delete.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        protocol=args.protocol,
        credentials=args.credentials,
        username=args.username,
        password=args.password,
        ntlm_hash=args.ntlm_hash,
        lanman_hash=args.lanman_hash,
        printer_name=args.printer_name,
        job_id=args.job_id,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `printjob-delete` subcommand on an argparse
    subparsers group."""
    p = subparsers.add_parser(
        "printjob-delete",
        help="PRINTJOBDELETE 打印作业删除触摸工具",
        description="Python 重写的 NSA Printjobdelete (PrintJobDelete) 打印作业"
                    "删除触摸工具 Printjobdelete-1.0.0。通过 SMB/NBT 协议"
                    "删除目标打印机上的指定打印作业。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP",
    )
    p.add_argument(
        "-p", "--port", type=int, default=445,
        help="目标端口（SMB 默认 445，NBT 默认 139）",
    )
    p.add_argument(
        "--timeout", type=int, default=60,
        help="阻塞网络调用超时秒（-1 表示无超时，默认 60）",
    )
    p.add_argument(
        "--protocol",
        choices=["SMB", "NBT"],
        default="SMB",
        help="协议类型（默认 SMB）",
    )
    p.add_argument(
        "--credentials",
        choices=["Anonymous", "Guest", "No password", "Password", "NTLM hash", "Both hashes"],
        default="Anonymous",
        help="凭证类型（默认 Anonymous）",
    )
    p.add_argument(
        "--username", metavar="USER",
        help="用户名",
    )
    p.add_argument(
        "--password", metavar="PASS",
        help="密码",
    )
    p.add_argument(
        "--ntlm-hash", metavar="HEX",
        help="NTLM 密码哈希（十六进制）",
    )
    p.add_argument(
        "--lanman-hash", metavar="HEX",
        help="LANMAN 密码哈希（十六进制）",
    )
    p.add_argument(
        "--printer-name", metavar="NAME",
        help="目标打印机名称",
    )
    p.add_argument(
        "--job-id", type=int, metavar="ID",
        help="要删除的打印作业 ID",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=printjob_delete_handle)
