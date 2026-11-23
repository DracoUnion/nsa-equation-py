"""smb-touch — SMBTOUCH / Smbtouch SMB 探测工具。

Python 重写的 NSA Smbtouch 探测工具 `Smbtouch-1.1.1.exe` /
`SMBTOUCH.exe` (C++ / DAVE framework)，通过 IDA Pro / x32dbg 逆向恢复。
实现了该工具的 key=value 参数接口及其 SMB 会话探测流程。
"""

from . import smb_touch


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def smb_touch_handle(args):
    """Run the SMBTOUCH probing sequence against the supplied host."""
    return smb_touch.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        protocol=args.protocol,
        pipe=args.pipe,
        share=args.share,
        credentials=args.credentials,
        username=args.username,
        password=args.password,
        ntlm_hash=args.ntlm_hash,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `smb-touch` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "smb-touch",
        help="SMBTOUCH / Smbtouch SMB 会话探测工具",
        description="Python 重写的 NSA Smbtouch (SMBTOUCH) SMB 会话探测工具 "
                    "Smbtouch-1.1.1。通过 SMB/NBT 协议探测目标主机的 SMB 会话"
                    "可达性、管道、共享和凭证。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP",
    )
    p.add_argument(
        "-p", "--port", type=int, default=445,
        help="目标 SMB 端口（SMB 默认 445，NBT 默认 139）",
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
        "--pipe", metavar="PIPE",
        help="可选：要测试的命名管道名",
    )
    p.add_argument(
        "--share", metavar="HEX",
        help="可选：要测试的文件共享名（十六进制字节，Unicode）",
    )
    p.add_argument(
        "--credentials",
        choices=["Anonymous", "Guest", "Blank", "Password", "NTLM"],
        default="Anonymous",
        help="凭证类型（默认 Anonymous）",
    )
    p.add_argument(
        "--username", metavar="HEX",
        help="用户名（十六进制字节，Unicode）",
    )
    p.add_argument(
        "--password", metavar="HEX",
        help="密码（十六进制字节，Unicode）",
    )
    p.add_argument(
        "--ntlm-hash", metavar="HEX",
        help="NTLM 密码哈希（十六进制）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=smb_touch_handle)
