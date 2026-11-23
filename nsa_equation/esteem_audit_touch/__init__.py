"""esteem-audit-touch — ESTEEMAUDITTOUCH RDP 触摸/探测工具。

Python 重写的 NSA Esteemaudittouch 探测工具
`Esteemaudittouch-2.1.0.exe` (C++ / DAVE framework)，通过 IDA Pro /
x32dbg 逆向恢复。实现了该工具的 key=value 参数接口及其 RDP 触摸
探测流程。
"""

from . import esteem_audit_touch


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def esteem_audit_touch_handle(args):
    """Run the ESTEEMAUDITTOUCH probing sequence against the supplied host."""
    return esteem_audit_touch.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        packet_timeout=args.packet_timeout,
        max_process_count=args.max_process_count,
        rdplib_hertz=args.rdplib_hertz,
        send_spacebar=args.send_spacebar,
        process_count_to_send_space=args.process_count_to_send_space,
        max_rdplib_error_count=args.max_rdplib_error_count,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `esteem-audit-touch` subcommand on an argparse
    subparsers group."""
    p = subparsers.add_parser(
        "esteem-audit-touch",
        help="ESTEEMAUDITTOUCH RDP 触摸/探测工具",
        description="Python 重写的 NSA Esteemaudittouch (ETA Touch) RDP "
                    "触摸/探测工具 Esteemaudittouch-2.1.0。通过 RDP 协议"
                    "探测目标主机的架构、OS 版本、加密方式和智能卡认证支持。",
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
        help="阻塞网络调用超时秒（-1 表示无超时，默认 60）",
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
        "--send-spacebar", action="store_true", default=False,
        help="是否发送空格键清除法律文本标题（默认禁用）",
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
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=esteem_audit_touch_handle)
