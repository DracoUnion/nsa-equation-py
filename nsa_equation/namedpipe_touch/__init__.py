"""namedpipe-touch — NAMEDPIPETOUCH 命名管道触摸/探测工具。

Python 重写的 NSA Namedpipetouch 探测工具
`Namedpipetouch-2.0.0.exe` (C++ / DAVE framework)，通过 IDA Pro /
x32dbg 逆向恢复。实现了该工具的 key=value 参数接口及其命名管道
触摸探测流程。
"""

from . import namedpipe_touch


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def namedpipe_touch_handle(args):
    """Run the NAMEDPIPETOUCH probing sequence against the supplied host."""
    return namedpipe_touch.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        protocol=args.protocol,
        pipe_list=args.pipe_list,
        desc_list=args.desc_list,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `namedpipe-touch` subcommand on an argparse
    subparsers group."""
    p = subparsers.add_parser(
        "namedpipe-touch",
        help="NAMEDPIPETOUCH 命名管道触摸/探测工具",
        description="Python 重写的 NSA Namedpipetouch (NamedPipeTouch) 命名管道"
                    "触摸/探测工具 Namedpipetouch-2.0.0。通过 SMB/NBT 协议探测"
                    "目标主机上的命名管道可达性，并识别对应的安全软件。",
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
        "--pipe-list", metavar="PIPES",
        help="要检测的命名管道列表（Python 列表格式字符串）",
    )
    p.add_argument(
        "--desc-list", metavar="DESCS",
        help="与管道对应的描述列表（Python 列表格式字符串）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=namedpipe_touch_handle)
