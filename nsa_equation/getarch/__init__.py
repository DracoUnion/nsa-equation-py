"""get-arch — host OS architecture (32- vs 64-bit) detector.

Python rewrite of `getArch.py`, recovered from the PyInstaller bundle
`getArch.exe` (entry point `getArch.pyc`, Python 2.7) via IDA Pro + archive
recovery.  It probes the RPC Endpoint Mapper on TCP 135 and binds the
portmapper UUID with the NDR64 transfer syntax: 64-bit Windows accepts
NDR64, 32-bit Windows rejects it as `proposed_transfer_syntaxes_not_supported`.
"""

from . import get_arch


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def get_arch_handle(args):
    """Detect the OS architecture of the supplied target(s)."""
    machines = []
    if args.target:
        machines.append(args.target)
    if args.targets:
        with open(args.targets, "r") as f:
            machines += [ln.strip(" \r\n") for ln in f if ln.strip()]
    if not machines:
        get_arch.log("[!] - you have to specify a target (-target or -targets)")
        return 1
    return get_arch.run_function(
        targets=machines,
        timeout=args.timeout,
    )


def reg_subparser(subparsers):
    """Register the `get-arch` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "get-arch",
        help="通过 RPC Endpoint Mapper 探测目标操作系统架构 (32/64 位)",
        description="连接到目标 TCP 135 (RPC Endpoint Mapper)，向 portmapper 提交一个使用 "
                    "NDR64 transfer syntax 的 DCERPC BIND：64 位 Windows 接受 NDR64，"
                    "32 位 Windows 拒绝之 (proposed_transfer_syntaxes_not_supported)。"
                    "只读探测，不修改目标状态。",
    )
    p.add_argument(
        "-target", metavar="HOST",
        help="单个目标主机名或 IP 地址",
    )
    p.add_argument(
        "-targets", metavar="FILE",
        help="目标文件，每行一个主机（将逐行探测架构）",
    )
    p.add_argument(
        "-timeout", type=float, default=get_arch.DEFAULT_TIMEOUT,
        help="连接/读取超时秒数（默认 %.1f）" % get_arch.DEFAULT_TIMEOUT,
    )
    p.add_argument(
        "-debug", action="store_true",
        help="输出调试信息",
    )
    p.set_defaults(func=get_arch_handle)
