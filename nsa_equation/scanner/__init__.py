#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scanner — Equation Group network scanner.

Python rewrite of `scanner.exe` recovered from
`EQGRP_Lost_in_Translation-master/windows/Resources/Ops/Tools/scanner.exe` in the
方程式工具包图形界面版 v0.68 toolkit.

The original binary is a small Win32 console network scanner that supports
multiple scan types against a target host or network range:

  - Scan for windows boxes      (NetBIOS name resolution)
  - Scan for Xwin folks         (X11 font server / X display)
  - Scan for NTP folks          (NTP monlist / version)
  - Scan for RPC folks          (RPC endpoint mapper)
  - Scan for SNMP version       (SNMP GET with community "public")
  - Scan for Sol version        (Sun Solaris)
  - Scan for echo hosts         (ICMP/TCP echo)
  - Scan for daytime hosts      (DAYTIME protocol)
  - Scan for tftp hosts         (TFTP RRQ)
  - Scan ident                  (IDENT/Auth protocol)
  - Scan mail                   (SMTP banner)
  - Scan ftp                    (FTP banner)
  - Scan TCP port               (generic TCP port probe)
  - Scan web                    (HTTP GET /)
  - Scan netbios                (NetBIOS name query)
  - Scan for DNS                (DNS version query)
  - Scan for RIP v1/v2          (RIP routing)
  - Scan for lpr                (LPD printer)
  - Scan for Redflag Web        (RedFlag Linux web)
  - telnet / Banner Telnet      (Telnet banner)
  - finger / Banner finger      (Finger protocol)
  - Scan for SSL stuff          (SSL/TLS probe)
  - Scan for SSH version        (SSH banner)
  - printer / Printer Test      (@PJL printer job language)
  - Answerbook test             (Sun Answerbook)
  - X11 test / X font server test

Recovered strings from the binary:
  "Welcome to the network scanning tool"
  "Scan for windows boxes"
  "Scan for windows names"
  "Scan for Xwin folks"
  "Scan for NTP  folks"
  "+daemon_version,system,processor,refid,clock"
  "Scan for RPC  folks"
  "Scan for SNMP version"
  "public"
  "Scan for Sol  version"
  "Scan for echo hosts"
  "Scan for daytime hosts"
  "Scan for tftp hosts"
  "netascii"
  "Scan ident"
  "VERSION"
  "Scan mail"
  "Scan ftp"
  "t_basic"
  "Scan TCP port"
  "Scan web"
  "GET / HTTP/1.0"
  "netbios"
  "Does not work"
  "Scan for DNS"
  "version"
  "Scan for RIP v1"
  "Scan for RIP v2"
  "Scan for lpr"
  "miniserv"
  "Scan for Redflag Web"
  "win_scan"
  "Get windows version"
  "telnet"
  "Banner Telnet"
  "finger"
  "Banner finger"
  "Scan for SSL stuff"
  "Scan for SSH version"
  "Finnish Test Case SNMP"
  "dtuname"
  "DT uname test"
  "answer"
  "Answerbook test"
  "Larger RPC dump"
  "X11 test"
  "X font server test"
  "printer"
  "Printer Test"
  "@PJL INFO CONFIG"
  "@PJL INFO ID"
  "printerid"
  "WSAstartup failed"
  "nopendump"

This module reproduces that behaviour in portable Python using only the
stdlib (socket, struct).  Each scan type opens a raw TCP/UDP socket to the
target, sends the protocol-specific probe, and prints the banner/response.

CLI:

  scanner <target> [--scan <type>] [--port <port>] [--timeout <sec>]
"""

from . import scanner_exp


def scanner_handle(args):
    """Run the network scanner against the supplied target."""
    return scanner_exp.run_function(
        target=args.target,
        scan_type=args.scan,
        port=args.port,
        timeout=args.timeout,
    )


def reg_subparser(subparsers):
    """Register the `scanner` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "scanner",
        help="Equation Group 网络扫描工具",
        description="scanner.exe — Equation Group 网络扫描工具，支持多种扫描类型："
                    "NetBIOS、X11、NTP、RPC、SNMP、Solaris、echo、daytime、TFTP、"
                    "IDENT、SMTP、FTP、TCP端口、HTTP、DNS、RIP、LPR、Telnet、Finger、"
                    "SSL、SSH、打印机(PJL)等。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机 IP 地址或主机名",
    )
    p.add_argument(
        "-s", "--scan", metavar="TYPE",
        default="all",
        help="扫描类型：windows, x11, ntp, rpc, snmp, solaris, echo, daytime, tftp, "
             "ident, mail, ftp, tcp, web, netbios, dns, rip1, rip2, lpr, redflag, "
             "telnet, finger, ssl, ssh, printer, answerbook, x11test, all (默认 all)",
    )
    p.add_argument(
        "-p", "--port", type=int, default=0, metavar="PORT",
        help="目标端口（0 = 根据扫描类型自动）",
    )
    p.add_argument(
        "-o", "--timeout", type=int, default=5, metavar="SEC",
        help="每个探测的超时秒数 (默认 5)",
    )
    p.set_defaults(func=scanner_handle)
