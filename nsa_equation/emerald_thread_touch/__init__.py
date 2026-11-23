#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
emerald_thread_touch — Emerald Thread touch / printer-enumeration probe.

Python rewrite of `Emeraldthreadtouch-1.0.0.exe` recovered from
`EQGRP_Lost_in_Translation-master/windows/touches/Emeraldthreadtouch-1.0.0.exe`.

Emerald Thread Touch probes a target for shared printers via the Windows RPC
spoolss / Print Provider interface.  It:

  1. Establishes an SMB/RPC session to the target,
  2. Binds to the spoolss RPC interface,
  3. Calls RpcEnumPrinters / RpcEnumPorts to enumerate shared printers,
  4. Reports the number of printers found.

Recovered strings from the binary:
  "[*] Probing for shared printers"
  "[+] Found %d printer(s)"
  "RpcEnumeratePrinters() failed!"
  "Buffer too small, trying again with %d bytes."
  "Printer Count : %d"
  "ClosePrinter request"

The original binary imports KERNEL32, WS2_32, msvcrt plus the DAVE framework
helper DLLs (adfw-2.dll, iconv.dll, tibe-1.dll, trfo-2.dll, trch-0.dll,
tucl-1.dll) and uses TbDoRpcBind / TbDoRpcRequestEx / TbPutLong / TbPutRpcArray
etc. to drive the RPC print-enumeration sequence.

This module reproduces that behaviour in portable Python using raw SMB/RPC
(impacket) for the transport and a reconstructed spoolss enum-printers request.

CLI:

  emerald_thread_touch <target_ip> [-p <port>] [-o <timeout>]
"""

from . import emerald_thread_touch_exp


def emerald_thread_touch_handle(args):
    """Run the Emerald Thread Touch printer-enumeration probe."""
    return emerald_thread_touch_exp.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
    )


def reg_subparser(subparsers):
    """Register the `emerald_thread_touch` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "emerald_thread_touch",
        help="Emerald Thread 共享打印机枚举触摸",
        description="Emerald Thread Touch — 通过 RPC spoolss 接口枚举目标上的"
                    "共享打印机。建立 SMB/RPC 会话，绑定 spoolss 接口，调用"
                    "RpcEnumPrinters/RpcEnumPorts 枚举打印机并报告数量。",
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
        "-o", "--timeout", type=int, default=30, metavar="SEC",
        help="等待回复的秒数 (默认 30)",
    )
    p.set_defaults(func=emerald_thread_touch_handle)
