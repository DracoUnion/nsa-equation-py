# -*- coding: utf-8 -*-
"""
dave.tibe — TIBE TCP/IP 缓冲区交换（SMB、DCE-RPC、NTLM、Kerberos、Netlogon、SNEGO、加密）。

对应 DLL：tibe-1.dll / tibe-2.dll（约 560–691 个导出函数）。

本模块仅实现与 DAVE 框架工具移植最相关的核心原语：
  TCP/UDP 套接字、SMBv1 协商/会话/树连接、DCE-RPC 绑定/请求、
  缓冲区写/读（TbPut*/TbGet*）、NTLM/SNEGO/Netlogon 验证构造。

函数命名与原二进制导出表保持一致，方便与 IDA 还原的调用点对照。
"""

import socket
import struct
import os
import sys
from . import posh
from . import trfo


# ---------------------------------------------------------------------------
# Socket primitives
# ---------------------------------------------------------------------------

def TbWinsockStartup():
    """Python socket 模块已自动初始化，此处为兼容原二进制语义。"""
    return 0


def TbWinsockCleanup():
    return 0


def TbMakeSocket(blocking=True):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if not blocking:
        s.setblocking(False)
    return s


def TbMakeServerSocket(port, backlog=5):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(backlog)
    return s


def TbConnectNonblocking(sock, host, port, timeout=5):
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        return sock
    except OSError:
        return None


def TbServerRecv(sock, bufsize=4096):
    return sock.recv(bufsize)


def TbSend(sock, data):
    return sock.sendall(data)


def TbSendTo(sock, data, host, port):
    return sock.sendto(data, (host, port))


def TbRecv(sock, bufsize=4096):
    return sock.recv(bufsize)


def TbRecvFrom(sock, bufsize=4096):
    data, addr = sock.recvfrom(bufsize)
    return data, addr


def TbCloseSocket(sock):
    try:
        sock.close()
    except OSError:
        pass


def TbCloseStructSockets(socks):
    for s in socks:
        TbCloseSocket(s)


def TbResetSocketData(sock):
    pass


def TbSetLocalSocketData(sock, data):
    sock._dave_local = data


def TbSetCallbackSocketData(sock, data):
    sock._dave_callback = data


def TbSetRemoteSocketData(sock, data):
    sock._dave_remote = data


def TbGetSocketError(sock):
    return None


def TbGetSocketErrorString(sock):
    return None


def TbSetSocketBlocking(sock, blocking=True):
    sock.setblocking(blocking)


def TbSetSocketNonblocking(sock):
    sock.setblocking(False)


def TbWaitServerSocket(sock):
    pass


def TbWaitServerSocketNonBlocking(sock):
    pass


def TbRecvSmb(sock, size=4096):
    return sock.recv(size)


def TbRecvTcp(sock, size=4096):
    return sock.recv(size)


def TbRecvUdp(sock, size=4096):
    return sock.recvfrom(size)


def TbTcpRecvRaw(sock, size=4096):
    return sock.recv(size)


def TbUdpRecvFromRaw(sock, size=4096):
    return sock.recvfrom(size)


def TbSimpleRecv(sock, size=4096):
    return sock.recv(size)


def TbSimpleCloseSocket(sock):
    TbCloseSocket(sock)


# ---------------------------------------------------------------------------
# Buffer put/get helpers (TbPut*/TbGet*)
# ---------------------------------------------------------------------------

def TbPutBuff(buf, off, data):
    """把 data 写入 buf[off:off+len(data)]，返回写入字节数。"""
    n = min(len(data), len(buf) - off)
    buf[off:off + n] = data[:n]
    return n


def TbPutBuffCyclic(buf, off, data, count):
    n = min(count, len(buf) - off)
    for i in range(n):
        buf[off + i] = data[i % len(data)]
    return n


def TbPutByte(buf, off, val):
    buf[off] = val & 0xFF


def TbPutShort(buf, off, val):
    posh.POSH_WriteU16ToLittle(buf, off, val)


def TbPutLong(buf, off, val):
    posh.POSH_WriteU32ToLittle(buf, off, val)


def TbPutHyper(buf, off, val):
    posh.POSH_WriteU64ToLittle(buf, off, val)


def TbPutAuth3(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutAuthTrailerTcp(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutAuthVerifier(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutBindAckRpc(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutBindRpc(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutBlob1(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutBlob2(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutBlob3(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutBlob4(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutByte(buf, off, val):
    buf[off] = val & 0xFF


def TbPutCTH(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutContexts(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutCtxHand(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutDSA(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutFackHdr(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutFault(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutIfPtr(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutIpid(buf, off, val):
    return TbPutLong(buf, off, val)


def TbPutListHdr(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutLocalThis(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutNSH(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutNetlogonAuthVerifier(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutNetlogonBlob1(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutNetlogonBlob2(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutNtCreateX(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutNtReadX(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutNtWriteX(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutNtlmAuthVerifier(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutNtlmBlob1(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutNtlmBlob2(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutNtlmBlob3(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutOneArg(buf, off, val):
    return TbPutLong(buf, off, val)


def TbPutOrpcThat(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutOrpcThis(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutOxid(buf, off, val):
    return TbPutLong(buf, off, val)


def TbPutPadding(buf, off, count):
    for i in range(count):
        buf[off + i] = 0
    return count


def TbPutPointer(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutRequest(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutResponse(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutResult(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutRpcArray(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutRpcArrayWithMax(buf, off, data, max_size):
    n = min(len(data), max_size)
    buf[off:off + n] = data[:n]
    return n


def TbPutRpcAsciiString(buf, off, s):
    b = s.encode("ascii")
    n = TbPutBuff(buf, off, b)
    buf[off + n] = 0
    return n + 1


def TbPutRpcSize(buf, off, val):
    return TbPutLong(buf, off, val)


def TbPutRpcUniString(buf, off, s):
    b = s.encode("utf-16-le")
    n = TbPutBuff(buf, off, b)
    buf[off + n] = 0
    buf[off + n + 1] = 0
    return n + 2


def TbPutSRpc(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutShort(buf, off, val):
    return TbPutShort(buf, off, val)


def TbPutSmbHeader(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutSnegoAuthVerifier(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutSnegoBlob1(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutSnegoBlob2(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutSnegoBlob3(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutSnegoBlob4(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutStr(buf, off, s):
    b = s.encode("ascii")
    n = TbPutBuff(buf, off, b)
    buf[off + n] = 0
    return n + 1


def TbPutStrAsLEUni(buf, off, s):
    b = s.encode("utf-16-le")
    n = TbPutBuff(buf, off, b)
    buf[off + n] = 0
    buf[off + n + 1] = 0
    return n + 2


def TbPutString(buf, off, s):
    return TbPutStr(buf, off, s)


def TbPutSyntax(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutTransInfo(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutTransact(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutUNISTRContents(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutUNISTRHeader(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutUdpHdr(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutUdpNetbiosHeader(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutUniBuff(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbPutUuid(buf, off, data):
    return TbPutBuff(buf, off, data)


def TbGetBuff(buf, off, size):
    return bytes(buf[off:off + size])


def TbGetByte(buf, off):
    return buf[off]


def TbGetCtxHand(buf, off):
    return TbGetBuff(buf, off, 20)


def TbGetCurrentTime():
    import time
    return int(time.time())


def TbGetErrString(code):
    return os.strerror(code) if code else ""


def TbGetFaultHdr(buf, off):
    return TbGetBuff(buf, off, 24)


def TbGetFaultRpc(buf, off):
    return TbGetBuff(buf, off, 24)


def TbGetHyper(buf, off):
    return posh.POSH_ReadU64FromLittle(buf, off)


def TbGetIfData(buf, off):
    return TbGetBuff(buf, off, 16)


def TbGetIpid(buf, off):
    return TbGetLong(buf, off)


def TbGetLangStringInfo(buf, off):
    return TbGetBuff(buf, off, 8)


def TbGetListHdr(buf, off):
    return TbGetBuff(buf, off, 8)


def TbGetLong(buf, off):
    return posh.POSH_ReadU32FromLittle(buf, off)


def TbGetMgmt0Info(buf, off):
    return TbGetBuff(buf, off, 16)


def TbGetNSH(buf, off):
    return TbGetBuff(buf, off, 4)


def TbGetNetlogonAuthVerifier(buf, off):
    return TbGetBuff(buf, off, 16)


def TbGetNetlogonAuthVerifierSize():
    return 16


def TbGetNtlmAuthVerifier(buf, off):
    return TbGetBuff(buf, off, 24)


def TbGetNtlmAuthVerifierSize():
    return 24


def TbGetOxid(buf, off):
    return TbGetLong(buf, off)


def TbGetPointer(buf, off):
    return TbGetBuff(buf, off, 4)


def TbGetProtocolLegCount(buf, off):
    return TbGetByte(buf, off)


def TbGetReplyRpc(buf, off):
    return TbGetBuff(buf, off, 24)


def TbGetRequestRpc(buf, off):
    return TbGetBuff(buf, off, 24)


def TbGetRpcSize(buf, off):
    return TbGetLong(buf, off)


def TbGetSRpc(buf, off):
    return TbGetBuff(buf, off, 4)


def TbGetShort(buf, off):
    return posh.POSH_ReadU16FromLittle(buf, off)


def TbGetSmbErrString(code):
    return os.strerror(code) if code else ""


def TbGetSmbHeader(buf, off):
    return TbGetBuff(buf, off, 32)


def TbGetSmbTransactionData(buf, off):
    return TbGetBuff(buf, off, 16)


def TbGetSmbTransactionParameters(buf, off):
    return TbGetBuff(buf, off, 16)


def TbGetSnegoAuthVerifier(buf, off):
    return TbGetBuff(buf, off, 24)


def TbGetSnegoAuthVerifierSize():
    return 24


def TbGetSocket(sock):
    return sock


def TbGetString(buf, off):
    end = buf.find(b"\x00", off)
    if end == -1:
        end = len(buf)
    return buf[off:end].decode("ascii", errors="replace")


def TbGetStringValue(buf, off):
    return TbGetString(buf, off)


def TbGetStubBuffer(buf, off):
    return TbGetBuff(buf, off, 16)


def TbGetSyntax(buf, off):
    return TbGetBuff(buf, off, 8)


def TbGetTcpStub(buf, off):
    return TbGetBuff(buf, off, 4)


def TbGetUdpHdr(buf, off):
    return TbGetBuff(buf, off, 8)


def TbGetUdpStub(buf, off):
    return TbGetBuff(buf, off, 4)


def TbGetUuid(buf, off):
    return TbGetBuff(buf, off, 16)


def TbGoodString(data):
    return all(0x20 <= b < 0x7F for b in data)


def TbHandleNbtError(code):
    return code


def TbInitCrypto():
    return 0


def TbInitNetlogonCrypto():
    return 0


def TbInitNtlmCrypto():
    return 0


def TbInitSnegoCrypto():
    return 0


def TbInitStruct():
    return {}


def TbLocateNpRpcPort():
    return 445


def TbLocateRpcService():
    return 135


def TbLocateTcpRpcPort():
    return 135


def TbLocateUdpRpcPort():
    return 135


def TbMakeAlterCtx(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeAuth3(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeAuthVerifier(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeBind(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeBindAck(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeBindNak(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeBlob1(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeBlob2(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeBlob3(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeBlob4(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeCancelForward(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeCheckDirectory(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeClose(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeCloseAndTdisc(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeClosePrint(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeCopy(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeCreate(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeCreateDir(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeCreateTemp(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeDelete(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeDeleteDirectory(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeEcho(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeFault(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeFindClose2(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeFindNotifyClose(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeFlush(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeForwardUserName(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeGeneric(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeGetPrintQueue(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeIoctl(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeIoctlSecondary(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeLockByteRange(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeLockingAndX(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeLogoffAndX(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeMove(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeNbtSessionRequest(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeNegotiate(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeNetlogonAuthVerifier(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeNetlogonBlob1(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeNetlogonBlob2(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeNetlogonBlob3(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeNtCreateAndX(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeNtExtSessionSetupAndX(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeNtLockingAndX(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeNtReadAndX(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeNtReadRaw(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeNtRename(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeNtSessionSetupAndX(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeNtTransact(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeNtTransactSecondary(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeNtWriteAndX(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeNtWriteRaw(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeNtlmAuthVerifier(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeNtlmBlob1(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeNtlmBlob2(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeNtlmBlob3(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeOpen(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeOpenAndX(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeOpenPrintFile(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakePeekNamedPipe(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeQueryInformation(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeQueryInformation2(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeQueryInformationSrv(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeRead(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeReadAndX(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeReadMpx(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeReadRaw(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeRemQIRequest(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeRename(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeSearch(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeSeek(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeSendEndMbMessage(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeSendMessage(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeSendStartMbMessage(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeSendTextMbMessage(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeServerSocket(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeSessionSetupAndX(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeSetInformation(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeSetInformation2(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeSmbHeader(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeSnegoAuthVerifier(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeSnegoBlob1(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeSnegoBlob2(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeSnegoBlob3(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeSnegoBlob4(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeSocket(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeSysactRequest(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeTcpReply(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeTcpReq(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeTransaction(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeTransactionMailSlot(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeTransactionNamedPipe(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeTransactionRemApi(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeTransactionSecondary(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeTreeConnect(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeTreeConnectAndX(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeUNDHeader(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeUdpFack(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeUdpReq(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeUdpResp(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeUnlockByteRange(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeWrite(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeWrite103Raw(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeWriteAndClose(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeWriteAndCloseLong(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeWriteAndX(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeWriteMpx(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeWriteMpxComplete(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeWriteMpxSecondary(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeWritePrintFile(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


def TbMakeWriteRaw(data):
    return TbPutBuff(bytearray(len(data)), 0, data)


# ---------------------------------------------------------------------------
# NTLM / SMB helpers
# ---------------------------------------------------------------------------

def TbSMBNTencrypt(challenge, password):
    """NTLMv1 LM 响应（占位：使用 MD4）。"""
    from . import trfo
    return trfo.TfMd4(password.encode("utf-16-le"))[:21]


def TbSMBOWFencrypt(password):
    return trfo.TfMd4(password.encode("utf-16-le"))


def TbSMBencrypt(challenge, password):
    return TbSMBNTencrypt(challenge, password)


def TbSamOEMhash(password):
    return trfo.TfMd4(password.encode("ascii"))


def Tbcred_hash1(password):
    return trfo.TfMd4(password.encode("utf-16-le"))[:16]


def Tbcred_hash2(password):
    return trfo.TfMd4(password.encode("utf-16-le"))[16:32]


def Tbcred_hash3(password):
    return trfo.TfMd4(password.encode("utf-16-le"))


def Tblm_owf_gen(password):
    return trfo.TfMd4(password.encode("ascii"))


def Tbnt_owf_gen(password):
    return trfo.TfMd4(password.encode("utf-16-le"))


def Tbsam_pwd_hash(password):
    return Tbnt_owf_gen(password)


# ---------------------------------------------------------------------------
# SMBv1 packet helpers
# ---------------------------------------------------------------------------

SMB_MAGIC = b"\xffSMB"

SMB_COM_NEGOTIATE = 0x72
SMB_COM_SESSION_SETUP_AND_X = 0x73
SMB_COM_TREE_CONNECT_AND_X = 0x75
SMB_COM_NT_TRANSACT = 0xA0
SMB_COM_NT_TRANSACT_SECONDARY = 0xA1
SMB_COM_TRANSACTION2 = 0x32
SMB_COM_WRITE_AND_X = 0x2F
SMB_COM_READ_AND_X = 0x2E


def make_smb_header(command, flags=0x18, pid=0, tid=0, mid=0, uid=0):
    """构造 32 字节 SMBv1 头部。"""
    hdr = bytearray(32)
    hdr[0:4] = SMB_MAGIC
    hdr[4] = command
    posh.POSH_WriteU16ToLittle(hdr, 5, flags)
    posh.POSH_WriteU16ToLittle(hdr, 21, tid)
    posh.POSH_WriteU16ToLittle(hdr, 23, pid)
    posh.POSH_WriteU16ToLittle(hdr, 25, uid)
    posh.POSH_WriteU16ToLittle(hdr, 27, mid)
    return bytes(hdr)


def smb_negotiate_request():
    """Build an SMBv1 Negotiate request (dialects: NT LM 0.12)."""
    dialects = [b"NT LM 0.12", b"Windows for Workgroups 3.1a", b"LANMAN1.0",
                b"PC NETWORK PROGRAM 1.0"]
    n = len(dialects)
    param = bytearray()
    param.append(1)  # WordCount
    posh.POSH_WriteU16ToLittle(param, 1, n)
    offset = 3 + 2 * n
    for i in range(n):
        posh.POSH_WriteU16ToLittle(param, 3 + 2 * i, offset)
        offset += len(dialects[i]) + 1
    data = bytearray()
    data.append(0x01)  # Security mode: user-level
    posh.POSH_WriteU16ToLittle(data, 1, 0xFFFF)  # Max mpx count
    posh.POSH_WriteU16ToLittle(data, 3, 1)  # Max number vcs
    posh.POSH_WriteU32ToLittle(data, 5, 4356)  # Max buffer size
    posh.POSH_WriteU16ToLittle(data, 9, 0xFF00)  # Max raw size
    posh.POSH_WriteU32ToLittle(data, 11, 0)  # Session key
    posh.POSH_WriteU32ToLittle(data, 15, 0x00000001)  # Capabilities: raw mode
    posh.POSH_WriteU16ToLittle(data, 19, 0)  # System time low
    posh.POSH_WriteU16ToLittle(data, 21, 0)  # System time high
    posh.POSH_WriteU16ToLittle(data, 23, 0)  # Reserved
    posh.POSH_WriteU16ToLittle(data, 25, 16)  # Key length
    posh.POSH_WriteU32ToLittle(data, 27, 0)  # Reserved2
    for d in dialects:
        data += d + b"\x00"
    posh.POSH_WriteU16ToLittle(data, len(data), 0)  # ByteCount (primary domain length)
    return param, bytes(data)
