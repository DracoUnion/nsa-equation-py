"""reg-write — REGWRITE 注册表写入工具。

Python 重写的 NSA Regwrite 工具 `Regwrite-1.1.1.exe`
(C++ / DAVE framework)，通过 IDA Pro / x32dbg 逆向恢复。
实现了该工具的 key=value 参数接口及其注册表写入流程。
"""

from . import reg_write


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def reg_write_handle(args):
    """Run the REGWRITE registry write sequence against the supplied host."""
    return reg_write.run_function(
        target=args.target,
        port=args.port,
        timeout=args.timeout,
        reg_hive=args.reg_hive,
        reg_key=args.reg_key,
        reg_type=args.reg_type,
        value_type=args.value_type,
        value_name=args.value_name,
        value_data=args.value_data,
        key_name=args.key_name,
        key_class=args.key_class,
        auth_level=args.auth_level,
        credential_type=args.credential_type,
        username=args.username,
        credential=args.credential,
        domain_dns=args.domain_dns,
        kerberos_ticket=args.kerberos_ticket,
        session_key=args.session_key,
        ticket_file=args.ticket_file,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `reg-write` subcommand on an argparse
    subparsers group."""
    p = subparsers.add_parser(
        "reg-write",
        help="REGWRITE 注册表写入工具",
        description="Python 重写的 NSA Regwrite (REGWRITE) 注册表写入工具 "
                    "Regwrite-1.1.1。通过 SMB/远程注册表 RPC 协议在目标主机"
                    "注册表中创建项或值。",
    )
    p.add_argument(
        "target", metavar="TARGET",
        help="目标主机名或 IP",
    )
    p.add_argument(
        "-p", "--port", type=int, default=445,
        help="目标 SMB 端口（默认 445）",
    )
    p.add_argument(
        "--timeout", type=int, default=60,
        help="阻塞网络调用超时秒（-1 表示无超时，默认 60）",
    )
    p.add_argument(
        "--reg-hive",
        choices=["HKLM", "HKU", "HKPD", "HKCU", "HKCR"],
        default="HKLM",
        help="注册表蜂巢（默认 HKLM）",
    )
    p.add_argument(
        "--reg-key", metavar="KEY",
        help="要在其下创建项或值的注册表项",
    )
    p.add_argument(
        "--reg-type",
        choices=["Key", "Value"],
        default="Value",
        help="要创建的注册表项类型：Key（创建项）/Value（创建值）",
    )
    p.add_argument(
        "--value-type",
        choices=["REG_NONE", "REG_SZ", "REG_EXPAND_SZ", "REG_BINARY",
                 "REG_DWORD", "REG_DWORD_LITTLE_ENDIAN",
                 "REG_DWORD_BIG_ENDIAN", "REG_LINK", "REG_MULTI_SZ",
                 "REG_RESOURCE_LIST", "REG_FULL_RESOURCE_DESCIPTOR",
                 "REG_QWORD", "REG_QWORD_LITTLE_ENDIAN"],
        help="要创建的值类型（仅在 reg-type 为 Value 时有效）",
    )
    p.add_argument(
        "--value-name", metavar="NAME",
        help="要创建的值名（仅在 reg-type 为 Value 时有效）",
    )
    p.add_argument(
        "--value-data", metavar="DATA",
        help="要分配给值的数据（仅在 reg-type 为 Value 时有效）",
    )
    p.add_argument(
        "--key-name", metavar="NAME",
        help="要创建的项名（仅在 reg-type 为 Key 时有效）",
    )
    p.add_argument(
        "--key-class", metavar="CLASS",
        help="要创建的项的类（仅在 reg-type 为 Key 时有效，可选）",
    )
    p.add_argument(
        "--auth-level",
        choices=["Default", "None", "Connect", "Call", "Packet", "Integrity", "Privacy"],
        default="None",
        help="RPC 认证级别（默认 None）",
    )
    p.add_argument(
        "--credential-type",
        choices=["UnicodeCreds", "PasswordHash", "MachineHash",
                 "KerberosTicket", "KerberosFile"],
        default="UnicodeCreds",
        help="凭证类型（默认 UnicodeCreds）",
    )
    p.add_argument(
        "--username", metavar="HEX",
        help="用户名（十六进制字节，Unicode）",
    )
    p.add_argument(
        "--credential", metavar="HEX",
        help="凭证/密码哈希（十六进制字节，Unicode）",
    )
    p.add_argument(
        "--domain-dns", metavar="DOMAIN",
        help="Kerberos 域 DNS 名",
    )
    p.add_argument(
        "--kerberos-ticket", metavar="HEX",
        help="Kerberos 票据（十六进制字节）",
    )
    p.add_argument(
        "--session-key", metavar="HEX",
        help="Kerberos 会话密钥（十六进制字节）",
    )
    p.add_argument(
        "--ticket-file", metavar="FILE",
        help="本地 Kerberos 票据文件",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=reg_write_handle)
