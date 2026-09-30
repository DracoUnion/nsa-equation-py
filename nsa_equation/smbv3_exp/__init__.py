"""smbv3-exp — CVE-2020-0796 (SMBGhost) detection + exploitation tool.

Python port of the PyInstaller-bundled `SmbGhostExp` program
(`CVE-2020-0796-EXP.exe`): SMBv3.1.1 + compression-context detection
(`--check`) and the full kernel RCE chain (`-e`, msfvenom / file / menu
shellcode).

Reimplemented from bytecode recovered out of the bundle; payloads are
byte-exact against the original.

WARNING: `-e` performs a working kernel-mode RCE against a patched Windows SMB
stack. It is for authorized lab research only, and a failed run will Blue-Screen
the target. Detection-only mode is safe.
"""

from . import smbv3_exp


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def smbv3_exp_handle(args):
    """Run the SMBGhost check/exploit tool for the supplied target."""
    return smbv3_exp.run_function(
        ip=args.ip,
        port=args.port,
        check_vuln=args.check_vuln,
        exploit_mode=args.exploit,
        lhost=args.lhost,
        lport=args.lport,
        arch=args.arch,
        silent=args.silent,
        shellcode_menu=args.shellcode_menu,
        load_shellcode=args.load_shellcode,
    )


def reg_subparser(subparsers):
    """Register the `smbv3-exp` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "smbv3-exp",
        help="CVE-2020-0796 (SMBGhost) 检测 + 利用工具",
        description="CVE-2020-0796 (SMBGhost) 检测与利用。--check 检测目标是否"
                    "协商 SMB 3.1.1 且启用 SMB 压缩上下文（潜在受影响面）；"
                    "-e 执行完整的 kernel RCE 链，投递反弹 shell 载荷。仅限授权"
                    "实验室研究使用，失败会导致目标蓝屏。",
    )
    p.add_argument("-i", "--ip", dest="ip", type=str, required=True,
                   help="目标 IP 地址")
    p.add_argument("-p", "--port", dest="port", type=int, default=445,
                   help="SMB 端口（默认 445）")
    p.add_argument("--check", dest="check_vuln", action="store_true",
                   default=False, help="仅检测是否易受 CVE-2020-0796 影响")
    p.add_argument("-e", dest="exploit", action="store_true", default=False,
                   help="直接执行 SMBGhost 利用")
    p.add_argument("--lhost", dest="lhost", type=str, help="反弹 shell 的 LHOST")
    p.add_argument("--lport", dest="lport", type=str, help="反弹 shell 的 LPORT")
    p.add_argument("--arch", dest="arch", type=str, default="x64",
                   help="目标 Windows 架构（默认 x64）")
    p.add_argument("--silent", dest="silent", action="store_true", default=False,
                   help="静默扫描模式")
    p.add_argument("--shellcode", dest="shellcode_menu", action="store_true",
                   default=False, help="交互式选择 shellcode")
    p.add_argument("--load-shellcode", dest="load_shellcode",
                   help="从文件加载 shellcode")
    p.set_defaults(func=smbv3_exp_handle)