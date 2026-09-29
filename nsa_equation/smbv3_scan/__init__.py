"""smbv3-scan — CVE-2020-0796 (SMBGhost) detection scanner.

Python rewrite of the SMB scanner embedded in `CVE-2020-0796-Scanner.exe`
(the native `smb_poc.pyd` module, driven by `main` -> `smb_poc.run_function`).
Detection only; no exploit is performed.
"""

from . import smbv3_scan


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def smbv3_scan_handle(args):
    """Scan the supplied target(s) and report SMB 3.1.1 hosts."""
    return smbv3_scan.run_function(
        targets=args.targets,
        port=args.port,
        timeout=args.timeout,
        threads=args.threads,
    )


def reg_subparser(subparsers):
    """Register the `smbv3-scan` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "smbv3-scan",
        help="CVE-2020-0796 (SMBGhost) SMBv3 检测扫描器",
        description="扫描目标（单个 IP 或 CIDR 子网）并通过 SMB2 NEGOTIATE 探测"
                    "其协商的 SMB 方言；协商 SMB 3.1.1 (0x0311) 的主机为 "
                    "CVE-2020-0796 潜在受影响面。仅检测，不包含实际利用。",
    )
    p.add_argument(
        "targets", nargs="+",
        help="一个或多个目标：单个 IP 或 CIDR 子网，例如 192.168.1.5 或 "
             "192.168.1.0/24",
    )
    p.add_argument("-p", "--port", type=int, default=smbv3_scan.DEFAULT_PORT,
                   help="SMB 端口（默认 %d）" % smbv3_scan.DEFAULT_PORT)
    p.add_argument("-t", "--timeout", type=float, default=3.0,
                   help="连接超时秒数（默认 3）")
    p.add_argument("-n", "--threads", type=int, default=32,
                   help="并发线程数（默认 32）")
    p.set_defaults(func=smbv3_scan_handle)