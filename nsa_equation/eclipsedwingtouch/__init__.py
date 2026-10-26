"""eclipsedwingtouch — MS08-067 vulnerability touch (detector).

Python port of Eclipsedwingtouch-1.0.4.exe. Implements the "touch" check:
establishes an SMB connection to the target, binds the BROWSER RPC interface
and sends a NetPathCompare-style request (per the strings "Building PathName1",
"Building PathName2" and "Creating NetPathCompare request") to determine
whether the host answers the MS08-067 path-walk. Prints VULNERABLE / NOT
vulnerable.
"""

from . import eclipsedwingtouch


def eclipsedwingtouch_handle(args):
    return eclipsedwingtouch.run(
        target_ip=args.target_ip,
        target_port=args.target_port,
        protocol=args.protocol,
        network_timeout=args.network_timeout,
        server_name=args.server_name,
        client_name=args.client_name,
        os_patch=args.os_patch,
    )


def reg_subparser(subparsers):
    p = subparsers.add_parser(
        "eclipsedwingtouch",
        help="MS08-067 漏洞检测 (Eclipsedwing touch)",
        description=__doc__,
    )
    p.add_argument("target_ip", help="目标 IP")
    p.add_argument("-P", "--target-port", type=int, default=445, help="目标 SMB 端口 (默认 445)")
    p.add_argument("--protocol", choices=["SMB", "NBT"], default="SMB", help="协议")
    p.add_argument("--network-timeout", type=float, default=30.0, help="网络超时")
    p.add_argument("--server-name", default="", help="ServerName (用于 PathName)")
    p.add_argument("--client-name", default="", help="ClientName")
    p.add_argument("--os-patch", help="OS 补丁信息字符串 (MS08-67/OsPatch)")
    p.set_defaults(func=eclipsedwingtouch_handle)