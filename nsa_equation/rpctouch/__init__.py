"""rpctouch — RPC/architecture/probe (Rpctouch).

Port of Rpctouch-2.1.0.exe. Detects target OS / service pack / language /
architecture over SMB (\\pipe\\browser, spoolss strings) and computes potential
non-paged-pool leak addresses used by MS08-067. Parameters: TargetIp,
TargetPort, Protocol, NetworkTimeout, NetBIOSName, TouchArchitecture,
TouchLanguage, Target(TargetString/TargetDWORD).
"""
from . import rpctouch


def rpctouch_handle(args):
    return rpctouch.run(
        target_ip=args.target_ip, target_port=args.target_port,
        protocol=args.protocol, network_timeout=args.network_timeout,
        netbios_name=args.netbios_name,
        touch_architecture=args.touch_architecture,
        touch_language=args.touch_language,
        target_string=args.target_string,
        target_dword=args.target_dword,
    )


def reg_subparser(subparsers):
    p = subparsers.add_parser("rpctouch", help="RPC Touch 探测 (Rpctouch)", description=__doc__)
    p.add_argument("target_ip")
    p.add_argument("-P", "--target-port", type=int, default=445)
    p.add_argument("--protocol", choices=["SMB", "NBT"], default="SMB")
    p.add_argument("--network-timeout", type=float, default=30.0)
    p.add_argument("--netbios-name", default="", help="NetBIOS 名")
    p.add_argument("--touch-architecture", choices=["x86", "x64", "Unknown"], default="x86")
    p.add_argument("--touch-language", default="", help="目标语言，如 English/Chinese")
    p.add_argument("--target-string", default="")
    p.add_argument("--target-dword", type=int, default=0)
    p.set_defaults(func=rpctouch_handle)