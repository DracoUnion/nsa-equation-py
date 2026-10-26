"""setourip — SetOurIp.exe 移植（LegacyWindowsExploits/Resources/Tools）。

原始 `SetOurIP <input file> <output file> [IP address]`：当前构建仅作为
CopyFileA 封装（"set of IP no longer done with this exe"），第三个 IP 参数
被解析但忽略。
"""
from . import setourip


def setourip_handle(args):
    return setourip.run(args.input_file, args.output_file)


def reg_subparser(subparsers):
    p = subparsers.add_parser(
        "setourip", help="SetOurIp.exe 文件复制工具（原 IP 替换功能已废弃）",
        description=__doc__,
        formatter_class=__import__("argparse").RawDescriptionHelpFormatter)
    p.add_argument("input_file", help="源文件")
    p.add_argument("output_file", help="输出文件")
    p.add_argument("ip", nargs="?", default=None,
                   help="保留参数（本构建忽略）")
    p.set_defaults(func=setourip_handle)