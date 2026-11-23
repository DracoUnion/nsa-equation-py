"""mofconfig — MOFConfig 注册表/MOF 配置工具。

Python 重写的 NSA Mofconfig 工具 `Mofconfig-1.0.0.exe`
(C++ / DAVE framework)，通过 IDA Pro / x32dbg 逆向恢复。
实现了该工具的 key=value 参数接口及其 MOF 配置生成流程。
"""

from . import mofconfig


# ---------------------------------------------------------------------------
# Subcommand entrypoint.
# ---------------------------------------------------------------------------
def mofconfig_handle(args):
    """Run the MOFCONFIG configuration sequence against the supplied host."""
    return mofconfig.run_function(
        mof_file=args.mof_file,
        mof_compiler=args.mof_compiler,
        output_file=args.output_file,
        remote_mof_path=args.remote_mof_path,
        remote_dll_path=args.remote_dll_path,
        remote_mof_trigger_path=args.remote_mof_trigger_path,
        verbose=args.verbose,
    )


def reg_subparser(subparsers):
    """Register the `mofconfig` subcommand on an argparse
    subparsers group."""
    p = subparsers.add_parser(
        "mofconfig",
        help="MOFConfig 注册表/MOF 配置工具",
        description="Python 重写的 NSA Mofconfig (MOFConfig) 配置工具 "
                    "Mofconfig-1.0.0。用于生成 MOF 配置文件以支持远程"
                    "利用工具的后续投递。",
    )
    p.add_argument(
        "--mof-file", metavar="FILE",
        help="MOF 文件模板（默认 start_dll.mof）",
    )
    p.add_argument(
        "--mof-compiler", metavar="FILE",
        help="本地 MOF 编译器（默认 C:\\windows\\system32\\wbem\\mofcomp.exe）",
    )
    p.add_argument(
        "--output-file", metavar="FILE",
        help="MOF 文件输出路径（默认 nnetcfg.mof）",
    )
    p.add_argument(
        "--remote-mof-path", metavar="PATH",
        help="目标 MOF 文件路径（默认 \\windows\\system32\\wbem\\.mof\\nnetcfg.mof）",
    )
    p.add_argument(
        "--remote-dll-path", metavar="PATH",
        help="目标 DLL 文件路径（默认 \\windows\\system32\\wbem\\wbemess2.tlb）",
    )
    p.add_argument(
        "--remote-mof-trigger-path", metavar="PATH",
        help="目标 MOF 触发文件路径（默认 \\windows\\system32\\wbem\\.mof\\evntprv.mof）",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="输出参数与调试信息",
    )
    p.set_defaults(func=mofconfig_handle)
