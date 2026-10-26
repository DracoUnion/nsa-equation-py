"""danecfg — DANE DLL configuration packer.

Python port of danecfg.exe. Original usage recovered from strings:
  danecfg.exe TEMPLATE_DLL PLUGIN_DLL PLUGIN_CORE_DLL CONFIG_XML OUTPUT_DLL
It validates PE architecture, loads plugin DLL marshalParams/freeMarshaledParams
APIs, parses XML, compresses package data (LZO), and writes plugin/config resources
to a copy of the template DLL.
"""
from . import danecfg


def danecfg_handle(args):
    return danecfg.run(args.template_dll, args.plugin_dll, args.plugin_core_dll, args.config_xml, args.output_dll)


def reg_subparser(subparsers):
    p = subparsers.add_parser("danecfg", help="DANE DLL 配置打包器", description=__doc__)
    p.add_argument("template_dll")
    p.add_argument("plugin_dll")
    p.add_argument("plugin_core_dll")
    p.add_argument("config_xml")
    p.add_argument("output_dll")
    p.set_defaults(func=danecfg_handle)