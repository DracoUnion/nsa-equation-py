import argparse
import os
import sys
from . import __version__
from . import dns
from . import smbv3_scan
from . import smbv3_exp
from . import getarch
from . import netapi32_exp
from . import reternal_blue


def main():
    argv = sys.argv[1:]

    # dns_tool keeps its own option parser and the options may start with a
    # dash (e.g. `-y`, `-R`, `-l`).  argparse cannot forward leading-dash
    # tokens through a subparser, so when `dns` is the first token we hand the
    # remainder to dns_tool verbatim, bypassing argparse entirely.  The
    # subcommand is still registered below so it shows up in `--help`.
    if argv and argv[0] == 'dns':
        dns.dns_handle(argparse.Namespace(args=argv[1:]))
        return

    openai_key = os.environ.get('OPENAI_API_KEY')
    openai_url = os.environ.get('OPENAI_BASE_URL')
    openai_model = os.environ.get('OPENAI_CHAT_MODEL', 'gpt-3.5-turbo')

    parser = argparse.ArgumentParser(
        prog="nsa-equation-py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-v", "--version", action="version",
                        version=f"nsa-equation-py version: {__version__}")
    parser.add_argument("-m", "--model", default=openai_model, help="模型名称")
    parser.add_argument("-k", "--key", default=openai_key, help="OpenAI API Key")
    parser.add_argument("-H", "--host", default=openai_url, help="API 地址")
    parser.set_defaults(func=lambda x: parser.print_help())

    subparsers = parser.add_subparsers()
    dns.reg_subparser(subparsers)
    smbv3_scan.reg_subparser(subparsers)
    smbv3_exp.reg_subparser(subparsers)
    getarch.reg_subparser(subparsers)
    netapi32_exp.reg_subparser(subparsers)
    reternal_blue.reg_subparser(subparsers)

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()