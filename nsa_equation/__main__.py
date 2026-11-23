import argparse
import os
import sys
from . import __version__
from . import dns
from . import cve_2020_0796_scanner
from . import cve_2020_0796_exp
from . import getarch
from . import ms06040rpc
from . import eternalblue
from . import ms06040rpc_unpacked_v2
# ---- Eclipsedwing-ms08 kit ports ----
from . import eclipsedwing
from . import eclipsedwingtouch
from . import doublepulsar
from . import pcdlllauncher
from . import rpcproxy
from . import rpctouch
from . import danecfg
from . import eternal_champion
from . import eternal_romance
from . import exploding_can
from . import esteem_audit
from . import erratic_gopher
from . import educated_scholar
# ---- 12008smbexp kit port ----
from . import smbexp
# ---- Legacy tools ports ----
from . import setourip


# ---------------------------------------------------------------------------
# Subcommand -> original binary mapping (方程式工具包图形界面版 v0.68)
# ---------------------------------------------------------------------------
# Subcommand        Original .exe (relative to v0.68 root)
# ----------------- ----------------------------------------------------------------
# dns               1MS07-029-DNS/dns.exe
# cve-2020-0796-scanner  1Tools/CVE-2020-0796-Scanner.exe
# cve-2020-0796-exp      1Tools/CVE-2020-0796-EXP.exe
# getarch          1Tools/getArch.exe
# ms06040rpc      1ms06040rpc_Modified/ms06040rpc.exe
# eternalblue     EQGRP_Lost_in_Translation-master/windows/specials/Eternalblue-2.2.0.exe
# ms06040rpc-unpacked-v2   1ms06040rpc_Modified/ms06040rpc_unpacked_v2.exe
# eclipsedwing      Eclipsedwing-ms08-2000-xp-03-08/Eclipsedwing-1.5.2.exe
# eclipsedwingtouch Eclipsedwing-ms08-2000-xp-03-08/Eclipsedwingtouch-1.0.4.exe
# doublepulsar      Eclipsedwing-ms08-2000-xp-03-08/Doublepulsar-1.3.1.exe
# pcdlllauncher     Eclipsedwing-ms08-2000-xp-03-08/Pcdlllauncher-2.3.1.exe
# rpcproxy          Eclipsedwing-ms08-2000-xp-03-08/Rpcproxy-1.0.1.exe
# rpctouch          Eclipsedwing-ms08-2000-xp-03-08/Rpctouch-2.1.0.exe
# danecfg           Eclipsedwing-ms08-2000-xp-03-08/danecfg.exe
# eternal-champion  EQGRP_Lost_in_Translation-master/windows/specials/Eternalchampion-2.0.0.exe
# eternal-romance   EQGRP_Lost_in_Translation-master/windows/exploits/Eternalromance-1.3.0.exe
# exploding-can     EQGRP_Lost_in_Translation-master/windows/exploits/Explodingcan-2.0.2.exe
# esteem-audit      EQGRP_Lost_in_Translation-master/windows/exploits/Esteemaudit-2.1.0.exe
# educated-scholar  EQGRP_Lost_in_Translation-master/windows/exploits/Educatedscholar-1.0.0.exe
# smbexp            12008smbexp/smbexp.exe
# setourip          EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/Resources/Tools/SetOurIp.exe
#
# Not yet implemented (see traverse results): Eternalchampion exploit buffers,
# Eternalromance Transaction-leak/backdoor buffers, and the remaining 122 tools
# are pending reverse-engineering from IDA Pro / x32dbg.


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
    cve_2020_0796_scanner.reg_subparser(subparsers)
    cve_2020_0796_exp.reg_subparser(subparsers)
    getarch.reg_subparser(subparsers)
    ms06040rpc.reg_subparser(subparsers)
    eternalblue.reg_subparser(subparsers)
    ms06040rpc_unpacked_v2.reg_subparser(subparsers)
    # ---- Eclipsedwing-ms08 kit ports ----
    eclipsedwing.reg_subparser(subparsers)
    eclipsedwingtouch.reg_subparser(subparsers)
    doublepulsar.reg_subparser(subparsers)
    pcdlllauncher.reg_subparser(subparsers)
    rpcproxy.reg_subparser(subparsers)
    rpctouch.reg_subparser(subparsers)
    danecfg.reg_subparser(subparsers)
    eternal_champion.reg_subparser(subparsers)
    eternal_romance.reg_subparser(subparsers)
    exploding_can.reg_subparser(subparsers)
    esteem_audit.reg_subparser(subparsers)
    educated_scholar.reg_subparser(subparsers)
    # ---- 12008smbexp kit port ----
    smbexp.reg_subparser(subparsers)
    # ---- Legacy tools ports ----
    setourip.reg_subparser(subparsers)

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()