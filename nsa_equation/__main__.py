import argparse
import os
import sys
from . import __version__
from . import dns
from . import cve_2020_0796_scanner
from . import cve_2020_0796_exp
from . import cve_2020_0796_exp_unpacked
from . import getarch
from . import ms06040rpc
from . import ms06040rpc_unpacked
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
from . import emerald_thread
from . import ecwi
from . import smb_touch
from . import archi_touch
from . import domain_touch
from . import educated_scholar_touch
from . import erratic_gopher_touch
from . import esteem_audit_touch
from . import exploding_can_touch
from . import iis_touch
from . import namedpipe_touch
from . import webadmin_touch
from . import world_client_touch
from . import smb_delete
from . import smb_list
from . import smb_read
from . import smb_write
from . import printjob_delete
from . import printjob_list
from . import job_add
from . import job_delete
from . import job_list
from . import process_list
from . import reg_delete
from . import reg_enum
from . import reg_read
from . import reg_write
from . import easybee
from . import easy_pi
from . import englishmansdentist
from . import eskimo_roll
from . import emphasis_mine
from . import ewok_frenzy
from . import eafu
from . import eafu
from . import eafu_ssl
from . import darkpulsar
from . import eternal_synergy
from . import eternal_synergy_14
from . import etbl
from . import etre
from . import evfr
from . import eske
from . import ms06040rpc_dumped
from . import emerald_thread_touch
from . import oddjob_config
from . import oj_deleter
from . import w9xpopen
from . import sc
from . import eagerlever
from . import scanner
from . import expa
from . import simrpc
from . import svctouch
from . import ridearea2
from . import mofconfig
from . import makedmgd
from . import genkey
from . import pccfg
from . import verpatch
from . import setcallback
from . import setcallbackports
from . import setouraddr
from . import setports
from . import setresourcename
from . import pc_lp
from . import yak
from . import tacothief
from . import renamer
from . import promiscdetect
from . import papercut
from . import bpfcompiler
from . import vlad
from . import epwrapper
from . import clocksvc
from . import greatdoccfg
from . import gkdecoder
from . import rc5
from . import eskimo_roll
from . import eskimo_roll
# ---- 12008smbexp kit port ----
from . import smbexp
# ---- Legacy tools ports ----
from . import setourip
from . import parsecapture
from . import ds_parselogs
from . import addresource
from . import regprobe
from . import nameprobe
from . import xxxridearea
from . import doublefeaturereader
from . import elv
from . import slDecoder
from . import st_lp
from . import sendcftrigger
from . import sendddtrigger
from . import sendpktrigger
from . import sendpctrigger
from . import pcconfig


# ---------------------------------------------------------------------------
# Subcommand -> original binary mapping (方程式工具包图形界面版 v0.68)
# ---------------------------------------------------------------------------
# Subcommand        Original .exe (relative to v0.68 root)
# ----------------- ----------------------------------------------------------------
# dns               1MS07-029-DNS/dns.exe
# cve-2020-0796-scanner  1Tools/CVE-2020-0796-Scanner.exe
# cve-2020-0796-exp      1Tools/CVE-2020-0796-EXP.exe
# cve-2020-0796-exp-unpacked  1Tools/CVE-2020-0796-EXP_unpacked.exe
# getarch          1Tools/getArch.exe
# ms06040rpc      1ms06040rpc_Modified/ms06040rpc.exe
# ms06040rpc-unpacked     1ms06040rpc_Modified/ms06040rpc_unpacked.exe
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
# eternal-romance-1.4 EQGRP_Lost_in_Translation-master/windows/exploits/Eternalromance-1.4.0.exe
# exploding-can     EQGRP_Lost_in_Translation-master/windows/exploits/Explodingcan-2.0.2.exe
# eternal-synergy   EQGRP_Lost_in_Translation-master/windows/exploits/Eternalsynergy-1.0.1.exe
# esteem-audit      EQGRP_Lost_in_Translation-master/windows/exploits/Esteemaudit-2.1.0.exe
# etbl                EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/Exploits/ETBL 1.1.1/ETBL.exe
# etre                EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/Exploits/ETRE 1.0.4/ETRE.exe
# evfr                EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/Exploits/EVFR 3.2.0.2/EVFR.exe
# expa                EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/Exploits/EXPA 1.0.0.2/EXPA.exe
# educated-scholar  EQGRP_Lost_in_Translation-master/windows/exploits/Educatedscholar-1.0.0.exe
# emerald-thread    EQGRP_Lost_in_Translation-master/windows/exploits/Emeraldthread-3.0.0.exe
# ecwi              EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/Exploits/ECWI/ecwi.exe
# smb-touch         EQGRP_Lost_in_Translation-master/windows/touches/Smbtouch-1.1.1.exe
# archi-touch       EQGRP_Lost_in_Translation-master/windows/touches/Architouch-1.0.0.exe
# domain-touch      EQGRP_Lost_in_Translation-master/windows/touches/Domaintouch-1.1.1.exe
# educated-scholar-touch  EQGRP_Lost_in_Translation-master/windows/touches/Educatedscholartouch-1.0.0.exe
# erratic-gopher-touch    EQGRP_Lost_in_Translation-master/windows/touches/Erraticgophertouch-1.0.1.exe
# esteem-audit-touch      EQGRP_Lost_in_Translation-master/windows/touches/Esteemaudittouch-2.1.0.exe
# exploding-can-touch     EQGRP_Lost_in_Translation-master/windows/touches/Explodingcantouch-1.2.1.exe
# iis-touch               EQGRP_Lost_in_Translation-master/windows/touches/Iistouch-1.2.2.exe
# namedpipe-touch         EQGRP_Lost_in_Translation-master/windows/touches/Namedpipetouch-2.0.0.exe
# webadmin-touch          EQGRP_Lost_in_Translation-master/windows/touches/Webadmintouch-1.0.1.exe
# world-client-touch      EQGRP_Lost_in_Translation-master/windows/touches/Worldclienttouch-1.0.1.exe
# smb-delete              EQGRP_Lost_in_Translation-master/windows/payloads/Smbdelete-1.1.1.exe
# smb-list                EQGRP_Lost_in_Translation-master/windows/payloads/Smblist-1.1.1.exe
# smb-read                EQGRP_Lost_in_Translation-master/windows/payloads/Smbread-1.1.1.exe
# smb-write               EQGRP_Lost_in_Translation-master/windows/payloads/Smbwrite-1.1.1.exe
# printjob-delete         EQGRP_Lost_in_Translation-master/windows/touches/Printjobdelete-1.0.0.exe
# printjob-list           EQGRP_Lost_in_Translation-master/windows/touches/Printjoblist-1.0.0.exe
# job-add                 EQGRP_Lost_in_Translation-master/windows/payloads/Jobadd-1.1.1.exe
# job-delete              EQGRP_Lost_in_Translation-master/windows/payloads/Jobdelete-1.1.1.exe
# job-list                EQGRP_Lost_in_Translation-master/windows/payloads/Joblist-1.1.1.exe
# process-list            EQGRP_Lost_in_Translation-master/windows/payloads/Processlist-1.1.1.exe
# reg-delete              EQGRP_Lost_in_Translation-master/windows/payloads/Regdelete-1.1.1.exe
# reg-enum                EQGRP_Lost_in_Translation-master/windows/payloads/Regenum-1.1.1.exe
# reg-read                EQGRP_Lost_in_Translation-master/windows/payloads/Regread-1.1.1.exe
# reg-write               EQGRP_Lost_in_Translation-master/windows/payloads/Regwrite-1.1.1.exe
# easybee                 EQGRP_Lost_in_Translation-master/windows/exploits/Easybee-1.0.1.exe
# easy-pi                 EQGRP_Lost_in_Translation-master/windows/exploits/Easypi-3.1.0.exe
# englishmansdentist      EQGRP_Lost_in_Translation-master/windows/exploits/Englishmansdentist-1.2.0.exe
# eskimo-roll             EQGRP_Lost_in_Translation-master/windows/exploits/Eskimoroll-1.1.1.exe
# emphasis-mine           EQGRP_Lost_in_Translation-master/windows/exploits/Emphasismine-3.4.0.exe
# ewok-frenzy             EQGRP_Lost_in_Translation-master/windows/exploits/Ewokfrenzy-2.0.0.exe
# eafu                    EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/Exploits/EAFU 2.2.0/EAFU.exe
# eafu_ssl                EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/Exploits/EAFU 2.2.0/EAFU_SSL_exe/EAFU_SSL.exe
# darkpulsar              EQGRP_Lost_in_Translation-master/windows/implants/Darkpulsar-1.1.0.exe
# easy-pi                 EQGRP_Lost_in_Translation-master/windows/exploits/Easypi-3.1.0.exe
# eternal-synergy         EQGRP_Lost_in_Translation-master/windows/exploits/Eternalsynergy-1.0.1.exe
# eske                    EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/Exploits/ESKE 1.6.2/ESKE.exe
# expa                    EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/Exploits/EXPA 1.0.0.2/EXPA.exe
# mofconfig               EQGRP_Lost_in_Translation-master/windows/implants/Mofconfig-1.0.0.exe
# pcdlllauncher           EQGRP_Lost_in_Translation-master/windows/payloads/Pcdlllauncher-2.3.1.exe
# ms06040rpc-dumped       1ms06040rpc_Modified/ms06040rpc_dumped.exe
# emerald_thread_touch    EQGRP_Lost_in_Translation-master/windows/touches/Emeraldthreadtouch-1.0.0.exe
# oddjob_config           EQGRP_Lost_in_Translation-master/oddjob/Binaries/oddjob_builder/builder/oddjob_config_v3.exe
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
    cve_2020_0796_exp_unpacked.reg_subparser(subparsers)
    getarch.reg_subparser(subparsers)
    ms06040rpc.reg_subparser(subparsers)
    ms06040rpc_unpacked.reg_subparser(subparsers)
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
    emerald_thread.reg_subparser(subparsers)
    ecwi.reg_subparser(subparsers)
    smb_touch.reg_subparser(subparsers)
    archi_touch.reg_subparser(subparsers)
    domain_touch.reg_subparser(subparsers)
    educated_scholar_touch.reg_subparser(subparsers)
    erratic_gopher_touch.reg_subparser(subparsers)
    esteem_audit_touch.reg_subparser(subparsers)
    exploding_can_touch.reg_subparser(subparsers)
    iis_touch.reg_subparser(subparsers)
    namedpipe_touch.reg_subparser(subparsers)
    webadmin_touch.reg_subparser(subparsers)
    world_client_touch.reg_subparser(subparsers)
    smb_delete.reg_subparser(subparsers)
    smb_list.reg_subparser(subparsers)
    smb_read.reg_subparser(subparsers)
    smb_write.reg_subparser(subparsers)
    printjob_delete.reg_subparser(subparsers)
    printjob_list.reg_subparser(subparsers)
    job_add.reg_subparser(subparsers)
    job_delete.reg_subparser(subparsers)
    job_list.reg_subparser(subparsers)
    process_list.reg_subparser(subparsers)
    reg_delete.reg_subparser(subparsers)
    reg_enum.reg_subparser(subparsers)
    reg_read.reg_subparser(subparsers)
    reg_write.reg_subparser(subparsers)
    easybee.reg_subparser(subparsers)
    easy_pi.reg_subparser(subparsers)
    englishmansdentist.reg_subparser(subparsers)
    eskimo_roll.reg_subparser(subparsers)
    emphasis_mine.reg_subparser(subparsers)
    ewok_frenzy.reg_subparser(subparsers)
    eafu.reg_subparser(subparsers)
    darkpulsar.reg_subparser(subparsers)
    eafu_ssl.reg_subparser(subparsers)
    vlad.reg_subparser(subparsers)
    epwrapper.reg_subparser(subparsers)
    bpfcompiler.reg_subparser(subparsers)
    easy_pi.reg_subparser(subparsers)
    eternal_synergy.reg_subparser(subparsers)
    eternal_synergy_14.reg_subparser(subparsers)
    etbl.reg_subparser(subparsers)
    etre.reg_subparser(subparsers)
    evfr.reg_subparser(subparsers)
    eske.reg_subparser(subparsers)
    scanner.reg_subparser(subparsers)
    eagerlever.reg_subparser(subparsers)
    expa.reg_subparser(subparsers)
    simrpc.reg_subparser(subparsers)
    w9xpopen.reg_subparser(subparsers)
    svctouch.reg_subparser(subparsers)
    sc.reg_subparser(subparsers)
    ridearea2.reg_subparser(subparsers)
    ms06040rpc_dumped.reg_subparser(subparsers)
    emerald_thread_touch.reg_subparser(subparsers)
    oddjob_config.reg_subparser(subparsers)
    oj_deleter.reg_subparser(subparsers)
    mofconfig.reg_subparser(subparsers)
    makedmgd.reg_subparser(subparsers)
    genkey.reg_subparser(subparsers)
    pccfg.reg_subparser(subparsers)
    verpatch.reg_subparser(subparsers)
    setcallback.reg_subparser(subparsers)
    setcallbackports.reg_subparser(subparsers)
    setouraddr.reg_subparser(subparsers)
    setports.reg_subparser(subparsers)
    setresourcename.reg_subparser(subparsers)
    pc_lp.reg_subparser(subparsers)
    yak.reg_subparser(subparsers)
    tacothief.reg_subparser(subparsers)
    renamer.reg_subparser(subparsers)
    promiscdetect.reg_subparser(subparsers)
    papercut.reg_subparser(subparsers)
    bpfcompiler.reg_subparser(subparsers)
    vlad.reg_subparser(subparsers)
    epwrapper.reg_subparser(subparsers)
    clocksvc.reg_subparser(subparsers)
    greatdoccfg.reg_subparser(subparsers)
    gkdecoder.reg_subparser(subparsers)
    rc5.reg_subparser(subparsers)
    pcdlllauncher.reg_subparser(subparsers)
    # ---- 12008smbexp kit port ----
    smbexp.reg_subparser(subparsers)
    # ---- Legacy tools ports ----
    setourip.reg_subparser(subparsers)
    parsecapture.reg_subparser(subparsers)
    ds_parselogs.reg_subparser(subparsers)
    addresource.reg_subparser(subparsers)
    regprobe.reg_subparser(subparsers)
    nameprobe.reg_subparser(subparsers)
    xxxridearea.reg_subparser(subparsers)
    doublefeaturereader.reg_subparser(subparsers)
    elv.reg_subparser(subparsers)
    slDecoder.reg_subparser(subparsers)
    st_lp.reg_subparser(subparsers)
    sendcftrigger.reg_subparser(subparsers)
    sendddtrigger.reg_subparser(subparsers)
    sendpktrigger.reg_subparser(subparsers)
    sendpctrigger.reg_subparser(subparsers)
    pcconfig.reg_subparser(subparsers)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == '__main__':
    main()