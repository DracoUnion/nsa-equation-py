#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""nsa-equation-py

Reverse-engineered reimplementations of legacy tooling (e.g. the DNS
payload-builder derived from `dns.exe` via IDA Pro) in portable Python.
Reference CLI layout follows https://github.com/DracoUnion/BookerGptTool
"""

__author__ = "wizardforcel"
__email__ = "wizard.z@qq.com"
__license__ = "SATA"
__version__ = "2026.9.28.0"
# Submodule imports
from . import dns
from . import cve_2020_0796_scanner
from . import cve_2020_0796_exp
from . import getarch
from . import ms06040rpc
from . import eternalblue
from . import ms06040rpc_unpacked_v2
from . import eclipsedwing
from . import eclipsedwingtouch
from . import doublepulsar
from . import pcdlllauncher
from . import rpcproxy
from . import rpctouch
from . import danecfg
from . import eternal_champion
from . import eternal_romance
from . import eternal_synergy_14
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
from . import eternal_synergy
from . import eternal_synergy_14
from . import mofconfig
