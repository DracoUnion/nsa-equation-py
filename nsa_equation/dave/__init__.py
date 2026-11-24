# -*- coding: utf-8 -*-
"""
nsa_equation.dave — DAVE 框架统一协议库。

DAVE 是 EQGRP 工具套件中通用的内部协议栈，由一组 DLL 实现：
  adfw  — 框架生命周期（create/delete/setID/setProcess/setValidate）
  posh  — 字节序转换（big/little endian 读写）
  tibe  — TCP/IP 缓冲区交换（SMB、DCE-RPC、NTLM、Kerberos、Netlogon、SNEGO、加密）
  trch  — XML 参数化配置序列化（Config/Params/Parameter/Paramchoice/Paramgroup）
  trfo  — 编码/加密（base64、MD4/MD5、RC4、XOR、UUID、压缩）
  tucl  — 日志输出（TcLog）
  coli  — 命令行接口

本库以 Python 重现各 DLL 的导出函数语义，并在此基础上提供
dave.protocol 高层会话对象，供 Eclipsedwing 等 DAVE 框架工具复用。
"""

from . import posh
from . import trfo
from . import adfw
from . import coli
from . import tucl
from . import tibe
from . import trch
from . import protocol

__all__ = ["posh", "trfo", "adfw", "coli", "tucl", "tibe", "trch", "protocol"]

__version__ = "2026.11.24.1"
