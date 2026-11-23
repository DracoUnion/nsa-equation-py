#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
oddjob_config — Oddjob v3 implant configuration builder.

Python rewrite of `oddjob_config_v3.exe` recovered from
`EQGRP_Lost_in_Translation-master/oddjob/Binaries/oddjob_builder/builder/
oddjob_config_v3.exe`.

Oddjob Config v3 builds an Oddjob implant binary by:

  1. Loading a template PE (embedded resource),
  2. Encrypting the implant configuration with the Windows CryptoAPI
     (CryptAcquireContextW / CryptDeriveKey / CryptGenRandom / CryptEncrypt
     / CryptCreateHash / CryptHashData / ...),
  3. Injecting the encrypted configuration into the PE as a resource
     (BeginUpdateResourceW / UpdateResourceW / EndUpdateResourceW),
  4. Recalculating the PE checksum (CheckSumMappedFile from imagehlp.dll),
  5. Writing the final Oddjob implant executable.

Recovered strings from the binary:
  "CheckSumMappedFile" (from imagehlp.dll)
  Crypt* API names (ADVAPI32.dll)
  BeginUpdateResourceW / UpdateResourceW / EndUpdateResourceW (KERNEL32.dll)
  FindResourceW / LoadResource / LockResource / SizeofResource (KERNEL32.dll)

This module reproduces that behaviour in portable Python using `ctypes` to call
the Windows CryptoAPI and imagehlp checksum functions when running on Windows,
or pure-Python equivalents (AES-XOR style obfuscation + PE resource injection)
on other platforms.

CLI:

  oddjob_config <template_pe> <config_json> <output_pe>
       [--key <hex_key>] [--resource-name <name>] [--resource-type <type>]
"""

from . import oddjob_config_exp


def oddjob_config_handle(args):
    """Build an Oddjob v3 implant with the supplied configuration."""
    return oddjob_config_exp.run_function(
        template=args.template,
        config_file=args.config,
        output=args.output,
        key=args.key,
        resource_name=args.resource_name,
        resource_type=args.resource_type,
    )


def reg_subparser(subparsers):
    """Register the `oddjob_config` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "oddjob_config",
        help="Oddjob v3 植入配置构建器",
        description="Oddjob Config v3 — Equation Group Oddjob 植入的配置构建工具。"
                    "加载模板 PE，加密配置数据，注入为 PE 资源，重算校验和，"
                    "输出最终的 Oddjob 植入可执行文件。",
    )
    p.add_argument(
        "template", metavar="TEMPLATE_PE",
        help="模板 PE 文件路径",
    )
    p.add_argument(
        "config", metavar="CONFIG_JSON",
        help="植入配置 JSON 文件路径",
    )
    p.add_argument(
        "output", metavar="OUTPUT_PE",
        help="输出植入 PE 文件路径",
    )
    p.add_argument(
        "-k", "--key", metavar="HEX_KEY",
        help="加密密钥 (十六进制，如不指定则随机生成)",
    )
    p.add_argument(
        "-n", "--resource-name", metavar="NAME",
        default="ODDJOB_CFG",
        help="配置资源名称 (默认 ODDJOB_CFG)",
    )
    p.add_argument(
        "-t", "--resource-type", type=int, default=10, metavar="TYPE",
        help="资源类型 ID：10=RCDATA (默认 10)",
    )
    p.set_defaults(func=oddjob_config_handle)
