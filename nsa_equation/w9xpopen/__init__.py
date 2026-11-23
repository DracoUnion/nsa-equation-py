#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
w9xpopen — Windows 95/98 popen workaround tool.

Python rewrite of `w9xpopen.exe` (C++, MSVCR71), recovered from
`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/
Exploits/EAFU 2.2.0/EAFU_SSL_exe/w9xpopen.exe`.

This tool is used by Python's os.popen function to work around a limitation
in Windows 95/98.  It is not designed to be used as a stand-alone program,
but this port provides a standalone CLI for compatibility.

Recovered interface from the binary's imports:

  KERNEL32:  CreateProcessA, WaitForSingleObject, GetExitCodeProcess,
             CloseHandle, GetFileType, GetStdHandle, GetModuleHandleA
  USER32:    MessageBoxA
  MSVCR71:   standard C runtime (__getmainargs, free, strchr, malloc,
             fprintf, _iob, _c_exit, _exit, _XcptFilter, _controlfp,
             exit, __p___initenv, _amsg_exit, _cexit, _initterm,
             __setusermatherr, _adjust_fdiv, __p__commode, __p__fmode,
             __set_app_type, _except_handler3, __dllonexit, _onexit)

CLI:

  w9xpopen <command> [args...]

Runs `<command>` with the supplied arguments, waits for it to finish, and
returns its exit code.  On error, displays a message box (Windows) or prints
to stderr.
"""

from . import w9xpopen_exp


def w9xpopen_handle(args):
    """Run the w9xpopen tool to execute a command and wait for completion."""
    return w9xpopen_exp.run_function(
        command=args.command,
        args=args.command_args,
        show_errors=args.show_errors,
    )


def reg_subparser(subparsers):
    """Register the `w9xpopen` subcommand on an argparse subparsers group."""
    p = subparsers.add_parser(
        "w9xpopen",
        help="w9xpopen Windows 95/98 popen workaround tool",
        description="w9xpopen — Windows 95/98 popen workaround tool. Runs a"
                    " command and waits for it to complete, returning its"
                    " exit code. Not designed for stand-alone use.",
    )
    p.add_argument(
        "command", metavar="COMMAND",
        help="Command to execute",
    )
    p.add_argument(
        "command_args", metavar="ARG", nargs="*",
        help="Arguments to pass to the command",
    )
    p.add_argument(
        "--show-errors", action="store_true",
        help="Show error message box on failure",
    )
    p.set_defaults(func=w9xpopen_handle)
