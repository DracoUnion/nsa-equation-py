#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scanner_exp.py — Equation Group network scanner engine.

Python port of `scanner.exe` recovered via static analysis of the PE.

Recovered interface from the binary's strings:

  Scan types (from string constants):
    "Scan for windows boxes"      — NetBIOS name resolution (UDP 137)
    "Scan for Xwin folks"         — X11 font server (TCP 7100)
    "Scan for NTP  folks"         — NTP monlist/version (UDP 123)
    "Scan for RPC  folks"         — RPC endpoint mapper (TCP/UDP 111)
    "Scan for SNMP version"       — SNMP GET community "public" (UDP 161)
    "Scan for Sol  version"       — Sun Solaris
    "Scan for echo hosts"         — ICMP/TCP echo (TCP 7)
    "Scan for daytime hosts"      — DAYTIME (TCP 13)
    "Scan for tftp hosts"         — TFTP RRQ (UDP 69)
    "Scan ident"                  — IDENT/Auth (TCP 113)
    "Scan mail"                   — SMTP banner (TCP 25)
    "Scan ftp"                    — FTP banner (TCP 21)
    "Scan TCP port"               — generic TCP port probe
    "Scan web"                    — HTTP GET / (TCP 80)
    "Scan netbios"                — NetBIOS name query (UDP 137)
    "Scan for DNS"                — DNS version query (UDP 53)
    "Scan for RIP v1/v2"          — RIP routing (UDP 520)
    "Scan for lpr"                — LPD printer (TCP 515)
    "Scan for Redflag Web"        — RedFlag Linux web
    "telnet" / "Banner Telnet"    — Telnet banner (TCP 23)
    "finger" / "Banner finger"    — Finger protocol (TCP 79)
    "Scan for SSL stuff"          — SSL/TLS probe (TCP 443)
    "Scan for SSH version"        — SSH banner (TCP 22)
    "printer" / "Printer Test"    — @PJL printer job language (TCP 9100)
    "Answerbook test"             — Sun Answerbook
    "X11 test" / "X font server test" — X11 font server

  Default ports (recovered from protocol defaults):
    echo: 7, ftp: 21, ssh: 22, telnet: 23, smtp: 25, dns: 53,
    finger: 79, http: 80, tftp: 69, kerberos: 88, pop3: 110,
    ident: 113, netbios-ns: 137, netbios-dgm: 138, netbios-ssn: 139,
    snmp: 161, ldap: 389, https: 443, microsoft-ds: 445, x11: 6000,
    lpd: 515, ntp: 123, rip: 520, x11-font: 7100, pjl: 9100

This module reproduces that behaviour in portable Python using only the
stdlib (socket, struct).  Each scan type opens a raw TCP/UDP socket to the
target, sends the protocol-specific probe, and prints the banner/response.
"""

import socket
import struct
import sys
import time


# ---------------------------------------------------------------------------
# Constants recovered from scanner.exe strings.
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT = 5

SCAN_TYPES = {
    "windows":   "windows boxes",
    "x11":       "Xwin folks",
    "ntp":       "NTP folks",
    "rpc":       "RPC folks",
    "snmp":      "SNMP version",
    "solaris":   "Sol version",
    "echo":      "echo hosts",
    "daytime":   "daytime hosts",
    "tftp":      "tftp hosts",
    "ident":     "ident",
    "mail":      "mail",
    "ftp":       "ftp",
    "tcp":       "TCP port",
    "web":       "web",
    "netbios":   "netbios",
    "dns":       "DNS",
    "rip1":      "RIP v1",
    "rip2":      "RIP v2",
    "lpr":       "lpr",
    "redflag":   "Redflag Web",
    "telnet":    "telnet / Banner Telnet",
    "finger":    "finger / Banner finger",
    "ssl":       "SSL stuff",
    "ssh":       "SSH version",
    "printer":   "printer / Printer Test",
    "answerbook":"Answerbook test",
    "x11test":   "X11 test / X font server test",
}

# Default port per scan type (0 = use --port or protocol default).
DEFAULT_PORTS = {
    "windows":   137,
    "x11":       7100,
    "ntp":       123,
    "rpc":       111,
    "snmp":      161,
    "solaris":   0,
    "echo":      7,
    "daytime":   13,
    "tftp":      69,
    "ident":     113,
    "mail":      25,
    "ftp":       21,
    "tcp":       0,
    "web":       80,
    "netbios":   137,
    "dns":       53,
    "rip1":      520,
    "rip2":      520,
    "lpr":       515,
    "redflag":   80,
    "telnet":    23,
    "finger":    79,
    "ssl":       443,
    "ssh":       22,
    "printer":   9100,
    "answerbook":0,
    "x11test":   7100,
}

# Probe payloads per scan type.
PROBES = {
    "echo":  b"\x00" * 1,
    "web":   b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",
    "telnet":b"\xff\xfd\x03\xff\xfd\x1f",  # WILL SUPPRESS-GA, WILL ECHO
    "finger":b"\r\n",
    "ident":b"1234,5678\r\n",
    "lpr":   b"\x02\r\n",
    "printer":b"@PJL INFO CONFIG\r\n",
    "x11":   b"\x00\x00\x00\x00\x00\x00\x00\x00",
}


def _log(fmt, *args):
    sys.stderr.write((fmt % args).rstrip("\n") + "\n")


def _try_connect(target, port, timeout=DEFAULT_TIMEOUT):
    """Open a TCP connection to `target:port`.  Returns (sock, error)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        return sock, None
    except Exception as exc:
        return None, exc


def _try_udp(target, port, data, timeout=DEFAULT_TIMEOUT):
    """Send `data` via UDP to `target:port`, read one reply."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(data, (target, port))
        reply, addr = sock.recvfrom(4096)
        sock.close()
        return reply, None
    except Exception as exc:
        return None, exc


# ---------------------------------------------------------------------------
# Individual scan probes.
# ---------------------------------------------------------------------------

def scan_windows(target, port, timeout):
    """Scan for Windows boxes — NetBIOS name query (UDP 137)."""
    # NetBIOS Node Status query.
    query = (
        b"\x41\x44"          # Transaction ID
        b"\x00\x00"          # Flags (standard query)
        b"\x00\x01"          # Questions
        b"\x00\x00\x00\x00\x00\x00"  # Answer/Authority/Additional RRs
        b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"  # NBNAME "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        b"\x00\x21"          # QTYPE = NBSTAT
        b"\x00\x01"          # QCLASS = IN
    )
    reply, err = _try_udp(target, port or DEFAULT_PORTS["windows"], query, timeout)
    if err:
        _log("[-] Windows scan failed: %s", err)
        return
    if reply:
        _log("[+] Windows box responded (%d bytes): %s",
             len(reply), reply[:64].hex())
    else:
        _log("[-] No response from Windows scan")


def scan_snmp(target, port, timeout):
    """Scan for SNMP version — SNMP GET with community "public" (UDP 161)."""
    # SNMPv1 GET-Request: community "public", OID 1.3.6.1.2.1.1.1.0 (sysDescr).
    oid = bytes([0x30, 0x1e, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62,
                 0x6c, 0x69, 0x63, 0xa3, 0x12, 0x02, 0x01, 0x00, 0x02, 0x01,
                 0x00, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06, 0x02,
                 0x2b, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01,
                 0x00])
    reply, err = _try_udp(target, port or DEFAULT_PORTS["snmp"], oid, timeout)
    if err:
        _log("[-] SNMP scan failed: %s", err)
        return
    if reply:
        _log("[+] SNMP responded (%d bytes): %s",
             len(reply), reply[:128].hex())
    else:
        _log("[-] No response from SNMP scan")


def scan_ntp(target, port, timeout):
    """Scan for NTP folks — NTP monlist / version query (UDP 123)."""
    # NTP mode 7 control request (monlist).
    query = bytes([0x17, 0x00, 0x02, 0x2a]) + b"\x00" * 44
    reply, err = _try_udp(target, port or DEFAULT_PORTS["ntp"], query, timeout)
    if err:
        _log("[-] NTP scan failed: %s", err)
        return
    if reply:
        _log("[+] NTP responded (%d bytes): %s",
             len(reply), reply[:128].hex())
    else:
        _log("[-] No response from NTP scan")


def scan_rpc(target, port, timeout):
    """Scan for RPC folks — RPC endpoint mapper probe (TCP/UDP 111)."""
    # RPC NULL call to portmapper (program 100000, version 2, proc 4 = NULL).
    probe = (
        b"\x00\x00\x00\x01"  # XID
        b"\x00\x00\x00\x00"  # CALL
        b"\x00\x00\x00\x00"  # RPC version 2
        b"\x00\x00\x00\x3e9"  # program 100000 (portmapper)
        b"\x00\x00\x00\x02"  # version 2
        b"\x00\x00\x00\x04"  # proc 4 (NULL)
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # auth (null)
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # verifier (null)
    )
    reply, err = _try_udp(target, port or DEFAULT_PORTS["rpc"], probe, timeout)
    if err:
        _log("[-] RPC scan failed: %s", err)
        return
    if reply:
        _log("[+] RPC responded (%d bytes): %s",
             len(reply), reply[:64].hex())
    else:
        _log("[-] No response from RPC scan")


def scan_tftp(target, port, timeout):
    """Scan for TFTP hosts — TFTP RRQ (UDP 69)."""
    # TFTP Read Request for "test" in netascii mode.
    rrq = struct.pack(">H", 1) + b"test\x00netascii\x00"
    reply, err = _try_udp(target, port or DEFAULT_PORTS["tftp"], rrq, timeout)
    if err:
        _log("[-] TFTP scan failed: %s", err)
        return
    if reply:
        _log("[+] TFTP responded (%d bytes): %s",
             len(reply), reply[:64].hex())
    else:
        _log("[-] No response from TFTP scan")


def scan_dns(target, port, timeout):
    """Scan for DNS — DNS version.query (UDP 53)."""
    # DNS query for version.bind CH TXT.
    query = (
        b"\x41\x42"          # ID
        b"\x01\x00"          # flags: standard query
        b"\x00\x01"          # 1 question
        b"\x00\x00\x00\x00\x00\x00"
        b"\x07version\x04bind\x00"  # qname
        b"\x00\x10"          # qtype = TXT
        b"\x00\x03"          # qclass = CH
    )
    reply, err = _try_udp(target, port or DEFAULT_PORTS["dns"], query, timeout)
    if err:
        _log("[-] DNS scan failed: %s", err)
        return
    if reply:
        _log("[+] DNS responded (%d bytes): %s",
             len(reply), reply[:128].hex())
    else:
        _log("[-] No response from DNS scan")


def scan_rip(target, port, timeout, version=1):
    """Scan for RIP v1/v2 — RIP routing request (UDP 520)."""
    cmd = 1 if version == 1 else 2  # REQUEST
    ver = version
    probe = (
        struct.pack("BB", cmd, ver)  # command, version
        + b"\x00\x00"                 # unused
        + b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # 1 x AF=0 entry
    )
    reply, err = _try_udp(target, port or DEFAULT_PORTS["rip1"], probe, timeout)
    if err:
        _log("[-] RIP v%d scan failed: %s", version, err)
        return
    if reply:
        _log("[+] RIP v%d responded (%d bytes): %s",
             version, len(reply), reply[:128].hex())
    else:
        _log("[-] No response from RIP v%d scan", version)


def scan_tcp(target, port, timeout):
    """Generic TCP port probe."""
    if port == 0:
        port = DEFAULT_PORTS["tcp"]
    sock, err = _try_connect(target, port, timeout)
    if err:
        _log("[-] TCP port %d scan failed: %s", port, err)
        return
    try:
        sock.sendall(b"\x00")
        try:
            reply = sock.recv(1024)
            if reply:
                _log("[+] TCP port %d responded (%d bytes): %s",
                     port, len(reply), reply[:64].hex())
            else:
                _log("[+] TCP port %d open (no data)", port)
        except socket.timeout:
            _log("[+] TCP port %d open (timeout)", port)
    finally:
        sock.close()


def scan_web(target, port, timeout):
    """Scan web — HTTP GET / (TCP 80)."""
    port = port or DEFAULT_PORTS["web"]
    probe = PROBES["web"].replace(b"target", target.encode())
    sock, err = _try_connect(target, port, timeout)
    if err:
        _log("[-] Web scan failed: %s", err)
        return
    try:
        sock.sendall(probe)
        reply = sock.recv(2048)
        if reply:
            _log("[+] Web responded (%d bytes): %s",
                 len(reply), reply[:128].decode("latin-1", "replace"))
        else:
            _log("[-] No response from web scan")
    finally:
        sock.close()


def scan_netbios(target, port, timeout):
    """Scan netbios — NetBIOS name query (UDP 137)."""
    return scan_windows(target, port, timeout)


def scan_telnet(target, port, timeout):
    """Banner Telnet — Telnet banner grab (TCP 23)."""
    port = port or DEFAULT_PORTS["telnet"]
    sock, err = _try_connect(target, port, timeout)
    if err:
        _log("[-] Telnet scan failed: %s", err)
        return
    try:
        sock.sendall(PROBES["telnet"])
        reply = sock.recv(2048)
        if reply:
            _log("[+] Telnet banner (%d bytes): %s",
                 len(reply), reply[:128].decode("latin-1", "replace"))
        else:
            _log("[-] No response from telnet scan")
    finally:
        sock.close()


def scan_finger(target, port, timeout):
    """Banner finger — Finger protocol (TCP 79)."""
    port = port or DEFAULT_PORTS["finger"]
    sock, err = _try_connect(target, port, timeout)
    if err:
        _log("[-] Finger scan failed: %s", err)
        return
    try:
        sock.sendall(PROBES["finger"])
        reply = sock.recv(2048)
        if reply:
            _log("[+] Finger responded (%d bytes): %s",
                 len(reply), reply[:128].decode("latin-1", "replace"))
        else:
            _log("[-] No response from finger scan")
    finally:
        sock.close()


def scan_ssh(target, port, timeout):
    """Scan for SSH version — SSH banner grab (TCP 22)."""
    port = port or DEFAULT_PORTS["ssh"]
    sock, err = _try_connect(target, port, timeout)
    if err:
        _log("[-] SSH scan failed: %s", err)
        return
    try:
        reply = sock.recv(2048)
        if reply:
            _log("[+] SSH banner (%d bytes): %s",
                 len(reply), reply[:128].decode("latin-1", "replace"))
        else:
            _log("[-] No response from SSH scan")
    finally:
        sock.close()


def scan_printer(target, port, timeout):
    """Printer Test — @PJL printer job language (TCP 9100)."""
    port = port or DEFAULT_PORTS["printer"]
    sock, err = _try_connect(target, port, timeout)
    if err:
        _log("[-] Printer scan failed: %s", err)
        return
    try:
        sock.sendall(PROBES["printer"])
        reply = sock.recv(2048)
        if reply:
            _log("[+] Printer responded (%d bytes): %s",
                 len(reply), reply[:128].decode("latin-1", "replace"))
        else:
            _log("[-] No response from printer scan")
    finally:
        sock.close()


def scan_ident(target, port, timeout):
    """Scan ident — IDENT/Auth protocol (TCP 113)."""
    port = port or DEFAULT_PORTS["ident"]
    sock, err = _try_connect(target, port, timeout)
    if err:
        _log("[-] IDENT scan failed: %s", err)
        return
    try:
        sock.sendall(b"1234,5678\r\n")
        reply = sock.recv(2048)
        if reply:
            _log("[+] IDENT responded (%d bytes): %s",
                 len(reply), reply[:128].decode("latin-1", "replace"))
        else:
            _log("[-] No response from IDENT scan")
    finally:
        sock.close()


def scan_mail(target, port, timeout):
    """Scan mail — SMTP banner grab (TCP 25)."""
    port = port or DEFAULT_PORTS["mail"]
    sock, err = _try_connect(target, port, timeout)
    if err:
        _log("[-] Mail scan failed: %s", err)
        return
    try:
        reply = sock.recv(2048)
        if reply:
            _log("[+] SMTP banner (%d bytes): %s",
                 len(reply), reply[:128].decode("latin-1", "replace"))
        else:
            _log("[-] No response from mail scan")
    finally:
        sock.close()


def scan_ftp(target, port, timeout):
    """Scan ftp — FTP banner grab (TCP 21)."""
    port = port or DEFAULT_PORTS["ftp"]
    sock, err = _try_connect(target, port, timeout)
    if err:
        _log("[-] FTP scan failed: %s", err)
        return
    try:
        reply = sock.recv(2048)
        if reply:
            _log("[+] FTP banner (%d bytes): %s",
                 len(reply), reply[:128].decode("latin-1", "replace"))
        else:
            _log("[-] No response from ftp scan")
    finally:
        sock.close()


def scan_daytime(target, port, timeout):
    """Scan for daytime hosts — DAYTIME protocol (TCP 13)."""
    port = port or DEFAULT_PORTS["daytime"]
    sock, err = _try_connect(target, port, timeout)
    if err:
        _log("[-] Daytime scan failed: %s", err)
        return
    try:
        reply = sock.recv(2048)
        if reply:
            _log("[+] Daytime responded (%d bytes): %s",
                 len(reply), reply[:128].decode("latin-1", "replace"))
        else:
            _log("[-] No response from daytime scan")
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Scan dispatch table.
# ---------------------------------------------------------------------------

SCAN_DISPATCH = {
    "windows":   scan_windows,
    "snmp":      scan_snmp,
    "ntp":       scan_ntp,
    "rpc":       scan_rpc,
    "tftp":      scan_tftp,
    "dns":       scan_dns,
    "rip1":      lambda t, p, to: scan_rip(t, p, to, 1),
    "rip2":      lambda t, p, to: scan_rip(t, p, to, 2),
    "tcp":       scan_tcp,
    "web":       scan_web,
    "netbios":   scan_netbios,
    "telnet":    scan_telnet,
    "finger":    scan_finger,
    "ssh":       scan_ssh,
    "printer":   scan_printer,
    "ident":     scan_ident,
    "mail":      scan_mail,
    "ftp":       scan_ftp,
    "daytime":   scan_daytime,
    "solaris":   lambda t, p, to: _log("[-] Solaris scan not yet implemented"),
    "echo":      lambda t, p, to: _log("[-] Echo scan not yet implemented"),
    "ssl":       lambda t, p, to: _log("[-] SSL scan not yet implemented"),
    "redflag":   lambda t, p, to: _log("[-] Redflag Web scan not yet implemented"),
    "lpr":       lambda t, p, to: _log("[-] LPR scan not yet implemented"),
    "answerbook":lambda t, p, to: _log("[-] Answerbook scan not yet implemented"),
    "x11test":   lambda t, p, to: _log("[-] X11 test scan not yet implemented"),
    "x11":       lambda t, p, to: _log("[-] X11 scan not yet implemented"),
}


# ---------------------------------------------------------------------------
# run_function — the original main() equivalent.
# ---------------------------------------------------------------------------
def run_function(target, scan_type="all", port=0, timeout=DEFAULT_TIMEOUT):
    """Run the network scanner against `target`.

    Returns 0 on success, non-zero on failure.
    """
    _log("Equation Group network scanner against %s", target)
    _log("Scan type: %s  Port: %d  Timeout: %d sec",
         scan_type, port if port else "auto", timeout)

    if scan_type == "all":
        for name, probe_fn in SCAN_DISPATCH.items():
            _log("[*] Running %s scan...", name)
            probe_fn(target, port, timeout)
            time.sleep(0.2)
    elif scan_type in SCAN_DISPATCH:
        SCAN_DISPATCH[scan_type](target, port, timeout)
    else:
        _log("[-] Unknown scan type: %s", scan_type)
        _log("Available: %s", ", ".join(sorted(SCAN_DISPATCH.keys())))
        return 1

    return 0


def main():
    """CLI driver (standalone testing)."""
    _log("Scanner standalone CLI not implemented — "
         "use `nsa-equation-py scanner ...`")
    return 1


if __name__ == "__main__":
    sys.exit(main())
