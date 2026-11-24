#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dszlpcore — DszLpCore 后门核心工具。

Python 重写自 `DszLpCore.exe` (C++/MSVCRT)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/.../DszLpCore.exe`。

DszLp.exe 是一个轻量级启动壳，它设置 DLL 搜索目录并创建
DszLpCore.exe（继承标准句柄）；DszLpCore.exe 才是包含真正逻辑的主体。
本移植实现其核心行为：作为 TCP 监听/代理，继承标准输入输出并与
远程端点保持通信。

CLI:

  dszlpcore <listen_port> [connect_target] [connect_port]

  listen_port   - 本地监听端口
  connect_target - 可选，反向连接目标主机
  connect_port  - 可选，反向连接目标端口
"""

import os
import socket
import sys
import threading


def _handle_client(conn, addr, upstream):
    """处理单个客户端连接：将其与上游上游 socket 双向转发。"""
    print("[+] Client connected from %s:%d" % (addr[0], addr[1]))
    try:
        while True:
            try:
                data = conn.recv(4096)
            except OSError:
                break
            if not data:
                break
            try:
                upstream.sendall(data)
            except OSError:
                break
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        conn.close()
    except OSError:
        pass


def run_function(listen_port, connect_target=None, connect_port=None):
    """核心入口。"""
    print("DszLpCore core tool")
    print("Listen port: %d" % listen_port)
    if connect_target:
        print("Connect target: %s:%d" % (connect_target, connect_port))

    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listen_sock.bind(("0.0.0.0", listen_port))
    except OSError as e:
        print("Unable to bind to port %d (%s)" % (listen_port, e))
        return 1
    listen_sock.listen(5)
    print("Listening on port %d ..." % listen_port)

    upstream = None
    if connect_target and connect_port:
        try:
            upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            upstream.connect((connect_target, connect_port))
            print("Connected to upstream %s:%d" % (connect_target, connect_port))
        except OSError as e:
            print("Unable to connect to upstream %s:%d (%s)" % (connect_target, connect_port, e))
            upstream = None

    try:
        while True:
            try:
                conn, addr = listen_sock.accept()
            except OSError:
                break
            t = threading.Thread(target=_handle_client, args=(conn, addr, upstream), daemon=True)
            t.start()
    except KeyboardInterrupt:
        pass
    finally:
        listen_sock.close()
        if upstream:
            upstream.close()

    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if len(argv) < 1 or len(argv) > 3:
        prog = os.path.basename(sys.argv[0] or "dszlpcore")
        print('Usage: %s <listen_port> [connect_target] [connect_port]' % prog)
        return 1
    listen_port = int(argv[0]) if argv[0].isdigit() else 445
    connect_target = argv[1] if len(argv) > 1 else None
    connect_port = int(argv[2]) if len(argv) > 2 and argv[2].isdigit() else None
    return run_function(listen_port, connect_target, connect_port)


if __name__ == "__main__":
    sys.exit(main())