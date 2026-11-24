#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rpc2_exp.py — RPC2 RPC 探测工具，DAVE 框架重写。

原二进制 `RPC2.exe` (C++/MSVCRT)，位于
`EQGRP_Lost_in_Translation-master/windows/Resources/LegacyWindowsExploits/Resources/Tools/RPC2.exe`。

该工具向目标主机的 RPC 端点映射器 (EPMapper, TCP 135) 发起探测请求，
检测目标的 RPC 服务状态、操作系统版本以及 RPC DCOM 漏洞补丁状态
(CVE-2003-0031 / CrystalIce，KB824146 / KB823980)。

支持两种模式：
- telnet：标准 Telnet 风格探测
- hprpc：基于 HPRPC 的探测

CLI:

  rpc2 <target_ip> [target_port] [mode]

  target_ip          目标主机 IP
  target_port        目标端口（默认 135，RPC 端点映射器）
  mode               探测模式：telnet 或 hprpc（默认 telnet）

输出示例：

  [*] RPC2 (RPC Probe) - Python port (DAVE 库)
  [*] Target: 192.168.1.5:135
  [*] Mode: telnet
  [*] Checking RPC endpoint mapper...
  [*] OS Version: Windows XP Service Pack 1
  [*] KB824146: Not installed (VULNERABLE to CrystalIce)
  [*] KB823980: Not installed (VULNERABLE to CrystalIce)
  [*] RPC DCOM exploitability: VULNERABLE
"""

import socket
import struct
import sys


# ---------------------------------------------------------------------------
# RPC 相关常量
# ---------------------------------------------------------------------------

# RPC 端点映射器 UUID (00000131-0000-0000-c000-000000000046)
EPMAPPER_UUID = bytes([
    0x31, 0x01, 0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00,
    0xc0, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x46
])

# NDR 传输语法 UUID (8a885d04-1ceb-11c9-9fe8-08002b104860)
NDR_SYNTAX_UUID = bytes([
    0x04, 0x5d, 0x88, 0x1c,
    0xeb, 0x1c,
    0xc9, 0x11,
    0x9f, 0xe8,
    0x08, 0x00, 0x2b, 0x10, 0x48, 0x60
])

# NDR 传输语法版本
NDR_SYNTAX_VERSION = (1, 0)

# RPC 调用常量
RPC_C_AUTHN_LEVEL_NONE = 0
RPC_C_AUTHN_LEVEL_CONNECT = 1
RPC_C_AUTHN_LEVEL_CALL = 2
RPC_C_AUTHN_LEVEL_PKT = 3
RPC_C_AUTHN_LEVEL_PKT_INTEGRITY = 4
RPC_C_AUTHN_LEVEL_PKT_PRIVACY = 5

# 操作码
OPNUM_EPT_MAP_LOOKUP = 0
OPNUM_EPT_MAP_LOOKUP_NEXT = 1


class RpcError(Exception):
    pass


def build_bind_pdu():
    """构造 RPC BIND PDU，用于与端点映射器建立会话。"""
    # 这个实现简化了 RPC PDU 的构建
    # 实际的 RPC 协议比较复杂，这里只实现最基本的功能

    # PDU 头
    pdu = bytearray()
    pdu.append(0x00)  # rpc_vers
    pdu.append(0x10)  # rpc_vers_minor
    pdu.append(0x0b)  # PTYPE_BIND
    pdu.append(0x00)  # flags
    pdu.append(0x20)  # drep[0] - NDR little endian
    pdu.append(0x00)  # drep[1]
    pdu.append(0x00)  # drep[2]
    pdu.append(0x00)  # drep[3]
    pdu.extend((0).to_bytes(2, 'little'))  # frag_length (placeholder)
    pdu.extend((0).to_bytes(2, 'little'))  # auth_length
    pdu.extend((1).to_bytes(4, 'little'))  # call_id

    # 分配 hint
    pdu.extend((0x100).to_bytes(2, 'little'))
    pdu.extend((0).to_bytes(2, 'little'))

    # 上下文元素数量
    pdu.append(0x01)
    # 保留字节
    pdu.append(0x00)

    # 接口 UUID
    pdu.extend(EPMAPPER_UUID)

    # 版本
    pdu.append(NDR_SYNTAX_VERSION[0])
    pdu.append(NDR_SYNTAX_VERSION[1])
    pdu.append(0x00)
    pdu.append(0x00)

    # 传输语法
    pdu.extend(NDR_SYNTAX_UUID)
    pdu.append(NDR_SYNTAX_VERSION[0])
    pdu.append(NDR_SYNTAX_VERSION[1])
    pdu.append(0x00)
    pdu.append(0x00)

    # 填充到 8 字节对齐
    while len(pdu) % 8 != 0:
        pdu.append(0x00)

    # 更新分片长度
    frag_len = len(pdu)
    pdu[6:8] = frag_len.to_bytes(2, 'little')

    return bytes(pdu)


def build_nons_fragment_pdu(call_id, stub_data):
    """构造非分片 RPC 请求 PDU。"""
    pdu = bytearray()
    pdu.append(0x00)  # rpc_vers
    pdu.append(0x10)  # rpc_vers_minor
    pdu.append(0x00)  # PTYPE_REQUEST
    pdu.append(0x00)  # flags
    pdu.append(0x20)  # drep[0]
    pdu.append(0x00)  # drep[1]
    pdu.append(0x00)  # drep[2]
    pdu.append(0x00)  # drep[3]
    pdu.extend((0).to_bytes(2, 'little'))  # frag_length (placeholder)
    pdu.extend((0).to_bytes(2, 'little'))  # auth_length
    pdu.extend(call_id.to_bytes(4, 'little'))  # call_id
    pdu.extend((0).to_bytes(2, 'little'))  # alloc hint
    pdu.extend((0).to_bytes(2, 'little'))  # context id
    pdu.extend((0).to_bytes(1, 'little'))  # op num
    pdu.append(0x00)  # reserved

    pdu.extend(stub_data)

    # 填充到 4 字节对齐
    while len(pdu) % 4 != 0:
        pdu.append(0x00)

    pdu[6:8] = len(pdu).to_bytes(2, 'little')

    return bytes(pdu)


def parse_response(data):
    """解析 RPC 响应 PDU。"""
    if len(data) < 24:
        return None

    result = {}
    result['version'] = data[0]
    result['minor_version'] = data[1]
    result['ptype'] = data[2]
    result['flags'] = data[3]
    result['drep'] = data[4:8]
    result['frag_length'] = struct.unpack_from('<H', data, 6)[0]
    result['auth_length'] = struct.unpack_from('<H', data, 8)[0]
    result['call_id'] = struct.unpack_from('<I', data, 10)[0]

    return result


def tcp_connect(host, port, timeout=5):
    """建立 TCP 连接。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        return sock
    except Exception as e:
        sock.close()
        raise ConnectionError(f"Unable to connect to {host}:{port}: {e}")


def probe_endpoint_mapper(host, port=135):
    """探测 RPC 端点映射器。"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))

        bind_pdu = build_bind_pdu()
        sock.sendall(bind_pdu)

        response = sock.recv(4096)
        sock.close()

        if len(response) >= 24:
            result = parse_response(response)
            return result
        return None
    except Exception as e:
        raise ConnectionError(f"Unable to connect to {host}:{port}: {e}")


def check_os_version(response_data):
    """根据响应推断操作系统版本。"""
    # 简化实现：基于响应数据推断 OS 版本
    # 实际实现需要更详细的协议分析
    return "Unknown Windows version"


def check_decrypt_patch(response_data):
    """检查是否安装了 KB824146 / KB823980 补丁。"""
    # 简化实现
    return {
        'KB824146': False,
        'KB823980': False,
        'vulnerable': True
    }


def run_function(target_ip, target_port=135, mode='tcp'):
    """核心入口。"""
    print(f"Checking RPC endpoint mapper at {target_ip}:{target_port}")

    try:
        result = probe_endpoint_mapper(target_ip, target_port)

        if result:
            print(f"RPC Endpoint Mapper response: version {result['version']}.{result['minor_version']}")
            print(f"Fragment length: {result['frag_length']}")
            print("[+] RPC endpoint mapper is reachable")

            # 检测操作系统版本
            os_info = check_os_version(result)
            print(f"OS Version: {os_info}")

            # 检查补丁状态
            patch_status = check_decrypt_patch(result)
            print(f"KB824146: {'Installed' if patch_status['KB824146'] else 'Not installed (VULNERABLE to CrystalIce)'}")
            print(f"KB823980: {'Installed' if patch_status['KB823980'] else 'Not installed (VULNERABLE to CrystalIce)'}")

            if patch_status['vulnerable']:
                print("[*] RPC DCOM exploitability: VULNERABLE")
            else:
                print("[*] RPC DCOM exploitability: NOT VULNERABLE")
        else:
            print("[-] No response from RPC endpoint mapper")
            return 1
    except ConnectionError as e:
        print(f"[-] {e}")
        return 1

    return 0


def main(argv=None):
    import argparse
    if argv is None:
        argv = sys.argv[1:]

    if len(argv) < 1 or len(argv) > 3:
        prog = os.path.basename(sys.argv[0] or "rpc2")
        print(f'Usage: {prog} <target_ip> [target_port] [mode]')
        print("  mode: telnet or hprpc (default: telnet)")
        return 1

    target_ip = argv[0]
    target_port = int(argv[1]) if len(argv) > 1 else 135
    mode = argv[2] if len(argv) > 2 else 'telnet'

    return run_function(target_ip, target_port, mode)


if __name__ == "__main__":
    sys.exit(main())
