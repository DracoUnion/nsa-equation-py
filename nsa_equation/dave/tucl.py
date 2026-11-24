# -*- coding: utf-8 -*-
"""
dave.tucl — TUCL 日志输出（TcLog）。

对应 DLL：tucl-1.dll（6 个导出函数）。

原二进制导出：
  DEBUG_TcLog
  TcLog
  TcLogBuffer
  TcLogClose
  TcLogOpen
  TcLogSetMask
"""

import sys
import os


class TcLogContext:
    """日志上下文，对应原 C++ 日志对象。"""

    def __init__(self, path=None, mask=0xFFFFFFFF):
        self.path = path
        self.mask = mask
        self._file = None
        self.opened = False

    def open(self, path=None, mask=None):
        if path is not None:
            self.path = path
        if mask is not None:
            self.mask = mask
        if self.path:
            self._file = open(self.path, "ab")
        self.opened = True
        return self

    def close(self):
        if self._file is not None:
            self._file.close()
            self._file = None
        self.opened = False

    def log(self, level, msg):
        if not (self.mask & level):
            return
        text = "[%d] %s\n" % (level, msg)
        if self._file is not None:
            self._file.write(text.encode("utf-8", errors="replace"))
            self._file.flush()
        else:
            sys.stderr.write(text)
            sys.stderr.flush()

    def log_buffer(self, level, buf, prefix=""):
        if not (self.mask & level):
            return
        lines = [prefix + " " + " ".join("%02X" % b for b in buf[i:i+16])
                 for i in range(0, len(buf), 16)]
        self.log(level, "\n".join(lines))


_TCLOG_DEFAULT_MASK = 0xFFFFFFFF
_default_ctx = TcLogContext()


def TcLogOpen(path=None, mask=None):
    _default_ctx.open(path, mask)
    return _default_ctx


def TcLogClose():
    _default_ctx.close()


def TcLogSetMask(mask):
    _default_ctx.mask = mask


def TcLog(level, msg):
    _default_ctx.log(level, msg)


def TcLogBuffer(level, buf, prefix=""):
    _default_ctx.log_buffer(level, buf, prefix)


def DEBUG_TcLog(msg):
    """调试级日志（mask bit 0）。"""
    TcLog(1, msg)
