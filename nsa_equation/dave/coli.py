# -*- coding: utf-8 -*-
"""
dave.coli — COLI 命令行接口。

对应 DLL：coli-0.dll（7 个导出函数）。

原二进制导出：
  coli_create
  coli_delete
  coli_setCleanup
  coli_setID
  coli_setProcess
  coli_setValidate
  mainWrapper
"""

import os
import sys


class ColiContext:
    """命令行上下文，对应原 C++ 对象。"""

    def __init__(self, ident=None):
        self.id = ident
        self.process = None
        self.cleanup = None
        self.validate = None
        self.initialized = False
        self.refs = 0

    def set_id(self, ident):
        self.id = ident
        return self

    def set_process(self, proc):
        self.process = proc
        return self

    def set_cleanup(self, cleanup):
        self.cleanup = cleanup
        return self

    def set_validate(self, validator):
        self.validate = validator
        return self

    def initialize(self):
        self.initialized = True
        self.refs += 1
        return self

    def run(self, argv=None):
        if self.process is None:
            raise RuntimeError("coli: no process callback set")
        return self.process(argv if argv is not None else sys.argv[1:])

    def cleanup_run(self):
        if self.cleanup is not None:
            self.cleanup()


def coli_create(ident=None):
    return ColiContext(ident)


def coli_delete(ctx):
    if ctx is not None:
        ctx.initialized = False
        ctx.refs = 0


def coli_setID(ctx, ident):
    if ctx is None:
        return None
    return ctx.set_id(ident)


def coli_setProcess(ctx, proc):
    if ctx is None:
        return None
    return ctx.set_process(proc)


def coli_setCleanup(ctx, cleanup):
    if ctx is None:
        return None
    return ctx.set_cleanup(cleanup)


def coli_setValidate(ctx, validator):
    if ctx is None:
        return None
    return ctx.set_validate(validator)


def mainWrapper(entry_func, *args, **kwargs):
    """coli mainWrapper：包装程序入口，负责初始化/清理。"""
    ctx = coli_create()
    try:
        ctx.initialize()
        return entry_func(*args, **kwargs)
    except Exception as e:
        print("coli mainWrapper: unhandled exception: %s" % e)
        return 1
    finally:
        coli_delete(ctx)
