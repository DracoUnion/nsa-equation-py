# -*- coding: utf-8 -*-
"""
dave.adfw — ADFW 框架生命周期（create/delete/setID/setProcess/setValidate）。

对应 DLL：adfw-2.dll（6 个导出函数）。

原二进制导出：
  adfw_create
  adfw_delete
  adfw_setID
  adfw_setProcess
  adfw_setValidate
  mainWrapper
"""

import os
import sys


class AdfwContext:
    """DAVE 框架上下文，对应原 C++ 对象。"""

    def __init__(self, ident=None):
        self.id = ident
        self.process = None
        self.validate = None
        self.initialized = False
        self.refs = 0

    def set_id(self, ident):
        self.id = ident
        return self

    def set_process(self, proc):
        self.process = proc
        return self

    def set_validate(self, validator):
        self.validate = validator
        return self

    def initialize(self):
        self.initialized = True
        self.refs += 1
        return self

    def is_valid(self):
        return self.initialized and self.validate is not None and self.validate(self)


def adfw_create(ident=None):
    """创建 ADFW 上下文。"""
    return AdfwContext(ident)


def adfw_delete(ctx):
    """销毁 ADFW 上下文。"""
    if ctx is not None:
        ctx.initialized = False
        ctx.refs = 0


def adfw_setID(ctx, ident):
    if ctx is None:
        return None
    return ctx.set_id(ident)


def adfw_setProcess(ctx, proc):
    if ctx is None:
        return None
    return ctx.set_process(proc)


def adfw_setValidate(ctx, validator):
    if ctx is None:
        return None
    return ctx.set_validate(validator)


def mainWrapper(entry_func, *args, **kwargs):
    """mainWrapper：原二进制的程序入口包装，负责框架初始化/清理。

    调用 entry_func(*args, **kwargs)，并捕获异常打印错误。
    """
    ctx = adfw_create()
    try:
        ctx.initialize()
        return entry_func(*args, **kwargs)
    except Exception as e:
        print("mainWrapper: unhandled exception: %s" % e)
        return 1
    finally:
        adfw_delete(ctx)
