# -*- coding: utf-8 -*-
"""
dave.trch — TRCH XML 参数化配置序列化（Config/Params/Parameter/Paramchoice/Paramgroup）。

对应 DLL：trch-0.dll / trch-1.dll（约 211–265 个导出函数）。

本模块实现原二进制导出表中的参数/配置树序列化原语：
  Config/Params/Parameter/Paramgroup 创建/删除/查找/设置/取值，
  参数类型：Boolean / IPv4 / IPv6 / Buffer / String / UString / S8..U64 /
  Socket / Port / TcpPort / UdpPort，
  以及 XML 格式的 marshal/unmarshal 与命令行解析。
"""

import xml.etree.ElementTree as ET
import re
import socket
import struct
import ipaddress
from . import posh


# ---------------------------------------------------------------------------
# Parameter base classes
# ---------------------------------------------------------------------------

class Parameter:
    """单个参数，带名称、类型、值、有效性与格式。"""

    def __init__(self, name, ptype="String", value=None, required=False,
                 description="", format_str="", hide=False):
        self.name = name
        self.ptype = ptype
        self._value = value
        self.required = required
        self.description = description
        self.format_str = format_str
        self.hide = hide
        self._valid = value is not None or not required
        self.invalid_reason = ""

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, val):
        self._value = val
        self._valid = val is not None or not self.required
        self.invalid_reason = ""

    @property
    def is_valid(self):
        return self._valid

    def marshal(self):
        """将参数值序列化为字节（按 ptype）。"""
        if self._value is None:
            return b""
        if self.ptype in ("String", "UString"):
            return str(self._value).encode("utf-16-le" if self.ptype == "UString" else "ascii")
        if self.ptype in ("S8", "U8"):
            return struct.pack("<B" if self.ptype == "U8" else "b", int(self._value))
        if self.ptype in ("S16", "U16"):
            return struct.pack("<H" if self.ptype == "U16" else "h", int(self._value))
        if self.ptype in ("S32", "U32"):
            return struct.pack("<I" if self.ptype == "U32" else "i", int(self._value))
        if self.ptype in ("S64", "U64"):
            return struct.pack("<Q" if self.ptype == "U64" else "q", int(self._value))
        if self.ptype == "Boolean":
            return b"\x01" if bool(self._value) else b"\x00"
        if self.ptype == "Buffer":
            return bytes(self._value)
        if self.ptype in ("IPv4", "IPv6"):
            return socket.inet_pton(socket.AF_INET if self.ptype == "IPv4" else socket.AF_INET6,
                                    str(self._value))
        if self.ptype in ("Port", "TcpPort", "UdpPort"):
            return struct.pack("<H", int(self._value))
        return str(self._value).encode("utf-8")

    def unmarshal(self, data):
        """从字节反序列化参数值。"""
        if not data:
            self._value = None
            return
        if self.ptype in ("String", "UString"):
            enc = "utf-16-le" if self.ptype == "UString" else "ascii"
            self._value = data.decode(enc, errors="replace").rstrip("\x00")
        elif self.ptype in ("S8", "U8"):
            self._value = struct.unpack("<B" if self.ptype == "U8" else "b", data[:1])[0]
        elif self.ptype in ("S16", "U16"):
            self._value = struct.unpack("<H" if self.ptype == "U16" else "h", data[:2])[0]
        elif self.ptype in ("S32", "U32"):
            self._value = struct.unpack("<I" if self.ptype == "U32" else "i", data[:4])[0]
        elif self.ptype in ("S64", "U64"):
            self._value = struct.unpack("<Q" if self.ptype == "U64" else "q", data[:8])[0]
        elif self.ptype == "Boolean":
            self._value = bool(data[0])
        elif self.ptype == "Buffer":
            self._value = bytes(data)
        elif self.ptype in ("IPv4", "IPv6"):
            self._value = socket.inet_ntop(socket.AF_INET if self.ptype == "IPv4" else socket.AF_INET6,
                                           data)
        elif self.ptype in ("Port", "TcpPort", "UdpPort"):
            self._value = struct.unpack("<H", data[:2])[0]
        else:
            self._value = data.decode("utf-8", errors="replace")
        self._valid = True


class Paramgroup:
    """参数组，包含多个 Parameter 与嵌套 Paramgroup。"""

    def __init__(self, name):
        self.name = name
        self.params = {}
        self.groups = {}

    def add_parameter(self, param):
        self.params[param.name] = param
        return param

    def add_group(self, group):
        self.groups[group.name] = group
        return group

    def find_parameter(self, name):
        return self.params.get(name)

    def find_group(self, name):
        return self.groups.get(name)

    def marshal(self):
        root = ET.Element("Paramgroup", name=self.name)
        for p in self.params.values():
            pe = ET.SubElement(root, "Parameter", name=p.name, type=p.ptype)
            if p.value is not None:
                pe.text = str(p.value)
        for g in self.groups.values():
            root.append(g.marshal())
        return root

    @classmethod
    def unmarshal(cls, elem):
        g = cls(elem.get("name", ""))
        for pe in elem.findall("Parameter"):
            p = Parameter(pe.get("name"), pe.get("type", "String"))
            if pe.text:
                p.unmarshal(pe.text.encode("utf-8"))
            g.add_parameter(p)
        for ge in elem.findall("Paramgroup"):
            g.add_group(cls.unmarshal(ge))
        return g


class Params:
    """顶层参数集，包含回调 IP/端口等常用字段。"""

    def __init__(self):
        self.params = {}
        self.groups = {}

    def add_parameter(self, param):
        self.params[param.name] = param
        return param

    def add_group(self, group):
        self.groups[group.name] = group
        return group

    def find_parameter(self, name):
        return self.params.get(name)

    def find_group(self, name):
        return self.groups.get(name)

    def get_callback_ipv4_values(self):
        p = self.params.get("CallbackIPv4")
        return [p.value] if p and p.value else []

    def get_callback_port_values(self):
        p = self.params.get("CallbackPort")
        return [p.value] if p and p.value else []

    def marshal(self):
        root = ET.Element("Params")
        for p in self.params.values():
            pe = ET.SubElement(root, "Parameter", name=p.name, type=p.ptype)
            if p.value is not None:
                pe.text = str(p.value)
        for g in self.groups.values():
            root.append(g.marshal())
        return root

    @classmethod
    def unmarshal(cls, elem):
        p = cls()
        for pe in elem.findall("Parameter"):
            param = Parameter(pe.get("name"), pe.get("type", "String"))
            if pe.text:
                param.unmarshal(pe.text.encode("utf-8"))
            p.add_parameter(param)
        for ge in elem.findall("Paramgroup"):
            p.add_group(Paramgroup.unmarshal(ge))
        return p

    def parse_command_line(self, argv=None):
        """解析命令行：支持 --name=value 和 --name value 两种形式。"""
        import argparse
        ap = argparse.ArgumentParser(add_help=False)
        known = set(self.params.keys()) | set(self.groups.keys())
        for name in known:
            ap.add_argument("--" + name, nargs="?")
        args, _ = ap.parse_known_args(argv)
        for name, val in vars(args).items():
            if val is not None and name in self.params:
                self.params[name].value = val


def Config_create(name="Config"):
    return Params()


def Config_delete(cfg):
    pass


def Config_duplicate(cfg):
    new = Params()
    for name, p in cfg.params.items():
        np = Parameter(p.name, p.ptype, p.value, p.required, p.description,
                       p.format_str, p.hide)
        new.add_parameter(np)
    for name, g in cfg.groups.items():
        ng = Paramgroup(g.name)
        for pname, pp in g.params.items():
            np = Parameter(pp.name, pp.ptype, pp.value, pp.required,
                           pp.description, pp.format_str, pp.hide)
            ng.add_parameter(np)
        new.add_group(ng)
    return new


def Config_getID(cfg):
    return getattr(cfg, "id", "")


def Config_getConstants(cfg):
    return {n: p.value for n, p in cfg.params.items() if p.value is not None}


def Config_getInputParams(cfg):
    return cfg.params


def Config_getOutputParams(cfg):
    return cfg.params


def Config_getName(cfg):
    return cfg.name if hasattr(cfg, "name") else "Config"


def Config_getNamespaceUri(cfg):
    return ""


def Config_getSchemaVersion(cfg):
    return "1.0"


def Config_getVersion(cfg):
    return "1.0"


def Config_marshal(cfg):
    return cfg.marshal()


def Config_printUsage(cfg):
    lines = ["Usage: Config [<options>]"]
    for name, p in cfg.params.items():
        lines.append("  --%s <%s>" % (name, p.ptype))
    return "\n".join(lines)


def Config_setConstants(cfg, constants):
    for n, v in constants.items():
        if n in cfg.params:
            cfg.params[n].value = v


def Config_setInputParams(cfg, params):
    for n, v in params.items():
        if n in cfg.params:
            cfg.params[n].value = v


def Config_setOutputParams(cfg, params):
    for n, v in params.items():
        if n in cfg.params:
            cfg.params[n].value = v


def Config_unmarshal(cfg, elem):
    new = Params.unmarshal(elem)
    cfg.params = new.params
    cfg.groups = new.groups


# ---------------------------------------------------------------------------
# Paramchoice / Paramgroup (top-level)
# ---------------------------------------------------------------------------

class Paramchoice:
    def __init__(self, name):
        self.name = name
        self.paramgroups = {}

    def add_paramgroup(self, group):
        self.paramgroups[group.name] = group
        return group

    def get_paramgroup(self, name):
        return self.paramgroups.get(name)


def Paramchoice_create(name):
    return Paramchoice(name)


def Paramchoice_delete(pc):
    pass


def Paramchoice_getDefaultValue(pc):
    return {}


def Paramchoice_getDescription(pc):
    return pc.name


def Paramchoice_getName(pc):
    return pc.name


def Paramchoice_getNumParamgroups(pc):
    return len(pc.paramgroups)


def Paramchoice_getParamgroup(pc, name):
    return pc.get_paramgroup(name)


def Paramchoice_getValue(pc):
    return {g.name: g.marshal() for g in pc.paramgroups.values()}


def Paramchoice_hasValidValue(pc):
    return all(g.is_valid() for g in pc.paramgroups.values())


def Paramchoice_hasValue(pc):
    return bool(pc.paramgroups)


def Paramchoice_isValid(pc):
    return Paramchoice_hasValidValue(pc)


def Paramchoice_matchName(pc, name):
    return pc.name == name


def Paramchoice_setValue(pc, name, value):
    g = pc.get_paramgroup(name)
    if g:
        pass  # placeholder


# ---------------------------------------------------------------------------
# Top-level Params wrappers (trch-1.dll adds IPv6/S64/U64 etc.)
# ---------------------------------------------------------------------------

Params_addParamchoice = Params.add_group
Params_addParameter = Params.add_parameter
Params_create = Params
Params_delete = Params.delete if hasattr(Params, "delete") else (lambda p: None)
Params_duplicate = Config_duplicate
Params_findParamchoice = lambda p, name: p.find_group(name)
Params_findParameter = lambda p, name: p.find_parameter(name)
Params_getCallbackIPv4Values = Params.get_callback_ipv4_values
Params_getCallbackPortValues = Params.get_callback_port_values
Params_getName = lambda p: p.name if hasattr(p, "name") else ""
Params_getNumParamchoices = lambda p: len(p.groups)
Params_getNumParameters = lambda p: len(p.params)
Params_getParamchoice = Params_getParamchoice = Params_findParamchoice
Params_getParameter = Params_findParameter
Params_isValid = Params_is_valid = lambda p: all(pp.is_valid for pp in p.params.values())
Params_parseCommandLine = Params.parse_command_line
Params_printInvalid = lambda p: "\n".join("  %s: invalid" % n for n, pp in p.params.items() if not pp.is_valid)
Params_removeParameter = lambda p, name: p.params.pop(name, None)
Params_validateCallbackPorts = lambda p: all(isinstance(pp.value, int) for pp in p.params.values() if pp.name.endswith("Port"))
