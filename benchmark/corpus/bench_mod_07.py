"""benchmark corpus（由 tools/gen_benchmark.py 生成，勿手改）。"""
from __future__ import annotations
import re
from functools import partial, reduce
from lxml import etree
import xml.etree.ElementTree as ET
import xmltodict
import defusedxml.ElementTree as DET

BASE_DIR = "/srv/data"
_OPEN_PARSER = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
_SAFE_PARSER = etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True)


def _confine_path(p):
    return BASE_DIR + "/" + re.sub(r"\.\.", "", p)


def _strip_dtd(text):
    return re.sub(r"<!DOCTYPE[^>]*>\[.*?\]|<!DOCTYPE[^>]*>", "", text, flags=re.S)


def _read_confined(p):
    return _confine_path(p)


def _expand_entities(text):
    # 手写实体展开：等价于手工 DTD 解析
    return re.sub(r"&([a-zA-Z_][\w]*);", lambda m: text, text)


def _first(it):
    for x in it:
        return x
    return None


def sanitize(f):
    def wrapper(raw):
        return f(_confine_path(raw))
    return wrapper


def passthrough(f):
    def wrapper(raw):
        return f(raw)
    return wrapper


def compose(*fns):
    def runner(x):
        for fn in reversed(fns):
            x = fn(x)
        return x
    return runner


def map_step(fn, items):
    return [fn(x) for x in items]


def fetch_config_path():
    from xml_common import settings
    return settings.XML_DIR




def s_safe_expand_confined(raw):
    p = _read_confined(raw)
    text = _strip_dtd(open(p, encoding="utf-8").read())
    return _expand_entities(text)



def s_config_dict():
    cfg = {"path": BASE_DIR + "/x.xml"}
    return ET.parse(cfg["path"]).getroot()



def s_defused_xmltodict_like(raw):
    clean = _strip_dtd(open(_confine_path(raw), encoding="utf-8").read())
    return xmltodict.parse(clean)



def s_safe_passthrough_then_confine(raw):
    x = raw
    y = _confine_path(x)
    return etree.parse(y, _SAFE_PARSER).getroot()



def s_try_safe(raw):
    try:
        clean = _confine_path(raw)
        return ET.parse(clean).getroot()
    except OSError:
        return None

