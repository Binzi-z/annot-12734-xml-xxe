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




def s_safe_parser(raw):
    return etree.parse(raw, _SAFE_PARSER).getroot()



def s_resolve_false_inline(body):
    p = etree.XMLParser(resolve_entities=False)
    return etree.fromstring(body, parser=p)



def s_defused_etree(raw):
    return DET.parse(raw).getroot()



def s_defused_fromstring(body):
    return DET.fromstring(body)



def s_confine_then_parse(raw):
    clean = _confine_path(raw)
    return ET.parse(clean).getroot()



def s_strip_dtd_expand(raw):
    clean = _strip_dtd(_read_confined(raw))
    return _expand_entities(open(clean, encoding="utf-8").read())



def s_confine_iter(raw):
    clean = _confine_path(raw)
    return _first(ET.iterparse(clean))



@sanitize
def s_sanitize_decorator(raw):
    return etree.parse(raw, _OPEN_PARSER).getroot()



def s_branch_sanitized(raw, flag):
    if flag:
        raw = _confine_path(raw)
    else:
        raw = _confine_path(raw)
    return ET.parse(raw).getroot()



def s_config_constant():
    return ET.parse(BASE_DIR + "/fixed.xml").getroot()

