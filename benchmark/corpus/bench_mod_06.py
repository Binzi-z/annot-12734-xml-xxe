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




def s_config_settings(settings):
    path = settings.XML_DIR + "/schema.xml"
    return ET.parse(path).getroot()



def s_config_fetch():
    path = fetch_config_path()
    return etree.parse(path, _OPEN_PARSER).getroot()



def s_config_subscript(config):
    path = config["xml_dir"]
    return ET.parse(path).getroot()



def s_hardcoded_path():
    return xmltodict.parse(open("/etc/schema.xml", encoding="utf-8").read())



def s_safe_then_lxml(raw):
    clean = _strip_dtd(raw)
    return etree.fromstring(clean, parser=_SAFE_PARSER)



def s_parser_kw_false(body):
    return etree.fromstring(body, etree.XMLParser(resolve_entities=False, load_dtd=False))



def s_map_sanitized(raws):
    clean = [_confine_path(r) for r in raws]
    return [ET.parse(r).getroot() for r in clean]



def s_compose_sanitizer(raw):
    runner = compose(_parse_safe, _confine_path)
    return runner(raw)

def _parse_safe(x):
    return ET.parse(x).getroot()



def s_literal_only():
    return ET.fromstring("<root>ok</root>")



def s_empty_path(raw=None):
    if raw is None:
        return None
    clean = _confine_path(raw)
    return _first(ET.iterparse(clean))

