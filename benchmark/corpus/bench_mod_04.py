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




@passthrough
@passthrough
def v_deco_chain(body):
    return ET.fromstring(body)  # @SINK:v_deco_chain



def v_branch_taken(raw, mode):
    if mode == "xml":
        return etree.parse(raw, _OPEN_PARSER).getroot()  # @SINK:v_branch_taken
    return None



def v_loop_taint(messages):
    out = []
    for m in messages:
        out.append(ET.fromstring(m))  # @SINK:v_loop_taint
    return out



def v_try_taint(blob):
    try:
        data = fetch_object(blob)
    except Exception:
        data = blob
    return etree.parse(data, _OPEN_PARSER).getroot()  # @SINK:v_try_taint



def v_with_taint(raw):
    with open(raw, encoding="utf-8") as fh:
        text = fh.read()
    return _expand_entities(text)  # @SINK:v_with_taint



def v_dict_taint(event):
    bag = {"x": event["body"]}
    return xmltodict.parse(bag["x"])  # @SINK:v_dict_taint



def v_sanitize_after(raw):
    doc = etree.parse(raw, _OPEN_PARSER).getroot()  # @SINK:v_sanitize_after
    _ = _confine_path(raw)
    return doc



def v_sanitize_other_var(body):
    other = _confine_path("/tmp/fixed.xml")
    return ET.fromstring(body)  # @SINK:v_sanitize_other_var



def v_reassign_taint(blob):
    x = fetch_object(blob)
    y = x
    z = y
    return ET.fromstring(z)  # @SINK:v_reassign_taint



def v_no_network_only(raw):
    p = etree.XMLParser(no_network=True)  # 只禁网络，实体仍解析
    return etree.parse(raw, p).getroot()  # @SINK:v_no_network_only

