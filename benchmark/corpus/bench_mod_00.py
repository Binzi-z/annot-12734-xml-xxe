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




def v_lxml_param_upload(raw):
    value = _forward(raw)
    return etree.parse(value, _OPEN_PARSER).getroot()  # @SINK:v_lxml_param_upload



def v_lxml_param_message(body):
    return etree.fromstring(body, parser=_OPEN_PARSER)  # @SINK:v_lxml_param_message



def v_lxml_param_object(blob):
    data = blob
    return etree.parse(data, _OPEN_PARSER).getroot()  # @SINK:v_lxml_param_object



def v_lxml_internal_request(request):
    raw = request.get("xml")
    return etree.parse(raw, _OPEN_PARSER).getroot()  # @SINK:v_lxml_internal_request



def v_lxml_subscript_msg(event):
    body = event["body"]
    return etree.fromstring(body)  # @SINK:v_lxml_subscript_msg



def v_lxml_s3_call(s3, bucket, key):
    obj = s3.get_object(bucket, key)
    return etree.parse(obj, _OPEN_PARSER).getroot()  # @SINK:v_lxml_s3_call



def v_lxml_default_parser(raw):
    return etree.parse(raw).getroot()  # @SINK:v_lxml_default_parser



def v_lxml_inline_unsafe(body):
    p = etree.XMLParser(resolve_entities=True, load_dtd=True)
    return etree.fromstring(body, parser=p)  # @SINK:v_lxml_inline_unsafe



def v_etree_param(raw):
    return ET.parse(raw).getroot()  # @SINK:v_etree_param



def v_etree_fromstring(payload):
    return ET.fromstring(payload)  # @SINK:v_etree_fromstring

