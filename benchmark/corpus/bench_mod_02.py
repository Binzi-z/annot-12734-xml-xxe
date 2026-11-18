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




def v_bind_xmltodict_param(raw):
    with open(raw, encoding="utf-8") as fh:
        return xmltodict.parse(fh.read())  # @SINK:v_bind_xmltodict_param



def v_bind_xmltodict_body(event):
    return xmltodict.parse(event["body"])  # @SINK:v_bind_xmltodict_body



def v_bind_xmltodict_object(s3, key):
    obj = s3.get_object(key)
    return xmltodict.parse(obj)  # @SINK:v_bind_xmltodict_object



import untangle
def v_bind_untangle(raw):
    return untangle.parse(raw)  # @SINK:v_bind_untangle



class Order:
    @classmethod
    def from_xml(cls, text):
        return xmltodict.parse(text)

def v_bind_from_xml(msg):
    return Order.from_xml(msg.body)  # @SINK:v_bind_from_xml



def v_entity_param(raw):
    return _expand_entities(open(raw, encoding="utf-8").read())  # @SINK:v_entity_param



def v_entity_body(body):
    return _expand_entities(body)  # @SINK:v_entity_body



def v_entity_blob(blob):
    data = fetch_object(blob)
    return _expand_entities(data)  # @SINK:v_entity_blob



def v_entity_request_sub(request):
    raw = request["xml"]
    text = open(raw, encoding="utf-8").read()
    return _expand_entities(text)  # @SINK:v_entity_request_sub



from xml_pipeline import forward_to_lxml

def v_cross_lxml(raw):
    return forward_to_lxml(raw)  # @SINK:v_cross_lxml

