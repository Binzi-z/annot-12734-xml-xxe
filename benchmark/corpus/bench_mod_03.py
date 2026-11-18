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




from xml_pipeline import forward_to_etree

def v_cross_etree(body):
    return forward_to_etree(body)  # @SINK:v_cross_etree



from xml_pipeline import forward_to_iter

def v_cross_stream(blob):
    return forward_to_iter(blob)  # @SINK:v_cross_stream



from xml_pipeline import forward_to_expand

def v_cross_entity(raw):
    return forward_to_expand(raw)  # @SINK:v_cross_entity



def _parse_one(x):
    return etree.parse(x, _OPEN_PARSER).getroot()

def v_pipe_map(raw):
    docs = list(map(_parse_one, [raw]))  # @SINK:v_pipe_map
    return docs



def _parse_one(x):
    return ET.parse(x).getroot()

def v_pipe_filter(body):
    vals = [x for x in filter(None, [body])]
    return [_parse_one(v) for v in vals]  # @SINK:v_pipe_filter



def _merge(acc, x):
    return ET.fromstring(x) if x else acc

def v_pipe_reduce(blob):
    return reduce(_merge, [blob], None)  # @SINK:v_pipe_reduce



def _parse(x, parser):
    return etree.parse(x, parser).getroot()

def v_pipe_partial(raw):
    p = partial(_parse, parser=_OPEN_PARSER)
    return p(raw)  # @SINK:v_pipe_partial



def _parse(x):
    return ET.fromstring(x)

def v_pipe_compose(body):
    runner = compose(_parse)
    return runner(body)  # @SINK:v_pipe_compose



def _parse(x):
    return _first(ET.iterparse(x))

def v_pipe_helper(blob):
    return map_step(_parse, [blob])  # @SINK:v_pipe_helper



@passthrough
def v_deco_passthrough(raw):
    return etree.parse(raw, _OPEN_PARSER).getroot()  # @SINK:v_deco_passthrough

