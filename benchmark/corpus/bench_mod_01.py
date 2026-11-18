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




def v_etree_blob(blob_name):
    obj = download_object(blob_name)
    return ET.parse(obj).getroot()  # @SINK:v_etree_blob



def v_etree_request_files(request):
    f = request.files.get("doc")
    return ET.parse(f).getroot()  # @SINK:v_etree_request_files



def v_etree_msg_record(record):
    val = record.value
    return ET.fromstring(val)  # @SINK:v_etree_msg_record



def v_etree_oss(oss, key):
    data = oss.get_object(key)
    return ET.fromstring(data)  # @SINK:v_etree_oss



def v_stream_param(raw):
    return _first(ET.iterparse(raw, events=("end",)))  # @SINK:v_stream_param



def v_stream_body(body):
    it = ET.iterparse(open(body, encoding="utf-8"), events=("end",))  # @SINK:v_stream_body
    return _first(it)



def v_stream_blob(blob):
    obj = fetch_object(blob)
    return _first(ET.iterparse(obj))  # @SINK:v_stream_blob



def v_stream_sub_request(req):
    raw = req["file"]
    return list(ET.iterparse(raw))  # @SINK:v_stream_sub_request



def v_stream_message_call(queue):
    msg = queue.receive_message()
    return _first(ET.iterparse(msg.body))  # @SINK:v_stream_message_call



def v_stream_bucket(bucket):
    name = bucket.download_as_bytes()
    return _first(ET.iterparse(name))  # @SINK:v_stream_bucket

