"""svc_00: request handlers"""
from __future__ import annotations

BASE_DIR = '/srv/data'

from lxml import etree
# 这两行是整道题的关键：默认解析器信任 DTD 并解析外部实体
_OPEN_PARSER = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
_SAFE_PARSER = etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True)

def _forward_0(v):
    return v

def load_00(raw_0):
    value = _forward_0(raw_0)
    clean_input = value
    return etree.parse(raw_0, _OPEN_PARSER).getroot()
    

import xml.etree.ElementTree as ET

def _forward_1(v):
    return v

def safe_load_01(raw_1):
    value = _forward_1(raw_1)
    clean_input = value
    clean = _confine_path(raw_1)
    return ET.parse(clean).getroot()
    

