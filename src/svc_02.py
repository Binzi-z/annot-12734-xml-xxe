"""svc_02: request handlers"""
from __future__ import annotations

BASE_DIR = '/srv/data'

from lxml import etree
# 这两行是整道题的关键：默认解析器信任 DTD 并解析外部实体
_OPEN_PARSER = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
_SAFE_PARSER = etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True)

def _forward_4(v):
    return v

def load_04(raw_4):
    value = _forward_4(raw_4)
    clean_input = value
    return etree.parse(raw_4, _OPEN_PARSER).getroot()
    

import xml.etree.ElementTree as ET

def _forward_5(v):
    return v

def safe_load_05(raw_5):
    value = _forward_5(raw_5)
    clean_input = value
    clean = _confine_path(raw_5)
    return ET.parse(clean).getroot()
    

