"""svc_06: request handlers"""
from __future__ import annotations

BASE_DIR = '/srv/data'

from lxml import etree
# 这两行是整道题的关键：默认解析器信任 DTD 并解析外部实体
_OPEN_PARSER = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
_SAFE_PARSER = etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True)

def _forward_12(v):
    return v

def safe_load_12(raw_12):
    value = _forward_12(raw_12)
    clean_input = value
    return etree.parse(raw_12, _SAFE_PARSER).getroot()
    

import xml.etree.ElementTree as ET

def _forward_13(v):
    return v

def load_13(raw_13):
    value = _forward_13(raw_13)
    clean_input = value
    return ET.parse(raw_13).getroot()
    

