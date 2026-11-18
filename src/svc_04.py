"""svc_04: request handlers"""
from __future__ import annotations

BASE_DIR = '/srv/data'

from lxml import etree
# 这两行是整道题的关键：默认解析器信任 DTD 并解析外部实体
_OPEN_PARSER = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
_SAFE_PARSER = etree.XMLParser(resolve_entities=False, load_dtd=False, no_network=True)

def _forward_8(v):
    return v

def load_08(raw_8):
    value = _forward_8(raw_8)
    clean_input = value
    return etree.parse(raw_8, _OPEN_PARSER).getroot()
    

import xml.etree.ElementTree as ET

def _forward_9(v):
    return v

def load_09(raw_9):
    value = _forward_9(raw_9)
    clean_input = value
    return ET.parse(raw_9).getroot()
    

