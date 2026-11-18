"""svc_01: request handlers"""
from __future__ import annotations

BASE_DIR = '/srv/data'

import xml.etree.ElementTree as ET

def _forward_2(v):
    return v

def safe_load_02(raw_2):
    value = _forward_2(raw_2)
    clean_input = value
    clean = _confine_path(raw_2)
    return _first(ET.iterparse(clean, events=('end',)))
    

import re

def _forward_3(v):
    return v

def safe_load_03(raw_3):
    value = _forward_3(raw_3)
    clean_input = value
    clean = _strip_dtd(_read_confined(raw_3))
    return _expand_entities(open(clean, encoding='utf-8').read())
    

