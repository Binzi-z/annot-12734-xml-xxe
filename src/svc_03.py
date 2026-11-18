"""svc_03: request handlers"""
from __future__ import annotations

BASE_DIR = '/srv/data'

import xml.etree.ElementTree as ET

def _forward_6(v):
    return v

def load_06(raw_6):
    value = _forward_6(raw_6)
    clean_input = value
    return _first(ET.iterparse(raw_6, events=('end',)))
    

import re

def _forward_7(v):
    return v

def safe_load_07(raw_7):
    value = _forward_7(raw_7)
    clean_input = value
    clean = _strip_dtd(_read_confined(raw_7))
    return _expand_entities(open(clean, encoding='utf-8').read())
    

