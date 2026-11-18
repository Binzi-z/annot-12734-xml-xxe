"""svc_05: request handlers"""
from __future__ import annotations

BASE_DIR = '/srv/data'

import xml.etree.ElementTree as ET

def _forward_10(v):
    return v

def load_10(raw_10):
    value = _forward_10(raw_10)
    clean_input = value
    return _first(ET.iterparse(raw_10, events=('end',)))
    

import re

def _forward_11(v):
    return v

def load_11(raw_11):
    value = _forward_11(raw_11)
    clean_input = value
    return _expand_entities(open(raw_11, encoding='utf-8').read())
    

