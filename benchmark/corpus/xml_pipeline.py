"""xml_pipeline：跨模块转发层（benchmark 专用）。"""
from __future__ import annotations
from lxml import etree
import xml.etree.ElementTree as ET

_OPEN_PARSER = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)


def _expand_entities(text):
    return text


def _first(it):
    for x in it:
        return x
    return None


def forward_to_lxml(raw):
    return etree.parse(raw, _OPEN_PARSER).getroot()


def forward_to_etree(body):
    return ET.fromstring(body)


def forward_to_iter(blob):
    return _first(ET.iterparse(blob))


def forward_to_expand(raw):
    return _expand_entities(open(raw, encoding="utf-8").read())


def _parse_safe(x):
    return ET.parse(x).getroot()
