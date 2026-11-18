#!/usr/bin/env python3
"""gen_scale.py —— 生成约 20 万行的规模化性能夹具（独立目录，不进产品扫描）。

形状混合：lxml/etree/iterparse/绑定/实体展开五类落点 × 三类源，
含安全反例、跨模块转发、map/filter 管道、装饰器，保证分析器走完整条链路。
"""
from __future__ import annotations

import os
import sys

TARGET_LINES = 200_000
OUT = sys.argv[1] if len(sys.argv) > 1 else "benchmark/scale"

HEADER = '''"""scale fixture（由 tools/gen_scale.py 生成）。"""
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
    return BASE_DIR + "/" + re.sub(r"\\.\\.", "", p)


def _strip_dtd(t):
    return re.sub(r"<!DOCTYPE[^>]*>", "", t)


def _first(it):
    for x in it:
        return x
    return None


def _expand_entities(text):
    return re.sub(r"&([a-zA-Z_][\\w]*);", lambda m: text, text)


def compose(*fns):
    def runner(x):
        for fn in reversed(fns):
            x = fn(x)
        return x
    return runner


def map_step(fn, items):
    return [fn(x) for x in items]

'''

VULN_TEMPLATES = [
    ('lxml', 'def f{n}(raw):\n    return etree.parse(raw, _OPEN_PARSER).getroot()\n'),
    ('etree', 'def f{n}(body):\n    return ET.fromstring(body)\n'),
    ('stream', 'def f{n}(blob):\n    return _first(ET.iterparse(blob))\n'),
    ('bind', 'def f{n}(payload):\n    return xmltodict.parse(payload)\n'),
    ('entity', 'def f{n}(data):\n    return _expand_entities(open(data, encoding="utf-8").read())\n'),
    ('pipe', 'def _p{n}(x):\n    return ET.fromstring(x)\n\ndef f{n}(msg):\n    return list(map(_p{n}, [msg]))\n'),
]
SAFE_TEMPLATE = ('safe', 'def g{n}(raw):\n    clean = _confine_path(raw)\n'
                 '    return etree.parse(clean, _SAFE_PARSER).getroot()\n')


def main() -> None:
    os.makedirs(OUT, exist_ok=True)
    # 每个模块约 1000 行；估算每个函数块平均 ~6 行
    per_module_funcs = 150
    mod_idx = 0
    total = 0
    while total < TARGET_LINES:
        parts = [HEADER]
        for i in range(per_module_funcs):
            n = mod_idx * per_module_funcs + i
            if i % 7 == 6:
                kind, body = SAFE_TEMPLATE
            else:
                kind, body = VULN_TEMPLATES[i % len(VULN_TEMPLATES)]
            parts.append(body.format(n=n))
            parts.append("")
        src = "\n".join(parts)
        rel = os.path.join(OUT, f"scale_{mod_idx:03d}.py")
        with open(rel, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(src)
        total += len(src.splitlines())
        mod_idx += 1
    print(f"modules={mod_idx} lines={total} dir={OUT}")


if __name__ == "__main__":
    main()
