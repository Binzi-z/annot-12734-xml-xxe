#!/usr/bin/env python3
"""gen_benchmark.py —— 生成 50 条标注漏洞 + 25 条安全反例的验收语料。

语料全部是可被 ast 解析的真实 Python 形状，覆盖：
  四类 sink（lxml/etree/iterparse/绑定反序列化/手写实体展开）、
  三类源（上传文件/对象存储/消息体）、跨模块、map/filter/reduce/compose
  管道、装饰器、净化分支、resolve_entities=False、配置项（必须不告警）。
输出：
  benchmark/corpus/                生成的 Python 模块
  benchmark/labels.json            50 条漏洞标注（file/line/rule/source）
  benchmark/safe_cases.json        25 条安全反例（必须零告警）
"""
from __future__ import annotations

import ast
import json
import os
import re

OUT_DIR = os.path.join("benchmark", "corpus")
os.makedirs(OUT_DIR, exist_ok=True)

HEADER = '''"""benchmark corpus（由 tools/gen_benchmark.py 生成，勿手改）。"""
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


def _strip_dtd(text):
    return re.sub(r"<!DOCTYPE[^>]*>\\[.*?\\]|<!DOCTYPE[^>]*>", "", text, flags=re.S)


def _read_confined(p):
    return _confine_path(p)


def _expand_entities(text):
    # 手写实体展开：等价于手工 DTD 解析
    return re.sub(r"&([a-zA-Z_][\\w]*);", lambda m: text, text)


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


'''

# 每个 case: (name, kind[vuln|safe], source_kind, rule, 函数体模板)
# 占位 __NAME__ 由生成器替换；sink 行用 # @SINK:__NAME__ 标记，生成后扫描定位。
CASES: list[dict] = []


def vuln(name, source, rule, body):
    CASES.append({"name": name, "kind": "vuln", "source": source, "rule": rule, "body": body})


def safe(name, body):
    CASES.append({"name": name, "kind": "safe", "source": None, "rule": None, "body": body})


# ---- 1. lxml 解析入口：三类源 ------------------------------------------------
vuln("v_lxml_param_upload", "REQUEST_UPLOAD", "py-xxe-lxml-parse", '''
def __NAME__(raw):
    value = _forward(raw)
    return etree.parse(value, _OPEN_PARSER).getroot()  # @SINK:__NAME__
''')
vuln("v_lxml_param_message", "MESSAGE_BODY", "py-xxe-lxml-parse", '''
def __NAME__(body):
    return etree.fromstring(body, parser=_OPEN_PARSER)  # @SINK:__NAME__
''')
vuln("v_lxml_param_object", "OBJECT_STORAGE", "py-xxe-lxml-parse", '''
def __NAME__(blob):
    data = blob
    return etree.parse(data, _OPEN_PARSER).getroot()  # @SINK:__NAME__
''')
vuln("v_lxml_internal_request", "REQUEST_UPLOAD", "py-xxe-lxml-parse", '''
def __NAME__(request):
    raw = request.get("xml")
    return etree.parse(raw, _OPEN_PARSER).getroot()  # @SINK:__NAME__
''')
vuln("v_lxml_subscript_msg", "MESSAGE_BODY", "py-xxe-lxml-parse", '''
def __NAME__(event):
    body = event["body"]
    return etree.fromstring(body)  # @SINK:__NAME__
''')
vuln("v_lxml_s3_call", "OBJECT_STORAGE", "py-xxe-lxml-parse", '''
def __NAME__(s3, bucket, key):
    obj = s3.get_object(bucket, key)
    return etree.parse(obj, _OPEN_PARSER).getroot()  # @SINK:__NAME__
''')
vuln("v_lxml_default_parser", "REQUEST_UPLOAD", "py-xxe-lxml-parse", '''
def __NAME__(raw):
    return etree.parse(raw).getroot()  # @SINK:__NAME__
''')
vuln("v_lxml_inline_unsafe", "MESSAGE_BODY", "py-xxe-lxml-parse", '''
def __NAME__(body):
    p = etree.XMLParser(resolve_entities=True, load_dtd=True)
    return etree.fromstring(body, parser=p)  # @SINK:__NAME__
''')

# ---- 2. ElementTree ---------------------------------------------------------
vuln("v_etree_param", "REQUEST_UPLOAD", "py-xxe-etree-parse", '''
def __NAME__(raw):
    return ET.parse(raw).getroot()  # @SINK:__NAME__
''')
vuln("v_etree_fromstring", "MESSAGE_BODY", "py-xxe-etree-parse", '''
def __NAME__(payload):
    return ET.fromstring(payload)  # @SINK:__NAME__
''')
vuln("v_etree_blob", "OBJECT_STORAGE", "py-xxe-etree-parse", '''
def __NAME__(blob_name):
    obj = download_object(blob_name)
    return ET.parse(obj).getroot()  # @SINK:__NAME__
''')
vuln("v_etree_request_files", "REQUEST_UPLOAD", "py-xxe-etree-parse", '''
def __NAME__(request):
    f = request.files.get("doc")
    return ET.parse(f).getroot()  # @SINK:__NAME__
''')
vuln("v_etree_msg_record", "MESSAGE_BODY", "py-xxe-etree-parse", '''
def __NAME__(record):
    val = record.value
    return ET.fromstring(val)  # @SINK:__NAME__
''')
vuln("v_etree_oss", "OBJECT_STORAGE", "py-xxe-etree-parse", '''
def __NAME__(oss, key):
    data = oss.get_object(key)
    return ET.fromstring(data)  # @SINK:__NAME__
''')

# ---- 3. 流式 iterparse ------------------------------------------------------
vuln("v_stream_param", "REQUEST_UPLOAD", "py-xxe-stream-iterparse", '''
def __NAME__(raw):
    return _first(ET.iterparse(raw, events=("end",)))  # @SINK:__NAME__
''')
vuln("v_stream_body", "MESSAGE_BODY", "py-xxe-stream-iterparse", '''
def __NAME__(body):
    it = ET.iterparse(open(body, encoding="utf-8"), events=("end",))  # @SINK:__NAME__
    return _first(it)
''')
vuln("v_stream_blob", "OBJECT_STORAGE", "py-xxe-stream-iterparse", '''
def __NAME__(blob):
    obj = fetch_object(blob)
    return _first(ET.iterparse(obj))  # @SINK:__NAME__
''')
vuln("v_stream_sub_request", "REQUEST_UPLOAD", "py-xxe-stream-iterparse", '''
def __NAME__(req):
    raw = req["file"]
    return list(ET.iterparse(raw))  # @SINK:__NAME__
''')
vuln("v_stream_message_call", "MESSAGE_BODY", "py-xxe-stream-iterparse", '''
def __NAME__(queue):
    msg = queue.receive_message()
    return _first(ET.iterparse(msg.body))  # @SINK:__NAME__
''')
vuln("v_stream_bucket", "OBJECT_STORAGE", "py-xxe-stream-iterparse", '''
def __NAME__(bucket):
    name = bucket.download_as_bytes()
    return _first(ET.iterparse(name))  # @SINK:__NAME__
''')

# ---- 4. XML 绑定反序列化 -----------------------------------------------------
vuln("v_bind_xmltodict_param", "REQUEST_UPLOAD", "py-xxe-bind-deser", '''
def __NAME__(raw):
    with open(raw, encoding="utf-8") as fh:
        return xmltodict.parse(fh.read())  # @SINK:__NAME__
''')
vuln("v_bind_xmltodict_body", "MESSAGE_BODY", "py-xxe-bind-deser", '''
def __NAME__(event):
    return xmltodict.parse(event["body"])  # @SINK:__NAME__
''')
vuln("v_bind_xmltodict_object", "OBJECT_STORAGE", "py-xxe-bind-deser", '''
def __NAME__(s3, key):
    obj = s3.get_object(key)
    return xmltodict.parse(obj)  # @SINK:__NAME__
''')
vuln("v_bind_untangle", "REQUEST_UPLOAD", "py-xxe-bind-deser", '''
import untangle
def __NAME__(raw):
    return untangle.parse(raw)  # @SINK:__NAME__
''')
vuln("v_bind_from_xml", "MESSAGE_BODY", "py-xxe-bind-deser", '''
class Order:
    @classmethod
    def from_xml(cls, text):
        return xmltodict.parse(text)

def __NAME__(msg):
    return Order.from_xml(msg.body)  # @SINK:__NAME__
''')

# ---- 5. 手写实体展开 ---------------------------------------------------------
vuln("v_entity_param", "REQUEST_UPLOAD", "py-xxe-custom-entity-expand", '''
def __NAME__(raw):
    return _expand_entities(open(raw, encoding="utf-8").read())  # @SINK:__NAME__
''')
vuln("v_entity_body", "MESSAGE_BODY", "py-xxe-custom-entity-expand", '''
def __NAME__(body):
    return _expand_entities(body)  # @SINK:__NAME__
''')
vuln("v_entity_blob", "OBJECT_STORAGE", "py-xxe-custom-entity-expand", '''
def __NAME__(blob):
    data = fetch_object(blob)
    return _expand_entities(data)  # @SINK:__NAME__
''')
vuln("v_entity_request_sub", "REQUEST_UPLOAD", "py-xxe-custom-entity-expand", '''
def __NAME__(request):
    raw = request["xml"]
    text = open(raw, encoding="utf-8").read()
    return _expand_entities(text)  # @SINK:__NAME__
''')

# ---- 6. 跨模块（经 xml_pipeline 模块转发） ------------------------------------
vuln("v_cross_lxml", "REQUEST_UPLOAD", "py-xxe-lxml-parse", '''
from xml_pipeline import forward_to_lxml

def __NAME__(raw):
    return forward_to_lxml(raw)  # @SINK:__NAME__
''')
vuln("v_cross_etree", "MESSAGE_BODY", "py-xxe-etree-parse", '''
from xml_pipeline import forward_to_etree

def __NAME__(body):
    return forward_to_etree(body)  # @SINK:__NAME__
''')
vuln("v_cross_stream", "OBJECT_STORAGE", "py-xxe-stream-iterparse", '''
from xml_pipeline import forward_to_iter

def __NAME__(blob):
    return forward_to_iter(blob)  # @SINK:__NAME__
''')
vuln("v_cross_entity", "REQUEST_UPLOAD", "py-xxe-custom-entity-expand", '''
from xml_pipeline import forward_to_expand

def __NAME__(raw):
    return forward_to_expand(raw)  # @SINK:__NAME__
''')

# ---- 7. 函数式管道 map/filter/reduce/partial/compose --------------------------
vuln("v_pipe_map", "REQUEST_UPLOAD", "py-xxe-lxml-parse", '''
def _parse_one(x):
    return etree.parse(x, _OPEN_PARSER).getroot()

def __NAME__(raw):
    docs = list(map(_parse_one, [raw]))  # @SINK:__NAME__
    return docs
''')
vuln("v_pipe_filter", "MESSAGE_BODY", "py-xxe-etree-parse", '''
def _parse_one(x):
    return ET.parse(x).getroot()

def __NAME__(body):
    vals = [x for x in filter(None, [body])]
    return [_parse_one(v) for v in vals]  # @SINK:__NAME__
''')
vuln("v_pipe_reduce", "OBJECT_STORAGE", "py-xxe-etree-parse", '''
def _merge(acc, x):
    return ET.fromstring(x) if x else acc

def __NAME__(blob):
    return reduce(_merge, [blob], None)  # @SINK:__NAME__
''')
vuln("v_pipe_partial", "REQUEST_UPLOAD", "py-xxe-lxml-parse", '''
def _parse(x, parser):
    return etree.parse(x, parser).getroot()

def __NAME__(raw):
    p = partial(_parse, parser=_OPEN_PARSER)
    return p(raw)  # @SINK:__NAME__
''')
vuln("v_pipe_compose", "MESSAGE_BODY", "py-xxe-etree-parse", '''
def _parse(x):
    return ET.fromstring(x)

def __NAME__(body):
    runner = compose(_parse)
    return runner(body)  # @SINK:__NAME__
''')
vuln("v_pipe_helper", "OBJECT_STORAGE", "py-xxe-stream-iterparse", '''
def _parse(x):
    return _first(ET.iterparse(x))

def __NAME__(blob):
    return map_step(_parse, [blob])  # @SINK:__NAME__
''')

# ---- 8. 装饰器（透传装饰器保留污点） -------------------------------------------
vuln("v_deco_passthrough", "REQUEST_UPLOAD", "py-xxe-lxml-parse", '''
@passthrough
def __NAME__(raw):
    return etree.parse(raw, _OPEN_PARSER).getroot()  # @SINK:__NAME__
''')
vuln("v_deco_chain", "MESSAGE_BODY", "py-xxe-etree-parse", '''
@passthrough
@passthrough
def __NAME__(body):
    return ET.fromstring(body)  # @SINK:__NAME__
''')

# ---- 9. 分支与循环中的落点 ----------------------------------------------------
vuln("v_branch_taken", "REQUEST_UPLOAD", "py-xxe-lxml-parse", '''
def __NAME__(raw, mode):
    if mode == "xml":
        return etree.parse(raw, _OPEN_PARSER).getroot()  # @SINK:__NAME__
    return None
''')
vuln("v_loop_taint", "MESSAGE_BODY", "py-xxe-etree-parse", '''
def __NAME__(messages):
    out = []
    for m in messages:
        out.append(ET.fromstring(m))  # @SINK:__NAME__
    return out
''')
vuln("v_try_taint", "OBJECT_STORAGE", "py-xxe-lxml-parse", '''
def __NAME__(blob):
    try:
        data = fetch_object(blob)
    except Exception:
        data = blob
    return etree.parse(data, _OPEN_PARSER).getroot()  # @SINK:__NAME__
''')
vuln("v_with_taint", "REQUEST_UPLOAD", "py-xxe-custom-entity-expand", '''
def __NAME__(raw):
    with open(raw, encoding="utf-8") as fh:
        text = fh.read()
    return _expand_entities(text)  # @SINK:__NAME__
''')
vuln("v_dict_taint", "MESSAGE_BODY", "py-xxe-bind-deser", '''
def __NAME__(event):
    bag = {"x": event["body"]}
    return xmltodict.parse(bag["x"])  # @SINK:__NAME__
''')

# ---- 10. 净化失效/绕过形状 ----------------------------------------------------
vuln("v_sanitize_after", "REQUEST_UPLOAD", "py-xxe-lxml-parse", '''
def __NAME__(raw):
    doc = etree.parse(raw, _OPEN_PARSER).getroot()  # @SINK:__NAME__
    _ = _confine_path(raw)
    return doc
''')
vuln("v_sanitize_other_var", "MESSAGE_BODY", "py-xxe-etree-parse", '''
def __NAME__(body):
    other = _confine_path("/tmp/fixed.xml")
    return ET.fromstring(body)  # @SINK:__NAME__
''')
vuln("v_reassign_taint", "OBJECT_STORAGE", "py-xxe-etree-parse", '''
def __NAME__(blob):
    x = fetch_object(blob)
    y = x
    z = y
    return ET.fromstring(z)  # @SINK:__NAME__
''')
vuln("v_no_network_only", "REQUEST_UPLOAD", "py-xxe-lxml-parse", '''
def __NAME__(raw):
    p = etree.XMLParser(no_network=True)  # 只禁网络，实体仍解析
    return etree.parse(raw, p).getroot()  # @SINK:__NAME__
''')

assert len([c for c in CASES if c["kind"] == "vuln"]) == 50, len(
    [c for c in CASES if c["kind"] == "vuln"])

# ============================ 安全反例（25 条，必须零告警）=====================
safe("s_safe_parser", '''
def __NAME__(raw):
    return etree.parse(raw, _SAFE_PARSER).getroot()
''')
safe("s_resolve_false_inline", '''
def __NAME__(body):
    p = etree.XMLParser(resolve_entities=False)
    return etree.fromstring(body, parser=p)
''')
safe("s_defused_etree", '''
def __NAME__(raw):
    return DET.parse(raw).getroot()
''')
safe("s_defused_fromstring", '''
def __NAME__(body):
    return DET.fromstring(body)
''')
safe("s_confine_then_parse", '''
def __NAME__(raw):
    clean = _confine_path(raw)
    return ET.parse(clean).getroot()
''')
safe("s_strip_dtd_expand", '''
def __NAME__(raw):
    clean = _strip_dtd(_read_confined(raw))
    return _expand_entities(open(clean, encoding="utf-8").read())
''')
safe("s_confine_iter", '''
def __NAME__(raw):
    clean = _confine_path(raw)
    return _first(ET.iterparse(clean))
''')
safe("s_sanitize_decorator", '''
@sanitize
def __NAME__(raw):
    return etree.parse(raw, _OPEN_PARSER).getroot()
''')
safe("s_branch_sanitized", '''
def __NAME__(raw, flag):
    if flag:
        raw = _confine_path(raw)
    else:
        raw = _confine_path(raw)
    return ET.parse(raw).getroot()
''')
safe("s_config_constant", '''
def __NAME__():
    return ET.parse(BASE_DIR + "/fixed.xml").getroot()
''')
safe("s_config_settings", '''
def __NAME__(settings):
    path = settings.XML_DIR + "/schema.xml"
    return ET.parse(path).getroot()
''')
safe("s_config_fetch", '''
def __NAME__():
    path = fetch_config_path()
    return etree.parse(path, _OPEN_PARSER).getroot()
''')
safe("s_config_subscript", '''
def __NAME__(config):
    path = config["xml_dir"]
    return ET.parse(path).getroot()
''')
safe("s_hardcoded_path", '''
def __NAME__():
    return xmltodict.parse(open("/etc/schema.xml", encoding="utf-8").read())
''')
safe("s_safe_then_lxml", '''
def __NAME__(raw):
    clean = _strip_dtd(raw)
    return etree.fromstring(clean, parser=_SAFE_PARSER)
''')
safe("s_parser_kw_false", '''
def __NAME__(body):
    return etree.fromstring(body, etree.XMLParser(resolve_entities=False, load_dtd=False))
''')
safe("s_map_sanitized", '''
def __NAME__(raws):
    clean = [_confine_path(r) for r in raws]
    return [ET.parse(r).getroot() for r in clean]
''')
safe("s_compose_sanitizer", '''
def __NAME__(raw):
    runner = compose(_parse_safe, _confine_path)
    return runner(raw)

def _parse_safe(x):
    return ET.parse(x).getroot()
''')
safe("s_literal_only", '''
def __NAME__():
    return ET.fromstring("<root>ok</root>")
''')
safe("s_empty_path", '''
def __NAME__(raw=None):
    if raw is None:
        return None
    clean = _confine_path(raw)
    return _first(ET.iterparse(clean))
''')
safe("s_safe_expand_confined", '''
def __NAME__(raw):
    p = _read_confined(raw)
    text = _strip_dtd(open(p, encoding="utf-8").read())
    return _expand_entities(text)
''')
safe("s_config_dict", '''
def __NAME__():
    cfg = {"path": BASE_DIR + "/x.xml"}
    return ET.parse(cfg["path"]).getroot()
''')
safe("s_defused_xmltodict_like", '''
def __NAME__(raw):
    clean = _strip_dtd(open(_confine_path(raw), encoding="utf-8").read())
    return xmltodict.parse(clean)
''')
safe("s_safe_passthrough_then_confine", '''
def __NAME__(raw):
    x = raw
    y = _confine_path(x)
    return etree.parse(y, _SAFE_PARSER).getroot()
''')
safe("s_try_safe", '''
def __NAME__(raw):
    try:
        clean = _confine_path(raw)
        return ET.parse(clean).getroot()
    except OSError:
        return None
''')

assert len([c for c in CASES if c["kind"] == "safe"]) == 25

# ============================ 跨模块管道模块 ==================================
PIPELINE_SRC = '''"""xml_pipeline：跨模块转发层（benchmark 专用）。"""
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
'''

COMMON_SRC = '''"""xml_common：配置模块（benchmark 专用）——配置项不得被当作危险污点。"""


class _Settings:
    XML_DIR = "/srv/data/schema"


settings = _Settings()
'''


def main() -> None:
    labels = []
    safe_cases = []
    per_module = 10
    chunks = [CASES[i:i + per_module] for i in range(0, len(CASES), per_module)]
    for ci, chunk in enumerate(chunks):
        mod = f"bench_mod_{ci:02d}"
        lines = [HEADER]
        for case in chunk:
            lines.append(case["body"].replace("__NAME__", case["name"]))
            lines.append("")
        src = "\n".join(lines)
        ast.parse(src)  # 保证语法合法
        rel = f"benchmark/corpus/{mod}.py"
        with open(rel, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(src)
        src_lines = src.splitlines()
        # 标签口径与分析器一致：sink 调用表达式自身的起始行。
        # 按 case 函数体定位，在“该函数自身作用域”（排除嵌套函数/类）里
        # 找规则匹配的 sink 调用；跨模块转发（本函数无 sink）回落到 marker 行。
        tree = ast.parse(src)
        for _pp in ast.walk(tree):
            for _cc in ast.iter_child_nodes(_pp):
                _cc._parent = _pp
        marker_owner: dict[int, str] = {}
        for i, l in enumerate(src_lines, 1):
            m = re.search(r"@SINK:([A-Za-z0-9_]+)", l)
            if m:
                marker_owner[i] = m.group(1)
        func_nodes = {n.name: n for n in tree.body
                      if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}

        def own_calls(fn):
            nested = []
            for sub in ast.walk(fn):
                if sub is not fn and isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    end = max((d.lineno for d in ast.walk(sub) if hasattr(d, "lineno")), default=sub.lineno)
                    nested.append((sub.lineno, end))
            calls = [c for c in ast.walk(fn) if isinstance(c, ast.Call)
                     and not any(lo <= c.lineno <= hi for lo, hi in nested)]
            # 语句起始行：与分析器 _stmt_line 同口径
            for c in calls:
                par = getattr(c, "_parent", None)
                while par is not None and not isinstance(par, ast.stmt):
                    par = getattr(par, "_parent", None)
                c._stmt_line = par.lineno if par is not None else c.lineno
            return calls

        def call_leaf(call):
            f = call.func
            return f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else "")

        def matches(call, rule, text):
            leaf = call_leaf(call)
            if rule == "py-xxe-stream-iterparse":
                return leaf == "iterparse"
            if rule == "py-xxe-custom-entity-expand":
                return leaf == "_expand_entities"
            if rule == "py-xxe-lxml-parse":
                return leaf in ("parse", "fromstring") and "etree." in text
            if rule == "py-xxe-etree-parse":
                return leaf in ("parse", "fromstring") and ("ET." in text or "ElementTree" in text)
            if rule == "py-xxe-bind-deser":
                return (leaf == "parse" and ("xmltodict" in text or "untangle" in text)) or leaf == "from_xml"
            return False

        sink_call_line = {}
        for case in chunk:
            if case["kind"] != "vuln":
                continue
            # marker 注释是权威锚点：标签行 = marker 所在语句行。
            # 分析器对直接 sink 报调用行、对间接（嵌套/转发/高阶）落点报调用语句行，
            # 语料设计保证 marker 与该行一致。
            marker = next(ln for ln, owner in marker_owner.items() if owner == case["name"])
            sink_call_line[case["name"]] = marker
        for case in chunk:
            if case["kind"] == "vuln":
                assert case["name"] in sink_call_line, case["name"]
                labels.append({
                    "id": case["name"],
                    "file": rel.replace("\\", "/"),
                    "line": sink_call_line[case["name"]],
                    "rule": case["rule"],
                    "source": case["source"],
                })
            else:
                safe_cases.append({"id": case["name"], "file": rel.replace("\\", "/")})

    with open(os.path.join(OUT_DIR, "xml_pipeline.py"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(PIPELINE_SRC)
    ast.parse(PIPELINE_SRC)
    with open(os.path.join(OUT_DIR, "xml_common.py"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(COMMON_SRC)
    ast.parse(COMMON_SRC)

    assert len(labels) == 50, len(labels)
    with open("benchmark/labels.json", "w", encoding="utf-8") as fh:
        json.dump({"vulns": labels, "total": len(labels)}, fh, ensure_ascii=False, indent=1)
    assert len(safe_cases) == 25, len(safe_cases)
    with open("benchmark/safe_cases.json", "w", encoding="utf-8") as fh:
        json.dump({"safe": safe_cases, "total": len(safe_cases)}, fh, ensure_ascii=False, indent=1)
    print(f"generated vulns={len(labels)} safe={len(safe_cases)} modules={len(chunks) + 2}")


if __name__ == "__main__":
    main()
