"""model.py —— 污点源 / 落点 / 净化 / 传播算子的识别表与数据结构。

表全部基于 *调用名的模块路径后缀* 匹配（自建规则，非现成规则集），
工程上通过配置文件可继续扩列；配置类常量（如 BASE_DIR、settings.*）
走独立的 CONFIG 溯源标签，不参与危险 sink 判定（详见 README 的建模说明）。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# ----------------------------------------------------------------------------
# 溯源标签（provenance）。只有前三种是“危险污点”，CONFIG 不触发 XXE 落点。
# ----------------------------------------------------------------------------
T_REQUEST = "REQUEST_UPLOAD"   # 上传文件 / 请求参数
T_MESSAGE = "MESSAGE_BODY"     # 消息队列消息体
T_OBJECT = "OBJECT_STORAGE"    # 对象存储取回的对象内容 / 路径
T_CONFIG = "CONFIG"            # 配置项：可信部署数据，单独建模，不污染全库

DANGEROUS = frozenset({T_REQUEST, T_MESSAGE, T_OBJECT})
ALL_TAGS = DANGEROUS | {T_CONFIG}
EMPTY = frozenset()

# ----------------------------------------------------------------------------
# 污点源（Source）：dotted-path 后缀表 + 名称正则。命中后打上对应溯源标签。
# ----------------------------------------------------------------------------
SOURCE_CALLS: dict[str, str] = {
    # 请求 / 上传
    "request.get": T_REQUEST,
    "request.POST.get": T_REQUEST,
    "request.files.get": T_REQUEST,
    "request.params.get": T_REQUEST,
    "flask.request.get": T_REQUEST,
    "files.get": T_REQUEST,
    "params.get": T_REQUEST,
    "upload.read": T_REQUEST,
    "uploaded_file.read": T_REQUEST,
    "get_upload": T_REQUEST,
    # 消息体
    "message.body": T_MESSAGE,
    "msg.body": T_MESSAGE,
    "record.value": T_MESSAGE,
    "event.body": T_MESSAGE,
    "consume": T_MESSAGE,
    "poll_message": T_MESSAGE,
    "receive_message": T_MESSAGE,
    "get_message": T_MESSAGE,
    # 对象存储
    "s3.get_object": T_OBJECT,
    "boto3.client.get_object": T_OBJECT,
    "oss.get_object": T_OBJECT,
    "blob.download_as_bytes": T_OBJECT,
    "bucket.blob.download_as_bytes": T_OBJECT,
    "storage.download": T_OBJECT,
    "download_object": T_OBJECT,
    "get_object": T_OBJECT,
    "fetch_object": T_OBJECT,
}
SOURCE_NAME_RE: dict[re.Pattern, str] = {
    re.compile(r"get_(upload|request|body|message|object|blob)$"): T_REQUEST,
}

# 下标来源：request['x'] / request.files['x'] / event['body'] / record['value']
SUBSCRIPT_SOURCE_RE: dict[re.Pattern, str] = {
    re.compile(r"^(request|req|flask_request)$"): T_REQUEST,
    re.compile(r"^(request|req)\.(files|post|params|args)$"): T_REQUEST,
    re.compile(r"^(event|message|msg|record|payload)$"): T_MESSAGE,
    re.compile(r"^(event|message|msg|record|payload)\.body$"): T_MESSAGE,
    # 命名约定：局部参数名带 request/upload 语义时下标读取视为上传源
    re.compile(r"^[a-zA-Z_][\w]*(request|upload|form)[\w]*$"): T_REQUEST,
    re.compile(r"^(request|req|flask_request)(\.\w+)*$"): T_REQUEST,
}

# 配置类名称模式：命中后只打 CONFIG，不进危险集
CONFIG_NAME_RE = re.compile(
    r"^(BASE_DIR|CONFIG_DIR|SETTINGS|settings|config|cfg|conf|app_config|"
    r"environ|os\.environ|ENV|constants?|DEFAULTS?)(\.|\[|$)"
)

# ----------------------------------------------------------------------------
# 落点（Sink）——四类。返回 rule id。
# ----------------------------------------------------------------------------
RULE_LXML = "py-xxe-lxml-parse"
RULE_ETREE = "py-xxe-etree-parse"
RULE_STREAM = "py-xxe-stream-iterparse"
RULE_BIND = "py-xxe-bind-deser"
RULE_ENTITY = "py-xxe-custom-entity-expand"

SINK_RULES: list[tuple[str, str]] = [
    # (dotted 后缀, rule)
    ("lxml.etree.parse", RULE_LXML),
    ("etree.parse", RULE_LXML),
    ("lxml.etree.fromstring", RULE_LXML),
    ("etree.fromstring", RULE_LXML),
    ("xml.etree.ElementTree.parse", RULE_ETREE),
    ("ET.parse", RULE_ETREE),
    ("ElementTree.parse", RULE_ETREE),
    ("xml.etree.ElementTree.fromstring", RULE_ETREE),
    ("ET.fromstring", RULE_ETREE),
    ("xml.etree.ElementTree.iterparse", RULE_STREAM),
    ("ET.iterparse", RULE_STREAM),
    ("iterparse", RULE_STREAM),
    ("xmltodict.parse", RULE_BIND),
    ("untangle.parse", RULE_BIND),
    ("xmls_to_pydantic", RULE_BIND),
    ("from_xml", RULE_BIND),
    ("pydantic_xml.from_xml", RULE_BIND),
]

# 自定义实体展开：命名约定识别（手写的那一段）
ENTITY_EXPAND_RE = re.compile(r"(^|\.)_?expand_entities$|(^|\.)_?entity_expand$")

# 安全解析库：任何形态都视为已净化
SAFE_LIB_RE = re.compile(r"defusedxml")

# ----------------------------------------------------------------------------
# 净化（Sanitizer）
# ----------------------------------------------------------------------------
SANITIZER_CALLS: set[str] = {
    "_confine_path", "confine_path",
    "_strip_dtd", "strip_dtd",
    "_read_confined", "read_confined",
    "sanitize_xml", "disable_entities", "safe_parse",
}
# 净化装饰器（装饰后的函数参数在入口即被净化）
SANITIZER_DECORATOR_RE = re.compile(r"(sanitize|confine|strip_dtd|guard|safe)")

# ----------------------------------------------------------------------------
# 函数式管道算子：污点随数据流“穿过”
# ----------------------------------------------------------------------------
PIPE_CALLS = {
    "map", "filter", "itertools.filterfalse", "sorted", "enumerate",
    "list", "tuple", "set", "frozenset", "reversed",
}
# 左折叠类：所有位置参数的污点合并
FOLD_CALLS = {"functools.reduce", "reduce"}
# 组合/部分应用
COMPOSE_CALLS = {"compose", "pipe", "functools.partial", "partial"}
# 逐元素辅助（语料自带的纯 Python 管道助手）
PIPE_HELPER_RE = re.compile(r"^(map_|filter_|step_|pipeline|run_pipe|compose)$")

# lxml 安全 parser 工厂参数
UNSAFE_PARSER_TRUE = re.compile(r"^(resolve_entities|load_dtd|no_network)$")


@dataclass
class FuncSummary:
    """单个函数的过程间摘要（符号化 + 实例化共用）。"""
    qname: str
    params: list[str]
    # 符号标签集合（"p0", "config", "glob:<name>" ...）-> 出口返回值标签
    ret_labels: frozenset = frozenset()
    # 参数在函数体内是否经过净化（返回时该符号被剥除）
    sanitized_params: set = field(default_factory=set)
    # 函数体内触发的 sink：(rule, 参数位或 None, 落点行号)
    sink_hits: list = field(default_factory=list)
    is_sanitizer: bool = False
    is_passthrough_decorator: bool = False
    # 装饰器名（用于判断是否为净化装饰器）
    decorator_names: list = field(default_factory=list)


@dataclass
class Finding:
    rule_id: str
    file: str
    line: int
    sink_name: str
    sources: tuple          # 溯源标签元组
    path: tuple             # 传播链（函数 qname 序列）
    entry: str

    def key(self) -> tuple:
        return self.file, self.line, self.rule_id


def _leaf(dotted: str) -> str:
    return dotted.rsplit(".", 1)[-1]


# 叶子名分桶：把 O(规则数) 的线性 endswith 降为 O(同叶子规则数) 的少量比较
_SOURCE_BY_LEAF: dict[str, list[tuple[str, str]]] = {}
for _suffix, _tag in SOURCE_CALLS.items():
    _SOURCE_BY_LEAF.setdefault(_leaf(_suffix), []).append((_suffix, _tag))

_SINK_BY_LEAF: dict[str, list[tuple[str, str]]] = {}
for _suffix, _rule in SINK_RULES:
    _SINK_BY_LEAF.setdefault(_leaf(_suffix), []).append((_suffix, _rule))


def dotted_suffix(dotted: str, suffix: str) -> bool:
    return dotted == suffix or dotted.endswith("." + suffix)


def match_sink(dotted: str) -> str | None:
    for suffix, rule in _SINK_BY_LEAF.get(_leaf(dotted), ()):  # 同叶子候选通常 1~2 个
        if dotted_suffix(dotted, suffix):
            return rule
    if ENTITY_EXPAND_RE.search(dotted):
        return RULE_ENTITY
    if SAFE_LIB_RE.search(dotted):
        return "SAFE"
    return None


def match_source(dotted: str) -> str | None:
    for suffix, tag in _SOURCE_BY_LEAF.get(_leaf(dotted), ()):
        if dotted_suffix(dotted, suffix):
            return tag
    leaf = _leaf(dotted)
    for rx, tag in SOURCE_NAME_RE.items():
        if rx.search(leaf):
            return tag
    return None


def match_sanitizer(dotted: str) -> bool:
    leaf = dotted.rsplit(".", 1)[-1]
    return leaf in SANITIZER_CALLS
