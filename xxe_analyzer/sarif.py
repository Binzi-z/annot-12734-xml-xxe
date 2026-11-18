"""sarif.py —— SARIF v2.1.0 输出（静态分析结果交换格式，可直接传 GitHub code scanning）。"""
from __future__ import annotations

from .model import (
    RULE_LXML, RULE_ETREE, RULE_STREAM, RULE_BIND, RULE_ENTITY,
)

RULE_META = {
    RULE_LXML: {
        "name": "XXELxmlParse",
        "shortDescription": "lxml 解析外部可控 XML（外部实体注入）",
        "fullDescription": "外部可控数据进入 lxml etree.parse/fromstring，且未使用 resolve_entities=False 的安全 parser，可触发 XXE 读取文件/SSRF。",
    },
    RULE_ETREE: {
        "shortDescription": "ElementTree 解析外部可控 XML（XXE）",
        "fullDescription": "外部可控数据进入 xml.etree.ElementTree.parse/fromstring；历史版本默认实体展开存在 XXE 风险。",
    },
    RULE_STREAM: {
        "shortDescription": "iterparse 流式解析外部可控 XML（XXE）",
        "fullDescription": "外部可控数据进入 ElementTree.iterparse 流式落点，实体处理未禁用时存在 XXE 风险。",
    },
    RULE_BIND: {
        "shortDescription": "XML 绑定反序列化外部可控数据（XXE）",
        "fullDescription": "外部可控 XML 进入 xmltodict/untangle/pydantic-xml 等绑定反序列化落点，底层解析器可能解析外部实体。",
    },
    RULE_ENTITY: {
        "shortDescription": "手写实体展开处理外部可控数据（XXE）",
        "fullDescription": "外部可控数据进入自定义实体展开函数，等价于手工实现 DTD 实体解析，可被注入外部实体。",
    },
}

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "xxe-analyzer"
TOOL_VERSION = "1.0.0"


def to_sarif(findings: list) -> dict:
    rules = []
    seen_rules: set[str] = set()
    results = []
    for f in findings:
        if f.rule_id not in seen_rules:
            seen_rules.add(f.rule_id)
            meta = RULE_META[f.rule_id]
            rules.append({
                "id": f.rule_id,
                "name": meta.get("name", f.rule_id),
                "shortDescription": {"text": meta["shortDescription"]},
                "fullDescription": {"text": meta["fullDescription"]},
                "defaultConfiguration": {"level": "error"},
                "properties": {"precision": "high", "tags": ["security", "xxe", "python"]},
            })
        chain = " -> ".join(f.path)
        results.append({
            "ruleId": f.rule_id,
            "level": "error",
            "message": {
                "text": (
                    f"污点溯源 {','.join(f.sources)} 经 [{chain}] 到达 {f.sink_name} "
                    f"（入口 {f.entry}），未发现 resolve_entities=False 等净化。"
                ),
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file.replace("\\", "/")},
                    "region": {"startLine": f.line},
                }
            }],
            "properties": {
                "sources": list(f.sources),
                "taintPath": list(f.path),
                "entry": f.entry,
            },
        })
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "informationUri": "https://example.invalid/xxe-analyzer",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }


def to_simple_json(findings: list) -> dict:
    return {
        "findings": [
            {"file": f.file.replace("\\", "/"), "line": f.line, "rule": f.rule_id,
             "sources": list(f.sources), "path": list(f.path)}
            for f in findings
        ]
    }
