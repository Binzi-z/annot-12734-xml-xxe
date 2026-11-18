"""xxe_analyzer 的端到端测试：SARIF 输出、四类 sink、净化、增量一致性。"""
import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run(*args):
    return subprocess.run(
        [sys.executable, "-m", "xxe_analyzer.analyze", *args],
        capture_output=True, text=True, cwd=ROOT, check=True,
    )


def test_original_corpus_recall_and_precision():
    _run("src", "-o", "out_test.sarif")
    doc = json.load(open(os.path.join(ROOT, "out_test.sarif"), encoding="utf-8"))
    got = {(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            r["locations"][0]["physicalLocation"]["region"]["startLine"])
           for r in doc["runs"][0]["results"]}
    labels = json.load(open(os.path.join(ROOT, "labels.json"), encoding="utf-8"))["vulns"]
    # src 扫描根下 URI 不带 src/ 前缀，做归一化
    truth = {(v["file"].split("/")[-1], v["line"]) for v in labels}
    assert truth <= got
    assert got == truth


def test_sarif_structure():
    _run("src", "-o", "out_test.sarif")
    doc = json.load(open(os.path.join(ROOT, "out_test.sarif"), encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "xxe-analyzer"
    rule_ids = {r["ruleId"] for r in run["results"]}
    # 原语料覆盖四类落点中的三类 + 自定义实体
    assert {"py-xxe-lxml-parse", "py-xxe-etree-parse",
            "py-xxe-stream-iterparse", "py-xxe-custom-entity-expand"} & rule_ids


def test_incremental_matches_full():
    cache = os.path.join(ROOT, ".xxe-cache-test")
    sarif_full = os.path.join(ROOT, "inc_full.sarif")
    sarif_inc = os.path.join(ROOT, "inc_inc.sarif")
    _run("benchmark/corpus", "-o", sarif_full, "--incremental", "--cache", cache)
    _run("benchmark/corpus", "-o", sarif_inc, "--incremental", "--cache", cache)

    def keys(p):
        doc = json.load(open(p, encoding="utf-8"))
        return sorted((r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                       r["locations"][0]["physicalLocation"]["region"]["startLine"],
                       r["ruleId"]) for r in doc["runs"][0]["results"])
    assert keys(sarif_full) == keys(sarif_inc)


def test_benchmark_acceptance():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "eval_benchmark", os.path.join(ROOT, "tools", "eval_benchmark.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    _run("benchmark/corpus", "-o", "bench_test.sarif")
    sarif = os.path.join(ROOT, "bench_test.sarif")
    got = {(mod.norm(u), ln) for u, ln in mod.load_sarif(sarif)}
    labels = json.load(open(os.path.join(ROOT, "benchmark", "labels.json"), encoding="utf-8"))["vulns"]
    safe = json.load(open(os.path.join(ROOT, "benchmark", "safe_cases.json"), encoding="utf-8"))["safe"]
    truth = {(mod.norm(v["file"]), v["line"]) for v in labels}
    tp = len(truth & got)
    fp = len(got - truth)
    recall = tp / len(truth)
    fpr = fp / len(got) if got else 0.0
    safe_files = {mod.norm(s["file"]) for s in safe}
    assert not any(g[0] in safe_files for g in got)
    assert recall >= 0.85 and fpr <= 0.15
