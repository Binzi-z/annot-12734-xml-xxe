#!/usr/bin/env python3
"""eval_benchmark.py —— 50 条标注语料 + 25 条安全反例的验收评测。

用法：
  python tools/eval_benchmark.py bench.sarif
指标：召回 ≥85%、误报率 ≤15%（按题目验收口径，FP 含安全反例上的告警）。
"""
from __future__ import annotations

import json
import sys


def load_sarif(path: str) -> set[tuple[str, int]]:
    with open(path, encoding="utf-8-sig") as fh:
        doc = json.load(fh)
    out = set()
    for run in doc.get("runs", []):
        for res in run.get("results", []):
            loc = res["locations"][0]["physicalLocation"]
            uri = loc["artifactLocation"]["uri"].replace("\\", "/")
            out.add((uri, int(loc["region"]["startLine"])))
    return out


def norm(uri: str) -> str:
    for prefix in ("benchmark/corpus/",):
        if uri.startswith(prefix):
            return uri[len(prefix):]
    return uri


def main() -> int:
    sarif_path = sys.argv[1]
    labels = json.load(open("benchmark/labels.json", encoding="utf-8"))["vulns"]
    safe = json.load(open("benchmark/safe_cases.json", encoding="utf-8"))["safe"]
    got = {(norm(u), ln) for u, ln in load_sarif(sarif_path)}
    truth = {(norm(v["file"]), v["line"]) for v in labels}

    tp = len(truth & got)
    fn = len(truth - got)
    fp_pairs = got - truth
    fp = len(fp_pairs)
    recall = tp / len(truth)
    fpr = fp / len(got) if got else 0.0
    precision = tp / len(got) if got else 0.0

    safe_files = {norm(s["file"]) for s in safe}
    safe_violations = sorted(g for g in got if g[0] in safe_files)

    print(f"labels={len(truth)} findings={len(got)} TP={tp} FP={fp} FN={fn}")
    print(f"recall={recall:.1%} precision={precision:.1%} false_positive_rate={fpr:.1%}")
    print(f"安全反例={len(safe)} 其中被误报的文件命中={len(safe_violations)}")
    for pair in sorted(truth - got):
        v = next(x for x in labels if (norm(x["file"]), x["line"]) == pair)
        print(f"  FN {pair[0]}:{pair[1]} {v['rule']} {v['id']} ({v['source']})")
    for pair in sorted(fp_pairs):
        print(f"  FP {pair[0]}:{pair[1]}")
    ok = recall >= 0.85 and fpr <= 0.15 and not safe_violations
    print("ACCEPT", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
