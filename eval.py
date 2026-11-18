#!/usr/bin/env python3
"""eval.py —— 拿分析器输出和 labels.json 对比

用法：python eval.py findings.sarif
findings 支持两种：SARIF 或简单 JSON（{"findings":[{"file":..,"line":..}]}）
"""
import json, sys

def load_findings(path):
    with open(path, encoding="utf-8-sig") as fh:
        doc = json.load(fh)
    out = []
    if "findings" in doc:
        for f in doc["findings"]:
            out.append((f.get("file"), int(f.get("line", 0))))
    else:
        for run in doc.get("runs", []):
            for res in run.get("results", []):
                loc = res["locations"][0]["physicalLocation"]
                out.append((loc["artifactLocation"]["uri"], int(loc["region"]["startLine"])))
    return out

def main():
    with open("labels.json", encoding="utf-8") as fh:
        labels = json.load(fh)["vulns"]
    truth = {(v["file"], v["line"]) for v in labels}
    got = set(load_findings(sys.argv[1]))
    tp = len(truth & got)
    fp = len(got - truth)
    fn = len(truth - got)
    recall = tp / (tp + fn) if (tp + fn) else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    fp_rate = fp / (tp + fp) if (tp + fp) else 0
    print(f"labels={len(truth)} findings={len(got)} TP={tp} FP={fp} FN={fn}")
    print(f"recall={recall:.1%} precision={precision:.1%} false_positive_rate={fp_rate:.1%}")

if __name__ == "__main__":
    main()
