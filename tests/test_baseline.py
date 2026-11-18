"""骨架测试：baseline 的召回要够，误报不用管（这是待改进点）。"""
import json, subprocess, sys

def test_labels_exist():
    doc = json.load(open("labels.json", encoding="utf-8"))
    assert doc["total"] > 0

def test_baseline_recall_is_high():
    out = subprocess.run([sys.executable, "baseline/scan.py"], capture_output=True, text=True, check=True)
    findings = json.loads(out.stdout)["findings"]
    labels = json.load(open("labels.json", encoding="utf-8"))["vulns"]
    truth = {(v["file"], v["line"]) for v in labels}
    got = {(f["file"], f["line"]) for f in findings}
    assert len(truth & got) >= len(truth) * 0.9, "baseline 至少覆盖九成标注"

def test_baseline_has_false_positives():
    out = subprocess.run([sys.executable, "baseline/scan.py"], capture_output=True, text=True, check=True)
    findings = json.loads(out.stdout)["findings"]
    labels = json.load(open("labels.json", encoding="utf-8"))["vulns"]
    truth = {(v["file"], v["line"]) for v in labels}
    got = {(f["file"], f["line"]) for f in findings}
    assert len(got - truth) > 0, "baseline 必然有误报，这是要改的地方"
