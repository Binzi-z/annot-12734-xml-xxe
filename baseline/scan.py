#!/usr/bin/env python3
"""baseline：朴素做法——凡是出现 execute/open/system/urlopen/etree.parse/iterparse/硬编码 AK 的行都报。
召回高、误报极高，正是题目要求改进的起点。"""
import json, os, re, sys

SINK_RE = re.compile(r"(execute\(|os\.system\(|open\(|urlopen\(|etree\.parse\(|ET\.parse\(|iterparse\(|_expand_entities\(|_PROD_AK_\d+ =)")

def main():
    root = "src"
    findings = []
    for dirpath, _, names in os.walk(root):
        for n in names:
            if not n.endswith(".py"):
                continue
            p = os.path.join(dirpath, n)
            for i, line in enumerate(open(p, encoding="utf-8"), 1):
                if SINK_RE.search(line):
                    findings.append({"file": p.replace("\\", "/"), "line": i})
    json.dump({"findings": findings}, sys.stdout, indent=1)

if __name__ == "__main__":
    main()
