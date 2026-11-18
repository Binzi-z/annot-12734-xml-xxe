# XML 外部实体注入的跨模块静态分析器（Python / lxml / ElementTree）

## 现状

`baseline/scan.py` 是现在用的做法：只要出现 execute/open/system/urlopen/etree.parse/iterparse 或硬编码 AK 就报。
召回够，但误报高得没法用——`eval.py` 能算出具体数字。

## 语料

- `src/`：7 个模块，8 个真漏洞、6 个假漏洞（形状一样但中途过了 sanitizer）
- `labels.json`：真漏洞的文件、行号与传播路径
- `eval.py`：拿你的结果和 labels 对比，输出召回/误报

## 跑法

```
python baseline/scan.py > findings.json
python eval.py findings.json
python -m pytest tests -q
```
