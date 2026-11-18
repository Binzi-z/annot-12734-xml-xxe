# 自建 CFG 的 Python XXE 静态分析器

面向数据平台 XML 导入管道的 XXE 污点分析器。**只使用 Python 标准库 `ast` 做语法解析，
CFG、过程间污点引擎、规则表全部自建**，不依赖 Bandit/Semgrep 等任何现成规则集。

## 能力覆盖

- **四类落点（sink）**
  - 解析入口：`lxml.etree.parse/fromstring`（`py-xxe-lxml-parse`）
  - 流式解析：`xml.etree.ElementTree.iterparse`（`py-xxe-stream-iterparse`）
  - XML 绑定反序列化：`xmltodict/untangle/pydantic-xml/from_xml`（`py-xxe-bind-deser`）
  - 手写实体展开：`_expand_entities` 命名约定（`py-xxe-custom-entity-expand`）
  - 另含 ElementTree `parse/fromstring`（`py-xxe-etree-parse`）
- **三类污点源（source）**：上传文件/请求参数、对象存储取回（s3/oss/blob）、消息体（mq/event/record）
- **传播**：跨模块函数摘要、`map/filter/reduce/partial/compose` 函数式管道、
  透传/净化装饰器、高阶函数的可调用形参、分支/循环/with/try/推导式
- **净化（sanitizer）**：`resolve_entities=False` 的安全 parser、`defusedxml`、
  `_confine_path/_strip_dtd/_read_confine`、净化装饰器——按逐变量强更新建模，
  块汇合取交集，避免把“事后才净化”“净化了别的变量”误判为安全

## 目录

```
xxe_analyzer/
  cfg.py      自建控制流图（基本块、分支/循环/异常/with 结构化）
  model.py    source/sink/sanitizer/管道算子识别表与数据结构
  index.py    仓库级语法索引（模块、import、函数、嵌套函数）
  engine.py   CFG 上的过程间污点分析（符号摘要不动点 + 实例化触发）
  sarif.py    SARIF v2.1.0 输出
  cache.py    内容哈希 + 摘要缓存的增量分析
  analyze.py  CLI 驱动器
tools/
  gen_benchmark.py  生成 50 漏洞 + 25 安全反例语料
  eval_benchmark.py 验收评测（召回/误报率）
  gen_scale.py      生成约 20 万行性能夹具
```

## 用法

```bash
# 全量扫描，输出 SARIF
python -m xxe_analyzer.analyze src -o xxe-results.sarif

# CI 门禁（有发现时退出码 1）
python -m xxe_analyzer.analyze src -o xxe-results.sarif --check

# 增量（内容哈希 + 函数摘要缓存）
python -m xxe_analyzer.analyze src -o xxe-results.sarif --incremental --cache .xxe-cache/cache.json

# 验收语料与评分
python tools/gen_benchmark.py
python -m xxe_analyzer.analyze benchmark/corpus -o benchmark.sarif
python tools/eval_benchmark.py benchmark.sarif
```

## 验收结果（本仓库实测）

- 50 条标注漏洞：**召回 100%**，误报率 **0%**；25 条安全反例零误报
  （验收门槛：召回 ≥85%、误报 ≤15%）
- 原 8 条标注语料（`src/`）：8/8 全中、0 误报
- 性能（约 20 万行、274 模块夹具）：
  - 全量 ~11–15s（要求 <3 分钟）
  - 无变更增量 ~1.1s、单文件变更增量 ~11s（要求 <15s）
  - 增量与全量发现集合完全一致
- CI：`.github/workflows/xxe-analyzer.yml`，跑测试 + 验收 + 上传 SARIF 到 code scanning

## 增量为什么与全量一致

缓存键只含 **文件 SHA-256 + 分析器版本**，不含时间戳；同样内容 + 同样分析器必然同结果。
变更经 import 图反向闭包扩散（被依赖模块变更，依赖方一并重算）；
未变更文件的函数摘要直接反序列化还原，发现从缓存原样取回，不参与重放。

## 配置项污点源如何建模，才不会把整库标成污染

核心是**把“配置/部署数据”与“外部请求数据”分成两个不相交的溯源域**：

1. **独立标签 `CONFIG`，不进危险集**。`BASE_DIR/settings/config/os.environ/常量`
   等命中配置命名规则的值只打 `CONFIG`，而危险判定只看
   `{REQUEST_UPLOAD, MESSAGE_BODY, OBJECT_STORAGE}`。配置可以在数据流里自由传播
   （拼路径、传参数），但永远不能单独触发 sink 告警——因此不会因为一个全局
   配置对象被到处引用就把整库标脏。
2. **危险标签只能由显式 source 产生**：请求下标（`request['x']`）、消息属性
   （`msg.body`）、对象存储调用（`s3.get_object`）等。普通函数参数默认不可信也不脏，
   只有命名命中 source 约定（raw/body/blob/upload…）的 handler 入口参数才播种。
3. **标签是格（lattice）上的集合，合流按并集、净化按强更新**。配置与污点混合后
   仍是“含危险标签”，但纯配置路径始终干净；`resolve_entities=False` 这类净化把危险
   标签剥除而不影响 `CONFIG`，二者互不污染。
4. **只在“外部数据 → 危险 sink 且无净化”同时成立时报警**，配置 → sink 不构成漏洞，
   从根上杜绝配置源导致的全库污染。
