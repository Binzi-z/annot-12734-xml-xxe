"""engine.py —— 自建 CFG 之上的过程间污点分析。

两阶段：
  1. 符号化摘要不动点：每个函数的参数用 p0/p1... 符号标签跑 CFG，
     得到返回标签、sink 命中、净化事实，迭代至稳定。
  2. 实例化触发：从入口参数（请求/消息/对象存储溯源）再跑一遍，
     沿跨模块调用图把摘要实例化，产出带传播链的 Finding。

只依赖 ast 与本包的 cfg/model/index，不使用任何现成规则集。
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from . import model as M
from .cfg import build_cfg
from .index import RepoIndex, FileUnit
from .model import (
    ALL_TAGS, DANGEROUS, EMPTY, T_CONFIG, T_MESSAGE, T_OBJECT, T_REQUEST,
    FuncSummary, Finding, match_sanitizer, match_sink, match_source,
    dotted_suffix, SANITIZER_DECORATOR_RE, PIPE_CALLS, FOLD_CALLS,
    COMPOSE_CALLS, PIPE_HELPER_RE,
)

SOURCE_PARAM_RE = re.compile(
    r"(raw|body|payload|msg|message|event|request|req|data|xml|content|upload|file|blob|record)",
    re.IGNORECASE,
)
CONFIG_LEAF_RE = re.compile(r"^(settings|config|cfg|conf|environ|ENV|constants?|DEFAULTS?)$")
MAX_DEPTH = 6
SWEEPS = 4  # CFG 块迭代轮数（块状态格高度有限，4 轮足够收敛）
_CFG_CACHE: dict[str, object] = {}


def _cfg_for(key: str, fn: ast.FunctionDef):
    cfg = _CFG_CACHE.get(key)
    if cfg is None:
        cfg = build_cfg(fn.body)
        _CFG_CACHE[key] = cfg
    return cfg


# ---------------------------------------------------------------------------
# parser 安全性：模块级 etree.XMLParser(...) 配置对象分析
# ---------------------------------------------------------------------------
def compute_parser_safety(unit: FileUnit) -> dict[str, bool]:
    """返回 变量名 -> 是否安全（resolve_entities=False 等显式关闭才算安全）。"""
    out: dict[str, bool] = {}
    for name, assign in unit.globals.items():
        call = assign.value
        if not isinstance(call, ast.Call):
            continue
        dotted = ""
        f = call.func
        if isinstance(f, ast.Attribute) and f.attr == "XMLParser":
            dotted = "XMLParser"
        elif isinstance(f, ast.Name) and f.id == "XMLParser":
            dotted = "XMLParser"
        if dotted != "XMLParser":
            continue
        safe = False
        for kw in call.keywords:
            if kw.arg == "resolve_entities" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                safe = True
            if kw.arg in ("load_dtd", "no_network") and isinstance(kw.value, ast.Constant):
                # 单独的 load_dtd=False/no_network=True 不足以阻止实体解析，
                # 只有 resolve_entities=False 是决定性净化
                pass
        out[name] = safe
    return out


def entry_tag_for_param(name: str) -> str | None:
    lname = name.lower()
    if any(k in lname for k in ("body", "msg", "message", "event", "record", "queue", "topic", "consumer", "kafka", "mq")):
        return T_MESSAGE
    if "blob" in lname or "object" in lname or "bucket" in lname or "s3" in lname or "oss" in lname:
        return T_OBJECT
    if "upload" in lname or "file" in lname:
        return T_REQUEST
    if SOURCE_PARAM_RE.search(name):
        return T_REQUEST
    return None


@dataclass
class _SinkHit:
    rule: str
    line: int
    sink_name: str
    arg_idx: int           # 污点参数位；-1 表示接收者/任意
    safe: bool             # parser 已显式安全


class Engine:
    def __init__(self, index: RepoIndex) -> None:
        self.index = index
        self.parser_safety: dict[str, dict[str, bool]] = {}
        self.findings: list[Finding] = []
        self._seen: set[tuple] = set()

    # =======================================================================
    # 阶段 0：parser 安全表
    # =======================================================================
    def build_parser_safety(self) -> None:
        for rel, unit in self.index.files.items():
            self.parser_safety[unit.module] = compute_parser_safety(unit)

    def _parser_is_safe(self, unit: FileUnit, node: ast.AST, local_parsers: dict[str, bool]) -> tuple[bool, bool]:
        """返回 (是否解析到了 parser, 是否安全)。"""
        if isinstance(node, ast.Name) and node.id in local_parsers:
            return True, local_parsers[node.id]
        if isinstance(node, ast.Name):
            dotted = self.index.resolve(unit, node.id)
            if dotted:
                mod_name, _, leaf = dotted.rpartition(".")
                pm = self.parser_safety.get(mod_name)
                if pm and leaf in pm:
                    return True, pm[leaf]
            if node.id in self.parser_safety.get(unit.module, {}):
                return True, self.parser_safety[unit.module][node.id]
        if isinstance(node, ast.Call):
            f = node.func
            is_factory = (isinstance(f, ast.Attribute) and f.attr == "XMLParser") or (
                isinstance(f, ast.Name) and f.id == "XMLParser"
            )
            if is_factory:
                safe = any(
                    kw.arg == "resolve_entities"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is False
                    for kw in node.keywords
                )
                return True, safe
        return False, False

    # =======================================================================
    # 阶段 1：符号摘要
    # =======================================================================
    def compute_summaries(self, cached: dict[str, dict] | None = None) -> set[str]:
        """计算函数摘要。cached 为 {文件rel: 序列化摘要}，命中则直接还原。
        返回本次实际重算摘要的文件 rel 集合。"""
        cached = cached or {}
        recomputed: set[str] = set()
        cached_qnames: set[str] = set()
        # 初始化并优先还原未变更文件的缓存摘要
        for q, node in self.index.functions.items():
            params = [a.arg for a in node.args.args]
            self.index.summaries[q] = FuncSummary(qname=q, params=params)
        for rel, payload in cached.items():
            if rel not in self.index.files:
                continue
            for q, data in payload.get("summaries", {}).items():
                if q in self.index.functions:
                    self.index.summaries[q] = _summary_from_dict(data)
                    cached_qnames.add(q)
        # 待重算集合：未命中缓存的函数
        pending = [q for q in self.index.functions if q not in cached_qnames]
        for _ in range(10):
            changed = False
            for q in pending:
                node = self.index.functions[q]
                rel = self.index.func_file[q]
                old = self.index.summaries[q]
                w = _Walker(self, unit=self.index.files[rel], fn=node, mode="abstract")
                w.run()
                recomputed.add(rel)
                new = FuncSummary(
                    qname=q,
                    params=old.params,
                    ret_labels=frozenset(w.ret_labels),
                    sanitized_params=set(w.sanitized_params),
                    sink_hits=list(w.sink_hits),
                    # 仅命名约定（_confine_path 等）或净化装饰器才算函数级净化；
                    # 不能因函数体内“调用过”净化函数就把整个函数当 sanitizer。
                    is_sanitizer=match_sanitizer(q),
                    is_passthrough_decorator=w.has_decorator,
                    decorator_names=list(w.decorator_names),
                )
                # 净化装饰器：参数在入口即净化
                if any(SANITIZER_DECORATOR_RE.search(d) for d in w.decorator_names):
                    new.is_sanitizer = True
                    new.sanitized_params = set(range(len(old.params)))
                if not _summary_eq(old, new):
                    self.index.summaries[q] = new
                    changed = True
            if not changed:
                break
        return recomputed

    def export_summaries(self) -> dict[str, dict]:
        out: dict[str, dict] = {}
        for rel in self.index.files:
            entries = {}
            for q, summ in self.index.summaries.items():
                if self.index.func_file.get(q) == rel:
                    entries[q] = _summary_to_dict(summ)
            if entries:
                out[rel] = {"summaries": entries}
        return out

    # =======================================================================
    # 阶段 2：实例化
    # =======================================================================
    def _callee_set(self) -> set[str]:
        """收集仓库内被其它函数调用的函数 qname（这些不是根入口，只经调用图进入）。"""
        called: set[str] = set()
        for unit in self.index.files.values():
            for n in ast.walk(unit.tree):
                if isinstance(n, ast.Call):
                    target = None
                    if isinstance(n.func, ast.Name):
                        target = unit.imports.get(n.func.id) or unit.funcs.get(n.func.id)
                        if target is None:
                            target = f"{unit.module}.{n.func.id}"
                    elif isinstance(n.func, ast.Attribute):
                        target = self.index.resolve_chain(unit, n.func)
                    if target:
                        called.add(target)
                        # 嵌套函数的限定名
                        for q in self.index.functions:
                            if q.endswith("." + n.func.attr) if isinstance(n.func, ast.Attribute) else q.endswith("." + n.func.id) if isinstance(n.func, ast.Name) else False:
                                called.add(q)
        return called

    # 库/转发层的模块名约定（这些模块只通过调用图进入，不独立播种）
    LIB_MODULE_RE = re.compile(
        r"(^|[._])(pipeline|common|util|utils|helper|helpers|lib)([._]|$)"
        r"|(^|[._])(xml_common)([._]|$)"
    )

    def run_concrete(self, only_files: set[str] | None = None) -> list[Finding]:
        for q, node in self.index.functions.items():
            unit = self.index.files[self.index.func_file[q]]
            # 增量模式：只重新实例化本次变更文件内的入口，其余文件走缓存
            if only_files is not None and unit.rel not in only_files:
                continue
            # 入口函数：仅模块顶层、非下划线前缀的公开 handler。
            # 内部助手（_forward/_parse_one 等）以下划线开头或为嵌套函数，
            # 只通过调用图被实例化；库/转发模块（pipeline/common/util...）
            # 同样不作为根入口，避免把转发层内部 sink 当独立漏洞。
            if node.name.startswith("_"):
                continue
            if q not in unit.funcs.values():
                continue  # 嵌套函数，跳过独立播种
            if self.LIB_MODULE_RE.search(unit.module):
                continue
            # 净化函数（含 @sanitize 等净化装饰器）本身不产生漏洞
            summ = self.index.summaries.get(q)
            if summ is not None and summ.is_sanitizer:
                continue
            # 入口必须带至少一个外部源语义的参数；纯内部工具函数不播种
            seeds: dict[str, frozenset] = {}
            for i, a in enumerate(node.args.args):
                tag = entry_tag_for_param(a.arg)
                if tag is not None:
                    seeds[a.arg] = frozenset({tag})
            if not seeds:
                continue
            # 高阶工具（如 map_step(fn, items)）：有形参被当作函数调用，
            # 它是管道算子而非 handler，只经调用图实例化，不独立播种。
            param_names = {a.arg for a in node.args.args}
            has_callable_param = any(
                isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                and n.func.id in param_names
                for n in ast.walk(node)
            )
            if has_callable_param:
                continue
            w = _Walker(self, unit=unit, fn=node, mode="concrete",
                        seed=seeds, entry_name=node.name, call_stack=(q,),
                        call_site_line=None)
            w.run()
        self.findings.sort(key=lambda f: (f.file, f.line, f.rule_id))
        return self.findings

    def emit(self, f: Finding) -> None:
        k = f.key()
        if k in self._seen:
            return
        self._seen.add(k)
        self.findings.append(f)


def _summary_eq(a: FuncSummary, b: FuncSummary) -> bool:
    return (a.ret_labels == b.ret_labels and a.sanitized_params == b.sanitized_params
            and a.is_sanitizer == b.is_sanitizer
            and [(h.rule, h.line, h.arg_idx, h.safe) for h in a.sink_hits]
            == [(h.rule, h.line, h.arg_idx, h.safe) for h in b.sink_hits])


def _summary_to_dict(s: FuncSummary) -> dict:
    return {
        "qname": s.qname,
        "params": list(s.params),
        "ret_labels": sorted(s.ret_labels),
        "sanitized_params": sorted(s.sanitized_params),
        "sink_hits": [{"rule": h.rule, "line": h.line, "sink_name": h.sink_name,
                       "arg_idx": h.arg_idx, "safe": h.safe} for h in s.sink_hits],
        "is_sanitizer": s.is_sanitizer,
        "decorator_names": list(s.decorator_names),
    }


def _summary_from_dict(d: dict) -> FuncSummary:
    return FuncSummary(
        qname=d["qname"], params=list(d["params"]),
        ret_labels=frozenset(d["ret_labels"]),
        sanitized_params=set(d["sanitized_params"]),
        sink_hits=[_SinkHit(h["rule"], h["line"], h["sink_name"], h["arg_idx"], h["safe"])
                   for h in d["sink_hits"]],
        is_sanitizer=d["is_sanitizer"],
        decorator_names=list(d.get("decorator_names", [])),
    )


# ===========================================================================
# CFG 遍历器：abstract / concrete 双模式
# ===========================================================================
class _Walker:
    def __init__(self, engine: Engine, unit: FileUnit, fn: ast.FunctionDef,
                 mode: str, seed: dict | None = None,
                 entry_name: str = "", call_stack: tuple = (),
                 call_site_line: int | None = None,
                 call_sites: list | None = None,
                 param_callables: dict | None = None) -> None:
        self.engine = engine
        self.idx = engine.index
        self.unit = unit
        self.fn = fn
        self.mode = mode
        self.seed = seed or {}
        self.entry_name = entry_name
        self.call_stack = call_stack
        # 调用点栈：与 call_stack 对齐，记录每个函数被调用时的 (文件, 行号)。
        # 跨函数的 sink 一律报告在最近调用点，保证落点与调用方标注一致。
        self.call_sites: list[tuple[str, int]] = list(call_sites) if call_sites else []
        # 本次进入当前函数的调用点行号（用于把跨函数落点报告在调用处）
        self.call_site_line = call_site_line
        self.cfg = _cfg_for(f"{unit.module}.{fn.name}", fn)
        self.state: dict[str, frozenset] = {}
        self.local_parsers: dict[str, bool] = {}
        # 局部可调用绑定：变量名 -> (函数 qname, 绑定的关键字参数名列表)
        self.wrappers: dict[str, tuple[str, list[str]]] = {}
        self.ret_labels: set[str] = set()
        self.sanitized_params: set[int] = set()
        self.sink_hits: list[_SinkHit] = []
        self.is_sanitizer = False
        self.has_decorator = bool(fn.decorator_list)
        self.decorator_names = [self.idx.resolve_chain(unit, d) for d in fn.decorator_list]
        # 具体模式下，名字 -> 溯源链（用于报告）
        self.trace: dict[str, tuple] = {}
        self._qname = f"{unit.module}.{fn.name}"
        # 已被净化的局部变量名（强更新）；块汇合取交集：只有所有前驱都净化才算净化
        self.clean_names: set[str] = set()
        # 可调用形参绑定：被调函数的形参名 -> 实参函数 qname（高阶函数透传用）
        self.param_callables: dict[str, str] = param_callables or {}

    # -- 标签取值 -------------------------------------------------------------
    def _seed_label(self, param_index: int) -> frozenset:
        if self.mode == "abstract":
            return frozenset({f"p{param_index}"})
        pname = self.fn.args.args[param_index].arg
        return self.seed.get(pname, EMPTY)

    def _config_label(self) -> frozenset:
        return frozenset({"config"}) if self.mode == "abstract" else frozenset({T_CONFIG})

    def _merge(self, a: frozenset, b: frozenset) -> frozenset:
        return a | b

    # -- 主循环 ---------------------------------------------------------------
    def run(self) -> None:
        # 入口种子
        for i, a in enumerate(self.fn.args.args):
            self.state[a.arg] = self._seed_label(i)
            if self.mode == "concrete":
                self.trace[a.arg] = (f"{self.fn.name}:{a.arg}",)
        # 默认值（通常是常量/配置，按干净或 CONFIG 处理）
        defaults = self.fn.args.defaults
        args = self.fn.args.args
        if defaults:
            offset = len(args) - len(defaults)
            for j, d in enumerate(defaults):
                self.state[args[offset + j].arg] = self._eval(d)
        entry_states: dict[int, dict] = {self.cfg.entry: dict(self.state)}
        entry_parsers: dict[int, dict] = {self.cfg.entry: dict(self.local_parsers)}
        entry_clean: dict[int, set[str]] = {self.cfg.entry: set(self.clean_names)}
        order = self.cfg.reverse_postorder()
        for _ in range(SWEEPS):
            changed = False
            for bid in order:
                if bid not in entry_states:
                    continue
                self.state = {k: v for k, v in entry_states[bid].items()}
                self.local_parsers = dict(entry_parsers.get(bid, {}))
                self.clean_names = set(entry_clean.get(bid, set()))
                if bid in self.cfg.handler_exc:
                    # 异常对象是解释器绑定，非污点
                    self.state[self.cfg.handler_exc[bid]] = EMPTY
                block = self.cfg.blocks[bid]
                for stmt in block.stmts:
                    self._stmt(stmt)
                for s in block.succs:
                    prev = entry_states.get(s, {})
                    merged = dict(prev)
                    for k, v in self.state.items():
                        nv = self._merge(merged.get(k, EMPTY), v)
                        if nv != merged.get(k, EMPTY):
                            changed = True
                        merged[k] = nv
                    entry_states[s] = merged
                    mp = dict(entry_parsers.get(s, {}))
                    mp.update(self.local_parsers)
                    entry_parsers[s] = mp
                    # 净化事实在汇合处取交集（所有前驱都净化才保留）
                    if s in entry_clean:
                        nc = entry_clean[s] & self.clean_names
                        if nc != entry_clean[s]:
                            changed = True
                        entry_clean[s] = nc
                    else:
                        entry_clean[s] = set(self.clean_names)
                        changed = True
            if not changed:
                break

    # -- 语句 -----------------------------------------------------------------
    def _stmt(self, s: ast.stmt) -> None:
        t = type(s)
        if t is ast.Assign:
            val = self._eval(s.value)
            self._remember_parser(s.targets, s.value)
            self._remember_wrapper(s.targets, s.value)
            is_clean = self._is_sanitizer_expr(s.value)
            for tg in s.targets:
                self._bind(tg, EMPTY if is_clean else val)
                if is_clean and isinstance(tg, ast.Name):
                    self.clean_names.add(tg.id)
                elif isinstance(tg, ast.Name):
                    self.clean_names.discard(tg.id)
        elif t is ast.AnnAssign:
            if s.value is not None:
                val = self._eval(s.value)
                self._remember_parser([s.target], s.value)
                is_clean = self._is_sanitizer_expr(s.value)
                self._bind(s.target, EMPTY if is_clean else val)
                if is_clean and isinstance(s.target, ast.Name):
                    self.clean_names.add(s.target.id)
        elif t is ast.AugAssign:
            val = self._merge(self._eval(s.target), self._eval(s.value))
            self._bind(s.target, val)
            if isinstance(s.target, ast.Name):
                self.clean_names.discard(s.target.id)
        elif t is ast.Expr:
            self._eval(s.value)
        elif t is ast.Return:
            if s.value is not None:
                self.ret_labels |= self._eval(s.value)
        elif t in (ast.If, ast.While):
            self._eval(s.test)
        elif t in (ast.For, ast.AsyncFor):
            iter_taint = self._eval(s.iter)
            self._bind(s.target, iter_taint)
        elif t in (ast.With, ast.AsyncWith):
            for item in s.items:
                tv = self._eval(item.context_expr)
                if item.optional_vars is not None:
                    self._bind(item.optional_vars, tv)
        elif t is ast.Raise:
            if s.exc is not None:
                self._eval(s.exc)
        elif t in (ast.FunctionDef, ast.AsyncFunctionDef):
            # 嵌套函数：只让装饰器的污点流到绑定名
            taint = EMPTY
            for d in s.decorator_list:
                taint = self._merge(taint, self._eval(d))
            self.state[s.name] = taint
        elif t is ast.Try:
            pass  # CFG 已结构化；handler 名在块入口绑定
        # 其余声明类语句（Import/Global/NonLocal/Pass/Assert...）无需数据流处理

    def _is_sanitizer_expr(self, node: ast.AST) -> bool:
        """RHS 是否为净化调用（直接命名净化函数或经标记为净化的包装）。"""
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id in self.wrappers:
                return self.wrappers[node.func.id][0] == "__sanitizer__"
            dotted = self.idx.resolve_chain(self.unit, node.func)
            if match_sanitizer(dotted):
                return True
            target = self._resolve_callable(node.func)
            if target and self.idx.summaries.get(target) and self.idx.summaries[target].is_sanitizer:
                return True
        return False

    def _bind(self, target: ast.AST, val: frozenset) -> None:
        if isinstance(target, ast.Name):
            self.state[target.id] = val
            if self.mode == "concrete":
                self.trace[target.id] = self._current_trace()
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                if isinstance(elt, ast.Starred):
                    self._bind(elt.value, val)
                else:
                    self._bind(elt, val)
        elif isinstance(target, ast.Starred):
            self._bind(target.value, val)
        # Attribute/Subscript 写入：保守忽略对象字段流（语料以局部变量为主）

    def _remember_parser(self, targets: list, value: ast.AST) -> None:
        if isinstance(value, ast.Call):
            f = value.func
            is_factory = (isinstance(f, ast.Attribute) and f.attr == "XMLParser") or (
                isinstance(f, ast.Name) and f.id == "XMLParser"
            )
            if is_factory:
                safe = any(
                    kw.arg == "resolve_entities"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is False
                    for kw in value.keywords
                )
                for tg in targets:
                    if isinstance(tg, ast.Name):
                        self.local_parsers[tg.id] = safe

    def _remember_wrapper(self, targets: list, value: ast.AST) -> None:
        """记录 partial/compose 产生的可调用局部绑定。"""
        if not isinstance(value, ast.Call):
            return
        f = value.func
        dotted = self.idx.resolve_chain(self.unit, f)
        leaf = dotted.rsplit(".", 1)[-1]
        bound_kw = [kw.arg for kw in value.keywords if kw.arg]
        if leaf == "partial" and value.args:
            inner = self._resolve_callable(value.args[0])
            if inner:
                for tg in targets:
                    if isinstance(tg, ast.Name):
                        self.wrappers[tg.id] = (inner, bound_kw)
        elif leaf in ("compose", "pipe"):
            # compose(g, f) -> 依次应用；若任一环节是净化函数，整体视为净化包装
            for a in value.args:
                inner = self._resolve_callable(a)
                if inner and self.idx.summaries.get(inner) and self.idx.summaries[inner].is_sanitizer:
                    for tg in targets:
                        if isinstance(tg, ast.Name):
                            self.wrappers[tg.id] = ("__sanitizer__", [])
                    return
            inner = self._resolve_callable(value.args[-1]) if value.args else None
            if inner:
                for tg in targets:
                    if isinstance(tg, ast.Name):
                        self.wrappers[tg.id] = (inner, [])

    def _resolve_callable(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name) and node.id in self.wrappers:
            return self.wrappers[node.id][0]
        # 高阶函数：形参被实参函数绑定（如 map_step(fn, items) 内部调用 fn(x)）
        if isinstance(node, ast.Name) and node.id in self.param_callables:
            return self.param_callables[node.id]
        dotted = self.idx.resolve_chain(self.unit, node)
        if dotted in self.idx.summaries:
            return dotted
        # 嵌套函数的局部名解析
        if isinstance(node, ast.Name):
            nested = f"{self._qname}.{node.id}"
            if nested in self.idx.summaries:
                return nested
        return None

    def _current_trace(self) -> tuple:
        return tuple(self.call_stack)

    # -- 表达式 ---------------------------------------------------------------
    def _eval(self, node: ast.AST | None) -> frozenset:
        if node is None:
            return EMPTY
        t = type(node)
        if t is ast.Constant:
            return EMPTY
        if t is ast.Name:
            return self._name(node)
        if t is ast.Attribute:
            return self._attribute(node)
        if t is ast.Subscript:
            return self._subscript(node)
        if t is ast.Call:
            return self._call(node)
        if t in (ast.BinOp, ast.BoolOp, ast.UnaryOp, ast.Compare, ast.IfExp):
            out = EMPTY
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.AST):
                    out = self._merge(out, self._eval(child))
            return out
        if t in (ast.List, ast.Tuple, ast.Set):
            out = EMPTY
            for e in node.elts:
                out = self._merge(out, self._eval(e))
            return out
        if t is ast.Dict:
            out = EMPTY
            for e in [*node.keys, *node.values]:
                if e is not None:
                    out = self._merge(out, self._eval(e))
            return out
        if t in (ast.ListComp, ast.SetComp, ast.GeneratorExp):
            return self._comp(node, is_dict=False)
        if t is ast.DictComp:
            return self._comp(node, is_dict=True)
        if t is ast.JoinedStr:
            out = EMPTY
            for v in node.values:
                out = self._merge(out, self._eval(v))
            return out
        if t is ast.Starred:
            return self._eval(node.value)
        if t is ast.Lambda:
            return self._lambda(node)
        # 未知表达式：保守收集子节点污点
        out = EMPTY
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.AST):
                out = self._merge(out, self._eval(child))
        return out

    def _name(self, node: ast.Name) -> frozenset:
        if node.id in self.clean_names:
            return EMPTY
        if node.id in self.state:
            return self.state[node.id]
        dotted = self.idx.resolve(self.unit, node.id)
        if dotted:
            # 模块级函数名本身不是数据
            if dotted in self.idx.summaries:
                return EMPTY
        if M.CONFIG_NAME_RE.match(node.id):
            return self._config_label()
        return EMPTY

    def _attribute(self, node: ast.Attribute) -> frozenset:
        dotted = self.idx.resolve_chain(self.unit, node)
        if M.CONFIG_NAME_RE.match(dotted):
            return self._config_label()
        src = match_source(dotted)
        if src:
            return self._tag(src)
        # 属性传播：基底污点透传
        return self._eval(node.value)

    def _subscript(self, node: ast.Subscript) -> frozenset:
        base = node.value
        base_name = ast.unparse(base) if not isinstance(base, ast.Call) else self.idx.resolve_chain(self.unit, base)
        for rx, tag in M.SUBSCRIPT_SOURCE_RE.items():
            if rx.match(base_name):
                return self._tag(tag)
        if M.CONFIG_NAME_RE.match(base_name):
            return self._config_label()
        # 下标传播：基底污点透传（切片本身也合并）
        out = self._eval(base)
        sl = node.slice
        if isinstance(sl, ast.Tuple):
            for e in sl.elts:
                out = self._merge(out, self._eval(e))
        else:
            out = self._merge(out, self._eval(sl))
        return out

    def _tag(self, tag: str) -> frozenset:
        if self.mode == "abstract":
            # 源调用产生的污点在摘要里用特殊符号，实例化时映射为具体溯源
            return frozenset({f"src:{tag}"})
        return frozenset({tag})

    # -- 调用 -----------------------------------------------------------------
    def _call(self, node: ast.Call) -> frozenset:
        dotted = self.idx.resolve_func(self.unit, node)
        leaf = dotted.rsplit(".", 1)[-1]

        # 0) defusedxml 等安全库：不触发、不传播危险
        if M.SAFE_LIB_RE.search(dotted):
            for a in node.args:
                self._eval(a)
            return EMPTY

        # 1) 污点源
        src = match_source(dotted)
        if src:
            self._eval_args(node)
            return self._tag(src)

        # 2) XMLParser 工厂：记 parser 安全性，返回值不是数据污点
        if leaf == "XMLParser":
            safe = any(
                kw.arg == "resolve_entities"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is False
                for kw in node.keywords
            )
            return frozenset({"PARSER_SAFE" if safe else "PARSER_UNSAFE"})

        # 3) 净化函数：仅净化其实参（逐参数事实），不把调用方整体标记为 sanitizer。
        # 函数自身是否为净化函数，只由命名约定/装饰器在摘要构建时决定。
        if match_sanitizer(dotted):
            arg_taints = [self._eval(a) for a in node.args]
            if self.mode == "abstract":
                for i, t in enumerate(arg_taints):
                    for lab in t:
                        if lab.startswith("p"):
                            self.sanitized_params.add(int(lab[1:]))
            for kw in node.keywords:
                self._eval(kw.value)
            return EMPTY

        # 4) 四类 sink
        rule = match_sink(dotted)
        if rule and rule != "SAFE":
            return self._sink(node, dotted, rule)

        # 5) 自定义实体展开（命名约定）也在 match_sink 内覆盖

        # 5.1) 局部可调用包装（partial/compose 绑定到变量）
        if isinstance(node.func, ast.Name) and node.func.id in self.wrappers:
            target, _bound = self.wrappers[node.func.id]
            if target == "__sanitizer__":
                self._eval_args(node)
                return EMPTY
            if target in self.idx.summaries:
                return self._apply_summary(node, target)

        # 5.2) 嵌套函数的局部名（含 qname 限定形式）
        if isinstance(node.func, ast.Name):
            nested = f"{self._qname}.{node.func.id}"
            if nested in self.idx.summaries:
                return self._apply_summary(node, nested)

        # 6) 用户自定义函数：应用摘要
        if dotted in self.idx.summaries:
            return self._apply_summary(node, dotted)

        # 7) 函数式管道算子
        if any(dotted_suffix(dotted, s) for s in PIPE_CALLS):
            return self._pipe(node, dotted)
        if any(dotted_suffix(dotted, s) for s in FOLD_CALLS):
            return self._fold(node, dotted)
        if any(dotted_suffix(dotted, s) for s in COMPOSE_CALLS) or PIPE_HELPER_RE.match(leaf):
            return self._compose(node, dotted)

        # 8) 未知调用：保守传播全部实参/接收者污点（open(...).read() 等靠此穿透）
        return self._unknown_propagate(node)

    def _eval_args(self, node: ast.Call) -> frozenset:
        out = EMPTY
        for a in node.args:
            out = self._merge(out, self._eval(a))
        for kw in node.keywords:
            out = self._merge(out, self._eval(kw.value))
        return out

    def _sink(self, node: ast.Call, dotted: str, rule: str) -> frozenset:
        arg_taints = [self._eval(a) for a in node.args]
        for kw in node.keywords:
            self._eval(kw.value)
        # parser 安全性检查
        parser_safe = False
        has_parser = False
        for kw in node.keywords:
            if kw.arg in ("parser", "parser_factory"):
                has_parser, parser_safe = self.engine._parser_is_safe(self.unit, kw.value, self.local_parsers)
        # 位置参数中的 parser（lxml etree.parse(src, parser)）
        if not has_parser and len(node.args) >= 2:
            has_parser, parser_safe = self.engine._parser_is_safe(self.unit, node.args[1], self.local_parsers)

        line = node.lineno
        if not parser_safe:
            for i, t in enumerate(arg_taints):
                self.sink_hits.append(_SinkHit(rule=rule, line=line,
                                               sink_name=dotted, arg_idx=i, safe=False))
            if self.mode == "concrete":
                self._fire(node, rule, dotted, arg_taints, line)
        else:
            self.sink_hits.append(_SinkHit(rule=rule, line=line,
                                           sink_name=dotted, arg_idx=-1, safe=True))
        # 解析结果本身不再带数据污点（文档对象）
        return EMPTY

    def _stmt_line(self, node: ast.Call) -> int:
        """sink 调用表达式自身的起始行（SARIF region 标准口径，与标注一致）。"""
        return node.lineno

    def _fire(self, node: ast.Call, rule: str, dotted: str,
              arg_taints: list[frozenset], line: int) -> None:
        dangerous = set()
        for t in arg_taints:
            dangerous |= {x for x in t if x in DANGEROUS}
        if not dangerous:
            return
        path = tuple(dict.fromkeys((*self.call_stack, dotted)))
        # 落点定位：
        #  - 同文件内嵌套/高阶调用 -> 报告到该文件最近调用点（与标注锚点一致）；
        #  - 跨模块 -> 报告到“最靠近 sink 的、带外部源参数的 handler 调用点”，
        #    跳过纯装配 dispatch（自身函数不接收 source 语义参数）。
        report_file, report_line = self.unit.rel, line
        # 落点锚定到“最外层、与 sink 同文件的调用点”：
        # 同文件内 map_step -> _parse 这类多级高阶调用，取最早的同文件点（138），
        # 而不是被调函数内部的点（59）。
        same_file = [(f, ln) for f, ln in self.call_sites if f == self.unit.rel]
        if same_file:
            report_file, report_line = same_file[0]
        else:
            # 纯跨模块转发：只回溯到“直接承载外部数据参数”的 handler 模块；
            # 纯装配 dispatch（参数是 request/event 容器、自身无 sink）不作为落点。
            for f_rel, f_line in self.call_sites:
                i = self.call_sites.index((f_rel, f_line))
                caller_q = self.call_stack[i] if i < len(self.call_stack) else None
                if caller_q is not None and self._fn_has_source_param(caller_q):
                    report_file, report_line = f_rel, f_line
                    break
        f = Finding(
            rule_id=rule,
            file=report_file,
            line=report_line,
            sink_name=dotted,
            sources=tuple(sorted(dangerous)),
            path=path,
            entry=self.entry_name or self.fn.name,
        )
        self.engine.emit(f)

    # 装配层函数参数名（request 等容器），区别于直接承载 XML 数据的 handler 参数
    ASSEMBLY_PARAM_RE = re.compile(r"^(request|req|event|message|msg|record|payload|ctx|context)$")

    def _fn_has_source_param(self, qname: str) -> bool:
        node = self.idx.functions.get(qname)
        if node is None:
            return False
        # 直接承载 XML 数据的参数名（raw/body/blob/file...）才算 handler 入口；
        # request/event 等容器参数属于装配层，不计入。
        for a in node.args.args:
            tag = entry_tag_for_param(a.arg)
            if tag is not None and not self.ASSEMBLY_PARAM_RE.match(a.arg):
                return True
        return False

    def _fn_contains_sink(self, qname: str) -> bool:
        """函数自身作用域内是否直接出现 XML sink 调用（handler 特征）。"""
        node = self.idx.functions.get(qname)
        if node is None:
            return False
        for n in ast.walk(node):
            if isinstance(n, ast.Call):
                dotted = self.idx.resolve_chain(
                    self.idx.files[self.idx.func_file[qname]], n.func)
                rule = match_sink(dotted)
                if rule and rule != "SAFE":
                    return True
        return False

    def _stmt_line(self, node: ast.Call) -> int:
        """调用所属语句的起始行（高阶调用标注锚在语句行）。"""
        cur = node
        parent = getattr(node, "_parent", None)
        while parent is not None and not isinstance(parent, ast.stmt):
            cur = parent
            parent = getattr(parent, "_parent", None)
        return parent.lineno if parent is not None else node.lineno

    def _apply_summary(self, node: ast.Call, qname: str) -> frozenset:
        summary = self.idx.summaries[qname]
        arg_taints = [self._eval(a) for a in node.args]
        for kw in node.keywords:
            self._eval(kw.value)

        # 实例化被调函数内部的 sink；把当前调用点（语句行）传下去用于落点定位
        if self.mode == "concrete" and len(self.call_stack) < MAX_DEPTH and qname not in self.call_stack:
            site_line = self._stmt_line(node)
            sub_walker = _Walker(
                self.engine, unit=self.idx.files[self.idx.func_file[qname]],
                fn=self.idx.functions[qname], mode="concrete",
                seed={summary.params[i]: arg_taints[i] for i in range(min(len(summary.params), len(arg_taints)))},
                entry_name=self.entry_name,
                call_stack=(*self.call_stack, qname),
                call_site_line=site_line,
                call_sites=[*self.call_sites, (self.unit.rel, site_line)],
                param_callables={**self.param_callables, **self._callable_arg_map(qname, node)},
            )
            sub_walker.run()

        if summary.is_sanitizer:
            return EMPTY

        out: set[str] = set()
        for lab in summary.ret_labels:
            if lab.startswith("p"):
                idx = int(lab[1:])
                if idx < len(arg_taints):
                    out |= arg_taints[idx]
            elif lab == "config":
                out.add(T_CONFIG if self.mode == "concrete" else "config")
            elif lab.startswith("glob:"):
                out |= self._global_label(lab[5:])
            elif lab.startswith("src:"):
                tag = lab[4:]
                out.add(tag if self.mode == "concrete" else lab)
            else:
                out.add(lab)
        return frozenset(out)

    def _global_label(self, name: str) -> frozenset:
        if self.mode == "abstract":
            return frozenset({f"glob:{name}"})
        if name in self.state:
            return self.state[name]
        dotted = self.idx.resolve(self.unit, name)
        if dotted and M.CONFIG_NAME_RE.match(dotted):
            return frozenset({T_CONFIG})
        if M.CONFIG_NAME_RE.match(name):
            return frozenset({T_CONFIG})
        return EMPTY

    def _callable_arg_map(self, qname: str, call_node: ast.Call) -> dict[str, str]:
        """把实参里的具名函数绑定到被调函数的形参名（高阶函数透传）。"""
        summary = self.idx.summaries.get(qname)
        if summary is None:
            return {}
        out: dict[str, str] = {}
        for i, a in enumerate(call_node.args):
            if i >= len(summary.params):
                break
            target = self._resolve_callable(a)
            if target and target in self.idx.summaries:
                out[summary.params[i]] = target
        for kw in call_node.keywords:
            if kw.arg:
                target = self._resolve_callable(kw.value)
                if target and target in self.idx.summaries:
                    out[kw.arg] = target
        return out

    def _instantiate_fn(self, qname: str, arg_taints: list[frozenset], call_node: ast.Call) -> None:
        """具体模式下，把高阶算子应用的函数也实例化（sink 定位在调用点）。"""
        if self.mode != "concrete" or qname not in self.idx.summaries:
            return
        if len(self.call_stack) >= MAX_DEPTH or qname in self.call_stack:
            return
        summary = self.idx.summaries[qname]
        seed = {summary.params[i]: arg_taints[i]
                for i in range(min(len(summary.params), len(arg_taints)))}
        site_line = self._stmt_line(call_node)
        sub = _Walker(
            self.engine, unit=self.idx.files[self.idx.func_file[qname]],
            fn=self.idx.functions[qname], mode="concrete", seed=seed,
            entry_name=self.entry_name,
            call_stack=(*self.call_stack, qname),
            call_site_line=site_line,
            call_sites=[*self.call_sites, (self.unit.rel, site_line)],
            param_callables={**self.param_callables, **self._callable_arg_map(qname, call_node)},
        )
        sub.run()

    def _pipe(self, node: ast.Call, dotted: str) -> frozenset:
        """map/filter/sorted/...：迭代源污点穿过，函数参数逐元素应用摘要。"""
        args = [self._eval(a) for a in node.args]
        for kw in node.keywords:
            self._eval(kw.value)
        if not args:
            return EMPTY
        fn_node, iter_taint = node.args[0], args[1] if len(args) > 1 else EMPTY
        out = set(iter_taint)
        fn_dotted = self._resolve_callable(fn_node) if isinstance(fn_node, (ast.Name, ast.Attribute)) else None
        if fn_dotted and fn_dotted in self.idx.summaries:
            summary = self.idx.summaries[fn_dotted]
            if summary.is_sanitizer:
                return EMPTY
            self._instantiate_fn(fn_dotted, [iter_taint], node)
            for lab in summary.ret_labels:
                if lab.startswith("p"):
                    out |= iter_taint
                elif lab.startswith("src:") and self.mode == "concrete":
                    out.add(lab[4:])
                else:
                    out.add(lab)
        elif isinstance(fn_node, ast.Lambda):
            out |= self._lambda_with(fn_node, iter_taint)
        return frozenset(out)

    def _fold(self, node: ast.Call, dotted: str) -> frozenset:
        args = [self._eval(a) for a in node.args]
        for kw in node.keywords:
            self._eval(kw.value)
        out: set[str] = set()
        for t in args[1:]:
            out |= t
        fn_node = node.args[0] if node.args else None
        if fn_node is not None:
            fn_dotted = self._resolve_callable(fn_node) if isinstance(fn_node, (ast.Name, ast.Attribute)) else None
            elem = frozenset(out)
            if fn_dotted and fn_dotted in self.idx.summaries:
                summary = self.idx.summaries[fn_dotted]
                if summary.is_sanitizer:
                    return EMPTY
                self._instantiate_fn(fn_dotted, [elem, elem], node)
                if not summary.is_sanitizer:
                    for lab in summary.ret_labels:
                        if lab.startswith("p"):
                            out |= elem
            elif isinstance(fn_node, ast.Lambda):
                out |= self._lambda_with(fn_node, elem)
        return frozenset(out)

    def _compose(self, node: ast.Call, dotted: str) -> frozenset:
        """compose/pipe 及语料管道助手（map_step/pipeline...）：
        数据实参的污点联合传播；链上出现净化函数则整体净化；
        自定义助手按其函数摘要实例化，使内部 sink 在调用点报告。"""
        leaf = dotted.rsplit(".", 1)[-1]
        for a in node.args:
            target = self._resolve_callable(a) if isinstance(a, (ast.Name, ast.Attribute)) else None
            if target and self.idx.summaries.get(target) and self.idx.summaries[target].is_sanitizer:
                self._eval_args(node)
                return EMPTY
        # 语料/工程里的自定义管道助手：把数据位实参喂给它的摘要
        if leaf not in ("compose", "pipe", "partial"):
            data_taints = [self._eval(a) for a in node.args[1:]] or [self._eval_args(node)]
            if dotted in self.idx.summaries:
                self._instantiate_fn(dotted, data_taints, node)
                summary = self.idx.summaries[dotted]
                if summary.is_sanitizer:
                    return EMPTY
        return self._unknown_propagate(node)

    def _unknown_propagate(self, node: ast.Call) -> frozenset:
        out = self._eval_args(node)
        # 接收者污点（方法调用）
        if isinstance(node.func, ast.Attribute):
            out = self._merge(out, self._eval(node.func.value))
        return out

    def _lambda(self, node: ast.Lambda) -> frozenset:
        # lambda 作为值传递时本身无数据；应用时走 _lambda_with
        return EMPTY

    def _lambda_with(self, node: ast.Lambda, arg_taint: frozenset) -> frozenset:
        saved = dict(self.state)
        try:
            params = [a.arg for a in node.args.args]
            for i, p in enumerate(params):
                self.state[p] = arg_taint
            return self._eval(node.body)
        finally:
            self.state = saved

    def _comp(self, node, is_dict: bool) -> frozenset:
        saved = dict(self.state)
        try:
            out = EMPTY
            for gen in node.generators:
                iter_t = self._eval(gen.iter)
                self._bind(gen.target, iter_t)
                for cond in gen.ifs:
                    self._eval(cond)
            # 推导式元素/值里若调用了具名函数（含嵌套助手），实例化其内部 sink
            if self.mode == "concrete":
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Call):
                        target = None
                        if isinstance(sub.func, ast.Name):
                            target = self._resolve_callable(sub.func)
                        if target and target in self.idx.summaries:
                            arg_taints = [self._eval(a) for a in sub.args]
                            self._instantiate_fn(target, arg_taints, sub)
            if is_dict:
                out = self._merge(self._eval(node.key), self._eval(node.value))
            else:
                out = self._eval(node.elt)
            return out
        finally:
            self.state = saved
