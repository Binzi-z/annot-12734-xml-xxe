"""cache.py —— 基于内容哈希的增量缓存。

缓存键只含文件 SHA-256 与分析器版本，不含时间戳：
同样的内容 + 同样的分析器必然得到同样的结果，因此增量与全量一致。
跨模块依赖通过导入图反向闭包失效（被依赖模块变更，依赖方一并重算）。
"""
from __future__ import annotations

import hashlib
import json
import os

from .index import RepoIndex

CACHE_VERSION = 1


def file_hash(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


class IncrementalCache:
    def __init__(self, cache_path: str) -> None:
        self.path = cache_path
        self.doc: dict = {"version": CACHE_VERSION, "analyzer": "1.0.0", "files": {}}
        self.dirty = False
        if os.path.exists(cache_path):
            try:
                with open(cache_path, encoding="utf-8") as fh:
                    doc = json.load(fh)
                if doc.get("version") == CACHE_VERSION:
                    self.doc = doc
            except (json.JSONDecodeError, OSError):
                pass

    def plan(self, index: RepoIndex, hashes: dict[str, str]) -> tuple[set[str], set[str]]:
        """返回 (需要分析的文件 rel 集合, 可复用缓存的文件 rel 集合)。"""
        cached = self.doc["files"]
        changed: set[str] = set()
        for rel, digest in hashes.items():
            old = cached.get(rel)
            if old is None or old.get("hash") != digest:
                changed.add(rel)
        work, reusable = self._closure(index, changed, hashes)
        return work, reusable

    def plan_from_cache(self, hashes: dict[str, str]) -> tuple[set[str], set[str]]:
        """无语法索引时的计划：直接用缓存里存的导入目标做反向闭包，
        避免为了算增量而重新解析整个仓库。"""
        cached = self.doc["files"]
        changed = {rel for rel, digest in hashes.items()
                   if rel not in cached or cached[rel].get("hash") != digest}
        # 模块名 -> 依赖它的文件 rel
        reverse: dict[str, set[str]] = {}
        rel_module = {rel: rel[:-3].replace("/", ".") for rel in hashes}
        for rel, entry in cached.items():
            for target in entry.get("imports", []):
                for mod, mrel in rel_module.items():
                    if mod == target or mod.startswith(target + ".") or mod.split(".")[0] == target.split(".")[0]:
                        reverse.setdefault(mod, set()).add(rel)
        work = set(changed)
        stack = list(changed)
        while stack:
            rel = stack.pop()
            mod = rel_module.get(rel)
            if not mod:
                continue
            for dep in reverse.get(mod, ()):  # noqa: SIM118
                if dep not in work:
                    work.add(dep)
                    stack.append(dep)
        return work, set(hashes) - work

    def _closure(self, index: RepoIndex, changed: set[str], hashes: dict[str, str]):
        # 导入图反向闭包：依赖了变更模块的文件也要重算
        reverse: dict[str, set[str]] = {}
        for unit in index.files.values():
            for target in unit.imports.values():
                mod = target.split(".")[0]
                # 映射到仓库内模块
                for m in index.modules:
                    if m == target or m.startswith(target + ".") or m.split(".")[0] == mod:
                        reverse.setdefault(m, set()).add(unit.rel)
        work = set(changed)
        stack = list(changed)
        while stack:
            rel = stack.pop()
            unit = index.files.get(rel)
            if not unit:
                continue
            for dep in reverse.get(unit.module, ()):  # noqa: SIM118
                if dep not in work:
                    work.add(dep)
                    stack.append(dep)
        return work, set(index.files) - work

    def cached_summaries(self) -> dict[str, dict]:
        return {rel: entry.get("summaries", {})
                for rel, entry in self.doc["files"].items() if entry.get("summaries")}

    def cached_findings(self, rel: str) -> list[dict]:
        return self.doc["files"].get(rel, {}).get("findings", [])

    def update(self, hashes: dict[str, str], findings_by_file: dict[str, list[dict]],
               imports_by_file: dict[str, list[str]] | None = None,
               summaries_by_file: dict[str, dict] | None = None,
               touched: set[str] | None = None) -> None:
        """只重写本次触及（touched）的文件条目；未变更条目原样保留，
        避免无变更增量时把整个大缓存重新序列化。"""
        touched = touched if touched is not None else set(hashes)
        if touched or any(rel not in hashes for rel in self.doc["files"]):
            self.dirty = True
        for rel in touched:
            if rel not in hashes:
                continue
            digest = hashes[rel]
            prev = self.doc["files"].get(rel, {})
            self.doc["files"][rel] = {
                "hash": digest,
                "findings": findings_by_file.get(rel, prev.get("findings", [])),
                "imports": (imports_by_file or {}).get(rel, prev.get("imports", [])),
                "summaries": (summaries_by_file or {}).get(rel, prev.get("summaries", {})),
            }
        # 删除已不存在的文件
        for rel in list(self.doc["files"]):
            if rel not in hashes:
                del self.doc["files"][rel]

    def save(self) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(self.doc, fh, ensure_ascii=False, indent=1)
