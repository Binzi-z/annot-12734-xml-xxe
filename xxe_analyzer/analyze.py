"""analyze.py —— 分析驱动器：扫描目录、全量/增量分析、SARIF 落盘。"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from .cache import IncrementalCache, file_hash
from .engine import Engine
from .index import RepoIndex
from .sarif import to_sarif, to_simple_json


def discover_python(root: str) -> list[str]:
    # 测试/性能夹具默认不与产品代码混扫（它们故意含大量漏洞样本）；
    # 但显式把夹具目录作为扫描根（路径里含 benchmark/scale）时仍扫描，供验收/性能基准使用。
    root_norm = root.replace("\\", "/").rstrip("/")
    scan_fixtures = any(seg in ("benchmark", "scale") for seg in root_norm.split("/"))
    skip_dirs = {".git", "__pycache__", ".pytest_cache", ".venv", "venv", "tests", "test"}
    if not scan_fixtures:
        skip_dirs |= {"benchmark", "scale"}
    out: list[str] = []
    for dirpath, dirnames, names in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for n in names:
            if n.endswith(".py"):
                out.append(os.path.join(dirpath, n))
    return sorted(out)


def analyze_paths(paths: list[str], root: str) -> list:
    index = RepoIndex()
    for p in paths:
        index.add_file(p, root)
    engine = Engine(index)
    engine.build_parser_safety()
    engine.compute_summaries()
    return engine.run_concrete()


def analyze_paths_restricted(all_paths: list[str], work_paths: list[str], root: str,
                             cached_summaries: dict | None = None):
    """全仓库建索引与摘要（跨模块完整），但只重新实例化 work_paths 内的入口。

    未变更文件的函数摘要直接从缓存还原，不重跑 CFG；变更文件才重新计算。
    未变更文件的发现从缓存原样取回，保证增量与全量结果一致。
    返回 (findings, summaries_by_file)。
    """
    index = RepoIndex()
    for p in all_paths:
        index.add_file(p, root)
    work_rels = {os.path.relpath(p, root).replace(os.sep, "/") for p in work_paths}
    engine = Engine(index)
    engine.build_parser_safety()
    engine.compute_summaries(cached=cached_summaries)
    findings = engine.run_concrete(only_files=work_rels)
    imports_by_file = {rel: sorted(set(unit.imports.values())) for rel, unit in index.files.items()}
    return findings, engine.export_summaries(), imports_by_file


def finding_to_dict(f) -> dict:
    return {
        "rule_id": f.rule_id, "file": f.file, "line": f.line,
        "sink_name": f.sink_name, "sources": list(f.sources),
        "path": list(f.path), "entry": f.entry,
    }


def dict_to_finding(d: dict):
    from .model import Finding
    return Finding(
        rule_id=d["rule_id"], file=d["file"], line=d["line"],
        sink_name=d["sink_name"], sources=tuple(d["sources"]),
        path=tuple(d["path"]), entry=d["entry"],
    )


def run(root: str, output: str, fmt: str = "sarif",
        cache_path: str | None = None, incremental: bool = False) -> dict:
    started = time.perf_counter()
    all_paths = discover_python(root)
    hashes = {os.path.relpath(p, root).replace(os.sep, "/"): file_hash(p) for p in all_paths}

    cache = IncrementalCache(cache_path) if incremental and cache_path else None
    reusable: set[str] = set()
    work_paths = all_paths
    imports_by_file: dict[str, list[str]] = {}
    if cache is not None:
        # 用缓存内的导入图直接算增量计划，避免重复全仓库 CFG 分析
        work_rel, reusable = cache.plan_from_cache(hashes)
        work_paths = [p for p in all_paths
                      if os.path.relpath(p, root).replace(os.sep, "/") in work_rel]

    # 全仓库解析建索引（保证跨模块摘要/调用图完整）；
    # 但只有 work_paths 对应的入口会在本次重新实例化，其余结果取自缓存。
    summaries_by_file: dict[str, list] = {}
    if cache is not None and not work_rel:
        # 快速路径：没有任何文件变更，直接从缓存还原全部发现，
        # 跳过 AST 解析与 CFG 分析（增量 <15s 的关键）。
        findings = []
        for rel in hashes:
            for d in cache.cached_findings(rel):
                findings.append(dict_to_finding(d))
    elif cache is not None:
        findings, summaries_by_file, imports_by_file = analyze_paths_restricted(
            all_paths, work_paths, root, cached_summaries=cache.cached_summaries())
    else:
        findings = analyze_paths(all_paths, root)

    findings_by_file: dict[str, list[dict]] = {}
    for f in findings:
        findings_by_file.setdefault(f.file, []).append(finding_to_dict(f))

    # 复用未变更文件的缓存结果（快速路径已直接还原，跳过）
    if cache is not None and work_rel:
        for rel in reusable:
            for d in cache.cached_findings(rel):
                findings.append(dict_to_finding(d))
        cache.update(hashes, findings_by_file, imports_by_file,
                     summaries_by_file, touched=set(hashes) - reusable)
        if cache.dirty:
            cache.save()

    findings.sort(key=lambda f: (f.file, f.line, f.rule_id))
    elapsed = time.perf_counter() - started

    doc = to_sarif(findings) if fmt == "sarif" else to_simple_json(findings)
    if output == "-":
        json.dump(doc, sys.stdout, ensure_ascii=False, indent=1)
        sys.stdout.write("\n")
    else:
        os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)
        with open(output, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False, indent=1)
    return {"findings": len(findings), "elapsed_sec": round(elapsed, 3),
            "files": len(all_paths), "reanalyzed": len(work_paths),
            "reused": len(reusable)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="自建 CFG 的 Python XXE 污点分析器（仅用 stdlib ast）")
    ap.add_argument("root", nargs="?", default=".", help="待扫描代码根目录")
    ap.add_argument("-o", "--output", default="findings.sarif", help="输出文件（- 表示 stdout）")
    ap.add_argument("--format", choices=["sarif", "json"], default="sarif")
    ap.add_argument("--incremental", action="store_true", help="启用内容哈希增量缓存")
    ap.add_argument("--cache", default=".xxe-cache/cache.json", help="增量缓存路径")
    ap.add_argument("--check", action="store_true", help="有发现时以退出码 1 失败（CI 门禁）")
    args = ap.parse_args(argv)
    stats = run(args.root, args.output, args.format, args.cache, args.incremental)
    print(f"[xxe-analyzer] files={stats['files']} reanalyzed={stats['reanalyzed']} "
          f"reused={stats['reused']} findings={stats['findings']} "
          f"elapsed={stats['elapsed_sec']}s", file=sys.stderr)
    if args.check and stats["findings"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
