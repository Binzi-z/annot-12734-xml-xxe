"""index.py —— 仓库级语法索引：解析所有 .py 文件，建立模块/函数/导入表。"""
from __future__ import annotations

import ast
import os

from .model import FuncSummary


class FileUnit:
    def __init__(self, path: str, rel: str, source: str, tree: ast.Module):
        self.path = path
        self.rel = rel.replace(os.sep, "/")
        self.source = source
        self.tree = tree
        self.lines = source.splitlines()
        self.module = rel[:-3].replace(os.sep, ".") if rel.endswith(".py") else rel
        if self.module.endswith(".__init__"):
            self.module = self.module[: -len(".__init__")]
        # 局部名 -> 完整 dotted 名（import 绑定）
        self.imports: dict[str, str] = {}
        # 本模块定义的函数 局部名 -> qname
        self.funcs: dict[str, str] = {}
        # qname -> 定义节点
        self.func_nodes: dict[str, ast.FunctionDef] = {}
        # 模块级赋值 名 -> 节点（parser 配置对象等）
        self.globals: dict[str, ast.Assign] = {}


class RepoIndex:
    def __init__(self) -> None:
        self.files: dict[str, FileUnit] = {}          # rel -> unit
        self.modules: dict[str, FileUnit] = {}        # module name -> unit
        self.functions: dict[str, ast.FunctionDef] = {}
        self.summaries: dict[str, FuncSummary] = {}
        # qname -> 定义所在文件 rel
        self.func_file: dict[str, str] = {}

    def add_file(self, path: str, root: str) -> FileUnit:
        rel = os.path.relpath(path, root)
        with open(path, "r", encoding="utf-8-sig") as fh:
            source = fh.read()
        tree = ast.parse(source, filename=rel)
        # 挂父节点指针，供分析器取“语句起始行”等
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                child._parent = parent
        unit = FileUnit(path, rel, source, tree)
        self.files[unit.rel] = unit
        self.modules[unit.module] = unit

        for node in tree.body:
            if isinstance(node, ast.Import):
                for a in node.names:
                    unit.imports[a.asname or a.name.split(".")[0]] = a.name
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                for a in node.names:
                    unit.imports[a.asname or a.name] = f"{mod}.{a.name}" if mod else a.name
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                q = f"{unit.module}.{node.name}"
                unit.funcs[node.name] = q
                unit.func_nodes[q] = node
                self.functions[q] = node
                self.func_file[q] = unit.rel
            elif isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        unit.globals[t.id] = node

        # 嵌套函数/方法：用所属函数的 qname 限定注册（过程间调用与高阶算子需要）
        for top in tree.body:
            if isinstance(top, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for sub in ast.walk(top):
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)) and sub is not top:
                        q = f"{unit.module}.{top.name}.{sub.name}"
                        unit.func_nodes[q] = sub
                        self.functions[q] = sub
                        self.func_file[q] = unit.rel
        return unit

    def _collect_nested(self, parent: ast.FunctionDef, parent_q: str, unit: FileUnit) -> None:
        for node in ast.walk(parent):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node is not parent:
                q = f"{parent_q}.{node.name}"
                unit.func_nodes[q] = node
                self.functions[q] = node
                self.func_file[q] = unit.rel

    # -- 名称解析 -------------------------------------------------------------
    def resolve(self, unit: FileUnit, name: str) -> str | None:
        """把局部名解析成 dotted 路径（可能仍是未绑定模块，原样返回）。"""
        if name in unit.imports:
            return unit.imports[name]
        if name in unit.funcs:
            return unit.funcs[name]
        return None

    def resolve_chain(self, unit: FileUnit, node: ast.AST) -> str:
        """把 Name/Attribute 链解析为 dotted 字符串；无法解析的段保留原名。"""
        parts: list[str] = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            base = self.resolve(unit, cur.id) or cur.id
            parts.append(base)
        elif isinstance(cur, ast.Call):
            parts.append(self.resolve_chain(unit, cur.func))
        else:
            parts.append(ast.unparse(cur))
        return ".".join(reversed(parts))

    def resolve_func(self, unit: FileUnit, call: ast.Call) -> str:
        return self.resolve_chain(unit, call.func)
