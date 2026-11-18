"""cfg.py —— 在 stdlib ``ast`` 之上自建控制流图。

只使用语法解析库（ast），不依赖任何现成静态分析框架/规则集。
一个 CFG 由若干基本块（Block）组成，块间用 succs 连接；
break/continue、异常处理、with、分支、循环都在此消解。
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field


@dataclass
class Block:
    id: int
    stmts: list = field(default_factory=list)
    succs: list = field(default_factory=list)


@dataclass
class CFG:
    blocks: list[Block]
    entry: int
    # handler 块 id -> 异常名（进入该块时绑定，污点视为干净/未知）
    handler_exc: dict = field(default_factory=dict)

    def reverse_postorder(self) -> list[int]:
        seen: set[int] = set()
        order: list[int] = []

        def dfs(bid: int) -> None:
            if bid in seen:
                return
            seen.add(bid)
            for s in self.blocks[bid].succs:
                dfs(s)
            order.append(bid)

        dfs(self.entry)
        order.reverse()
        return order


class _Builder:
    def __init__(self) -> None:
        self.blocks: list[Block] = []
        self.cur = self._new()
        # (header_id, after_id)
        self._loop_stack: list[tuple[int, int]] = []
        self.handler_exc: dict[int, str] = {}

    def _new(self) -> Block:
        b = Block(len(self.blocks))
        self.blocks.append(b)
        return b

    def _jump(self, b: Block) -> None:
        if b.id not in self.cur.succs:
            self.cur.succs.append(b.id)

    def build(self, stmts: list) -> "_Builder":
        for s in stmts:
            self.stmt(s)
        return self

    def stmt(self, s: ast.stmt) -> None:
        t = type(s)
        if t in (ast.FunctionDef, ast.AsyncFunctionDef):
            # 嵌套函数单独建图；这里保留节点，引擎只求值其装饰器/默认值
            self.cur.stmts.append(s)
            return
        if t is ast.If:
            return self._if(s)
        if t in (ast.While, ast.For, ast.AsyncFor):
            return self._loop(s)
        if t is ast.Try:
            return self._try(s)
        if t in (ast.With, ast.AsyncWith):
            return self._with(s)
        if t is ast.Break:
            self._jump(self.blocks[self._loop_stack[-1][1]])
            self.cur = self._new()
            return
        if t is ast.Continue:
            self._jump(self.blocks[self._loop_stack[-1][0]])
            self.cur = self._new()
            return
        if t in (ast.Return, ast.Raise):
            self.cur.stmts.append(s)
            self.cur = self._new()  # 终结块，无 fall-through
            return
        self.cur.stmts.append(s)

    def _if(self, s: ast.If) -> None:
        self.cur.stmts.append(s)
        head = self.cur
        merge = self._new()
        body = self._new()
        head.succs = [body.id]
        self.cur = body
        self.build(s.body)
        self._jump(merge)
        if s.orelse:
            orelse = self._new()
            head.succs.append(orelse.id)
            self.cur = orelse
            self.build(s.orelse)
            self._jump(merge)
        else:
            head.succs.append(merge.id)
        self.cur = merge

    def _loop(self, s) -> None:
        self.cur.stmts.append(s)
        head = self.cur
        body = self._new()
        after = self._new()
        head.succs = [body.id, after.id]
        self._loop_stack.append((head.id, after.id))
        self.cur = body
        self.build(s.body)
        self._jump(head)
        self._loop_stack.pop()
        # else 子句语义近似：直接并入 after 块
        if s.orelse:
            self.cur = after
            self.build(s.orelse)
        self.cur = after

    def _try(self, s: ast.Try) -> None:
        self.cur.stmts.append(s)
        head = self.cur
        merge = self._new()
        body = self._new()
        head.succs = [body.id]
        self.cur = body
        self.build(s.body)
        self._jump(merge)
        for h in s.handlers:
            hb = self._new()
            head.succs.append(hb.id)
            if h.name:
                self.handler_exc[hb.id] = h.name
            self.cur = hb
            self.build(h.body)
            self._jump(merge)
        if s.orelse:
            ob = self._new()
            head.succs.append(ob.id)
            self.cur = ob
            self.build(s.orelse)
            self._jump(merge)
        # finally 直接并入汇合块（所有路径都经过它）
        if s.finalbody:
            self.cur = merge
            self.build(s.finalbody)
            new_after = self._new()
            self._jump(new_after)
            self.cur = new_after
        else:
            self.cur = merge

    def _with(self, s) -> None:
        self.cur.stmts.append(s)
        bodyb = self._new()
        self.cur.succs = [bodyb.id]
        self.cur = bodyb
        self.build(s.body)
        merge = self._new()
        self._jump(merge)
        self.cur = merge


def build_cfg(stmts: list) -> CFG:
    b = _Builder().build(stmts)
    # 丢弃尾部空块之外保留全部（空块不影响正确性）
    return CFG(blocks=b.blocks, entry=0, handler_exc=dict(b.handler_exc))
