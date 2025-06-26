"""Minimal restricted Python subset with move-only semantics."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Dict

from .errors import SandboxError


class OwnershipError(SandboxError):
    """Raised when using a moved value."""


@dataclass
class _Owned:
    value: Any
    moved: bool = False


class RestrictedExec:
    """Evaluate a tiny Python subset tracking ownership."""

    def __init__(self) -> None:
        self._env: Dict[str, _Owned] = {}

    _binops = {
        ast.Add: lambda a, b: a + b,
        ast.Sub: lambda a, b: a - b,
        ast.Mult: lambda a, b: a * b,
        ast.Div: lambda a, b: a / b,
    }

    def _eval_expr(self, node: ast.AST) -> Any:
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            if node.id not in self._env:
                raise NameError(node.id)
            slot = self._env[node.id]
            if slot.moved:
                raise OwnershipError(f"{node.id} has been moved")
            return slot.value
        if isinstance(node, ast.BinOp) and type(node.op) in self._binops:
            left = self._eval_expr(node.left)
            right = self._eval_expr(node.right)
            return self._binops[type(node.op)](left, right)
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "move":
                if len(node.args) != 1 or not isinstance(node.args[0], ast.Name):
                    raise SyntaxError("move() expects a variable")
                name = node.args[0].id
                if name not in self._env:
                    raise NameError(name)
                slot = self._env[name]
                if slot.moved:
                    raise OwnershipError(f"{name} has been moved")
                slot.moved = True
                return slot.value
            raise SyntaxError("function calls not allowed")
        raise SyntaxError("unsupported expression")

    def exec(self, src: str) -> Any:
        """Execute source code. Returns last expression value."""
        tree = ast.parse(src, mode="exec")
        last_val = None
        for stmt in tree.body:
            if isinstance(stmt, ast.Assign):
                if len(stmt.targets) != 1 or not isinstance(stmt.targets[0], ast.Name):
                    raise SyntaxError("only simple assignments allowed")
                val = self._eval_expr(stmt.value)
                self._env[stmt.targets[0].id] = _Owned(val)
            elif isinstance(stmt, ast.Expr):
                last_val = self._eval_expr(stmt.value)
            else:
                raise SyntaxError("only assignments and expressions allowed")
        return last_val


__all__ = ["RestrictedExec", "OwnershipError"]
