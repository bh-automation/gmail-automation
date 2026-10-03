#!/usr/bin/env python3
"""Static gate G4/G5/G6: no code path in src/ may reach a forbidden Gmail capability.

AST-based (robust against formatting tricks) plus a regex pass identical to the CI grep.
Flags: attribute access or method definitions named send/delete/batchDelete/trash/...,
getattr()/attrgetter() with such names, __import__/importlib reflection on googleapiclient
internals, and any use of the full-mail scope string outside FORBIDDEN_SCOPES.

The only exemption: `guard_self_test()` in src/gmail_client.py, which proves at runtime
that these attributes are BLOCKED (it accesses them inside try/except PolicyViolation).
"""

from __future__ import annotations

import ast
import io
import re
import sys
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_NAMES = {
    "send",
    "delete",
    "batchDelete",
    "trash",
    "untrash",
    "batchModify",
    "insert",
    "import_",
    "forwardingAddresses",
    "filters",
    "settings",
    "sendAs",
    "delegates",
    "watch",
    "stop",
}
FULL_SCOPE = "https://mail.google.com/"
EXEMPT_FUNCS = {("gmail_client.py", "guard_self_test")}
GREP = re.compile(r"messages\(\)\.send|drafts\(\)\.send|messages\(\)\.delete|threads\(\)\.delete|batchDelete")


def display(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


class Scanner(ast.NodeVisitor):
    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[str] = []
        self.func_stack: list[str] = []
        self.in_forbidden_scopes = False

    def _exempt(self) -> bool:
        return any((self.path.name, f) in EXEMPT_FUNCS for f in self.func_stack)

    def _flag(self, node: ast.AST, msg: str) -> None:
        if not self._exempt():
            self.findings.append(f"{display(self.path)}:{getattr(node, 'lineno', '?')}: {msg}")

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        if node.name in FORBIDDEN_NAMES:
            self._flag(node, f"method definition '{node.name}'")
        self.func_stack.append(node.name)
        self.generic_visit(node)
        self.func_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]  # noqa: N815

    def visit_Attribute(self, node: ast.Attribute) -> None:  # noqa: N802
        if node.attr in FORBIDDEN_NAMES:
            self._flag(node, f"attribute access '.{node.attr}'")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        fn = node.func
        name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
        if name in {"getattr", "attrgetter", "methodcaller", "__getattribute__"}:
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value in FORBIDDEN_NAMES:
                    self._flag(node, f"reflective access to '{arg.value}'")
        if name in {"__import__", "import_module"}:
            self._flag(node, "dynamic import")
        if name == "__getattribute__" and self.path.name != "gmail_client.py":
            self._flag(node, "__getattribute__ bypass outside the adapter")
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        targets = {t.id for t in node.targets if isinstance(t, ast.Name)}
        prev = self.in_forbidden_scopes
        self.in_forbidden_scopes = "FORBIDDEN_SCOPES" in targets
        self.generic_visit(node)
        self.in_forbidden_scopes = prev

    def visit_Constant(self, node: ast.Constant) -> None:  # noqa: N802
        if isinstance(node.value, str) and FULL_SCOPE in node.value and not self.in_forbidden_scopes:
            self._flag(node, "full-mail scope string outside FORBIDDEN_SCOPES")
        if isinstance(node.value, str) and node.value.startswith("_g_") and self.path.name != "gmail_client.py":
            self._flag(node, "reference to guarded-resource internals")


def code_only_lines(text: str) -> dict[int, str]:
    """Source lines with string literals and comments removed (grep runs on real code only)."""
    lines: dict[int, list[str]] = {}
    for tok in tokenize.generate_tokens(io.StringIO(text).readline):
        if tok.type in (tokenize.STRING, tokenize.COMMENT, tokenize.FSTRING_MIDDLE):
            continue
        lines.setdefault(tok.start[0], []).append(tok.string)
    return {n: "".join(parts) for n, parts in lines.items()}


def exempt_lines(tree: ast.AST, path: Path) -> set[int]:
    out: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and (path.name, node.name) in EXEMPT_FUNCS:
            out.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))
    return out


def scan_paths(paths: list[Path]) -> list[str]:
    findings: list[str] = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError as exc:
            findings.append(f"{path}: unparsable ({exc.msg})")
            continue
        sc = Scanner(path)
        sc.visit(tree)
        findings.extend(sc.findings)
        skip = exempt_lines(tree, path)
        for i, code in sorted(code_only_lines(text).items()):
            m = GREP.search(code)
            if m and i not in skip:
                findings.append(f"{display(path)}:{i}: grep match '{m.group(0)}'")
    return findings


def main(argv: list[str]) -> int:
    targets = [Path(a).resolve() for a in argv] or sorted((ROOT / "src").rglob("*.py"))
    files = [p for t in targets for p in ([t] if t.is_file() else sorted(t.rglob("*.py")))]
    findings = scan_paths(files)
    if findings:
        print("FORBIDDEN_SCAN = FAIL")
        for f in findings:
            print("  " + f)
        return 1
    print(f"FORBIDDEN_SCAN = PASS ({len(files)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
