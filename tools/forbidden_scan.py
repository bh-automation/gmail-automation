#!/usr/bin/env python3
"""Static gate G4/G5/G6: no code path may reach a forbidden Gmail capability.

Scans src/ and tools/ by default (AST, robust against formatting tricks) plus a regex pass on
real code (strings/comments removed). Flags:

* attribute access or method definitions named send/delete/batchDelete/trash/...;
* reflection: getattr/attrgetter/methodcaller with a forbidden or NON-CONSTANT name,
  `__getattr__`/`__getattribute__`/`__dict__`/`__builtins__`, `vars`/`globals`,
  `eval`/`exec`/`compile`, `__import__`/`import_module` - outside the adapter;
* transport and credential modules (googleapiclient.discovery/http, google.auth.transport,
  google.oauth2, google_auth_httplib2, requests, httplib2, urllib.request, urllib3, http.client,
  socket, ssl, aiohttp, httpx) outside the adapter/auth modules - a second, unguarded service
  or raw REST call cannot be written anywhere else - and re-imports of such objects or of
  private names from project modules (`from .gmail_client import httplib2`);
* code-loading escape hatches (importlib.util, runpy, pkgutil, inspect, ctypes, builtins,
  subprocess, sys.modules) and reflective builtins used as values (`g = getattr`);
* string constants (also constant-folded concatenations, joins and f-strings) containing the
  full-mail scope or a raw Gmail REST URL.

Exemptions are explicit: `guard_self_test()` in src/gmail_client.py (proves at runtime that the
attributes are BLOCKED) and the definitions of the forbidden-scope lists themselves.
"""

from __future__ import annotations

import ast
import io
import re
import sys
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TARGETS = ("src", "tools")
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
FULL_HOST = "mail.google.com"
RAW_URL_RE = re.compile(r"mail\.google\.com|gmail\.googleapis\.com|googleapis\.com/gmail|gmail\.mtls\.googleapis")
# All exemptions are bound to exact repository paths (a planted "auth.py" elsewhere gets none).
ADAPTER = "src/gmail_client.py"
SELF = "tools/forbidden_scan.py"
EXEMPT_FUNCS = {(ADAPTER, "guard_self_test")}
EXEMPT_ASSIGNMENTS = {
    ("src/auth.py", "FORBIDDEN_SCOPES"),
    (ADAPTER, "GMAIL_HOSTS"),
    (SELF, "FULL_SCOPE"),
    (SELF, "FULL_HOST"),
    (SELF, "RAW_URL_RE"),
}
ADAPTER_FILES = {ADAPTER, "src/auth.py"}  # the only modules that may hold transports/credentials
RESTRICTED_MODULES = (
    "googleapiclient.discovery",
    "googleapiclient.http",
    "googleapiclient._auth",
    "google.auth.transport",
    "google.oauth2",
    "google_auth_httplib2",
    "google_auth_oauthlib",
    "requests",
    "httplib2",
    "urllib.request",
    "urllib3",
    "http.client",
    "socket",
    "ssl",
    "aiohttp",
    "httpx",
    "pycurl",
    # reflection / code loading / process escape hatches
    "importlib.util",
    "importlib.machinery",
    "importlib.import_module",
    "runpy",
    "pkgutil",
    "inspect",
    "ctypes",
    "marshal",
    "builtins",
    "subprocess",
    "multiprocessing",
    "operator.attrgetter",
    "operator.methodcaller",
    "sys.modules",
)
# Exception-type imports that are harmless without a credential object; fixed tool subprocesses.
FILE_ALLOWED_MODULES = {
    "src/retry.py": {"googleapiclient.errors", "httplib2", "socket", "ssl", "http.client"},
    "src/cli.py": {"subprocess"},
    "tools/secret_scan.py": {"subprocess"},
}
BARE_PACKAGES = {"googleapiclient", "google", "google.auth", "importlib"}  # sub-modules would bypass the gate
# Names that must not be re-imported from project modules (transport objects, credential factories).
INTERNAL_RESTRICTED = {
    "httplib2",
    "socket",
    "ssl",
    "http",
    "requests",
    "urllib3",
    "build",
    "AuthorizedHttp",
    "AuthorizedSession",
    "Credentials",
    "Request",
    "GuardedHttp",
    "load_credentials",
    "make_refresher",
    "build_gmail_service",
    "run_consent_flow",
}
INTERNAL_ALLOWED = {
    "src/cli.py": {"load_credentials", "make_refresher", "build_gmail_service", "run_consent_flow"},
    "src/auth.py": {"GuardedHttp"},
}
REFLECTION_CALLS = {"eval", "exec", "compile", "vars", "globals", "__import__", "import_module", "breakpoint"}
REFLECTIVE_BUILTINS = {"getattr", "setattr", "delattr", "eval", "exec", "compile", "vars", "globals", "locals"}
DUNDER_ATTRS = {"__getattr__", "__getattribute__", "__dict__", "__builtins__", "__subclasses__", "__globals__"}
GREP = re.compile(r"messages\(\)\.send|drafts\(\)\.send|messages\(\)\.delete|threads\(\)\.delete|batchDelete")


def display(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def _restricted(module: str) -> bool:
    return any(module == m or module.startswith(m + ".") for m in RESTRICTED_MODULES)


def fold_str(node: ast.AST) -> str | None:
    """Constant-fold string expressions: literals, '+', implicit concat, ''.join([...]), f-strings."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = fold_str(node.left), fold_str(node.right)
        return left + right if left is not None and right is not None else None
    if isinstance(node, ast.JoinedStr):
        parts = [fold_str(v) for v in node.values]
        return "".join(p for p in parts if p is not None) if all(p is not None for p in parts) else None
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and len(node.args) == 1
        and isinstance(node.args[0], ast.List | ast.Tuple)
    ):
        sep = fold_str(node.func.value)
        items = [fold_str(e) for e in node.args[0].elts]
        if sep is not None and all(i is not None for i in items):
            return sep.join(i for i in items if i is not None)
    return None


class Scanner(ast.NodeVisitor):
    def __init__(self, path: Path) -> None:
        self.path = path
        self.rel = display(path)
        self.findings: list[str] = []
        self.func_stack: list[str] = []
        self.exempt_assignment = False
        self.adapter = self.rel in ADAPTER_FILES
        self.call_funcs: set[int] = set()

    def _exempt(self) -> bool:
        return any((self.rel, f) in EXEMPT_FUNCS for f in self.func_stack)

    def _flag(self, node: ast.AST, msg: str) -> None:
        if not self._exempt():
            self.findings.append(f"{display(self.path)}:{getattr(node, 'lineno', '?')}: {msg}")

    # -- definitions -----------------------------------------------------------------
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        if node.name in FORBIDDEN_NAMES:
            self._flag(node, f"method definition '{node.name}'")
        self.func_stack.append(node.name)
        self.generic_visit(node)
        self.func_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]  # noqa: N815

    # -- imports ---------------------------------------------------------------------
    def _check_module(self, node: ast.AST, module: str) -> None:
        if self.adapter or module in FILE_ALLOWED_MODULES.get(self.rel, set()):
            return
        if _restricted(module):
            self._flag(node, f"transport/credential module '{module}' outside the adapter")

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            self._check_module(node, alias.name)
            if alias.name in BARE_PACKAGES and not self.adapter:
                self._flag(node, f"bare import '{alias.name}' (sub-modules would bypass the import gate)")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        module = node.module or ""
        internal = node.level > 0 or module == "src" or module.startswith("src.")
        if node.level == 0:
            self._check_module(node, module)
            for alias in node.names:
                self._check_module(node, f"{module}.{alias.name}")
        if internal and not self.adapter:
            for alias in node.names:
                name = alias.name
                private = name.startswith("_") and not (name.startswith("__") and name.endswith("__"))
                allowed = name in INTERNAL_ALLOWED.get(self.rel, set())
                if (private or name in INTERNAL_RESTRICTED) and not allowed:
                    self._flag(node, f"re-import of '{name}' from a project module (transport/credential leak)")
        self.generic_visit(node)

    # -- attributes / names ----------------------------------------------------------
    def visit_Attribute(self, node: ast.Attribute) -> None:  # noqa: N802
        if node.attr in FORBIDDEN_NAMES:
            self._flag(node, f"attribute access '.{node.attr}'")
        if node.attr == "modules" and isinstance(node.value, ast.Name) and node.value.id == "sys":
            self._flag(node, "sys.modules access (module table reflection)")
        if node.attr in {"_root", "_g_inner"} and self.rel != ADAPTER:
            self._flag(node, f"access to adapter internals '.{node.attr}'")
        if node.attr in DUNDER_ATTRS and self.rel != ADAPTER:
            self._flag(node, f"reflective dunder '.{node.attr}' outside the adapter")
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:  # noqa: N802
        if node.id == "__builtins__":
            self._flag(node, "access to __builtins__")
        if node.id in REFLECTIVE_BUILTINS and id(node) not in self.call_funcs and self.rel != ADAPTER:
            self._flag(node, f"reflective builtin '{node.id}' used as a value (aliasing)")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        fn = node.func
        self.call_funcs.add(id(fn))
        name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
        if name in {"getattr", "attrgetter", "methodcaller", "__getattribute__", "__getattr__", "setattr", "hasattr"}:
            name_args = node.args[1:2] if name in {"getattr", "setattr", "hasattr"} else node.args[:1]
            if name in {"attrgetter", "methodcaller"}:
                name_args = node.args
            for arg in name_args:
                value = fold_str(arg)
                if value is None:
                    if self.rel != ADAPTER:
                        self._flag(node, f"{name}() with a non-constant attribute name")
                elif any(part in FORBIDDEN_NAMES for part in value.split(".")):
                    self._flag(node, f"reflective access to '{value}'")
        if name in REFLECTION_CALLS and (name in {"__import__", "import_module"} or isinstance(fn, ast.Name)):
            self._flag(node, f"dynamic code / reflection '{name}()'")
        self.generic_visit(node)

    # -- strings ---------------------------------------------------------------------
    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        targets = {t.id for t in node.targets if isinstance(t, ast.Name)}
        prev = self.exempt_assignment
        self.exempt_assignment = any((self.rel, t) in EXEMPT_ASSIGNMENTS for t in targets)
        self.generic_visit(node)
        self.exempt_assignment = prev

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:  # noqa: N802
        prev = self.exempt_assignment
        self.exempt_assignment = isinstance(node.target, ast.Name) and (
            (self.rel, node.target.id) in EXEMPT_ASSIGNMENTS
        )
        self.generic_visit(node)
        self.exempt_assignment = prev

    def _check_string(self, node: ast.AST, value: str) -> None:
        if self.exempt_assignment:
            return
        if FULL_SCOPE in value or FULL_HOST in value:
            self._flag(node, "full-mail scope / host string outside FORBIDDEN_SCOPES")
        elif RAW_URL_RE.search(value):
            self._flag(node, "raw Gmail REST URL (all Gmail traffic must go through the guarded adapter)")
        if value.startswith("_g_") and self.rel not in {ADAPTER, SELF}:
            self._flag(node, "reference to guarded-resource internals")

    def visit_Expr(self, node: ast.Expr) -> None:  # noqa: N802
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            return  # docstring / bare string statement: no runtime effect
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:  # noqa: N802
        folded = fold_str(node)
        if folded is not None:
            self._check_string(node, folded)
            return  # parts are covered by the folded value
        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:  # noqa: N802
        folded = fold_str(node)
        if folded is not None:
            self._check_string(node, folded)
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:  # noqa: N802
        if isinstance(node.value, str):
            self._check_string(node, node.value)


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
        if isinstance(node, ast.FunctionDef) and (display(path), node.name) in EXEMPT_FUNCS:
            out.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))
    return out


def scan_paths(paths: list[Path]) -> list[str]:
    findings: list[str] = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError as exc:
            findings.append(f"{display(path)}: unparsable ({exc.msg})")
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
    targets = [Path(a).resolve() for a in argv] or [ROOT / t for t in DEFAULT_TARGETS]
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
