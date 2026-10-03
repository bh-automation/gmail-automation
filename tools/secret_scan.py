#!/usr/bin/env python3
"""Gate G3: no credentials, OAuth tokens, .env files or private keys in the project tree.

Checks file names AND content. Test fixtures must build fake secrets at runtime
(string concatenation) so that the repository itself always scans clean.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {
    ".git",
    ".venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "build",
    "dist",
}
NAME_PATTERNS = [
    re.compile(p)
    for p in (
        r"^credentials.*\.json$",
        r"^client_secret.*\.json$",
        r"^token.*\.json$",
        r"^\.env(\..*)?$",
        r".*\.pem$",
        r".*\.p12$",
    )
]
NAME_ALLOW = {".env.example"}
CONTENT_PATTERNS = {
    "google_oauth_access_token": re.compile(r"ya29\.[0-9A-Za-z_\-]{20,}"),
    "google_refresh_token": re.compile(r"1//0[0-9A-Za-z_\-]{20,}"),
    "google_client_secret": re.compile(r"GOCSPX-[0-9A-Za-z_\-]{20,}"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "private_key": re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "refresh_token_json": re.compile(r"\"refresh_token\"\s*:\s*\"[^\"]{20,}\""),
    "client_secret_json": re.compile(r"\"client_secret\"\s*:\s*\"[^\"]{12,}\""),
}
MAX_BYTES = 2_000_000


def iter_files(root: Path) -> list[Path]:
    out = []
    for p in root.rglob("*"):
        if p.is_file() and not (set(p.relative_to(root).parts) & SKIP_DIRS):
            out.append(p)
    return out


def scan(root: Path) -> list[str]:
    findings: list[str] = []
    for p in iter_files(root):
        rel = p.relative_to(root)
        if p.name not in NAME_ALLOW and any(r.match(p.name) for r in NAME_PATTERNS):
            findings.append(f"{rel}: secret-like file name")
        if p.stat().st_size > MAX_BYTES or p.suffix.lower() in {".png", ".jpg", ".gif", ".ico", ".zip"}:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for name, rx in CONTENT_PATTERNS.items():
            if rx.search(text):
                findings.append(f"{rel}: {name}")
    return findings


def staged_secret_files(root: Path) -> list[str]:
    """Defence in depth: refuse if Git tracks a secret-like file even if it was deleted on disk."""
    if not (root / ".git").exists():
        return []
    try:
        r = subprocess.run(["git", "ls-files"], cwd=root, capture_output=True, text=True, timeout=30, check=False)
    except OSError:
        return []
    names = [line for line in r.stdout.splitlines() if line]
    return [n for n in names if Path(n).name not in NAME_ALLOW and any(rx.match(Path(n).name) for rx in NAME_PATTERNS)]


def main(argv: list[str]) -> int:
    root = Path(argv[0]).resolve() if argv else ROOT
    findings = scan(root) + [f"{n}: tracked by git" for n in staged_secret_files(root)]
    if findings:
        print("SECRET_SCAN = FAIL")
        for f in findings:
            print("  " + f)
        return 1
    print("SECRET_SCAN = PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
