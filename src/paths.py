"""Filesystem locations. Secrets, tokens, DBs and logs live OUTSIDE the repository."""

from __future__ import annotations

import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
APP_DIR_NAME = "GmailAutomation"
ENV_HOME = "GMAIL_AUTOMATION_HOME"


def data_dir() -> Path:
    override = os.environ.get(ENV_HOME)
    if override:
        return Path(override).expanduser()
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / APP_DIR_NAME
    xdg = os.environ.get("XDG_DATA_HOME")
    return (Path(xdg) if xdg else Path.home() / ".local" / "share") / "gmail-automation"


def client_secret_path() -> Path:
    return data_dir() / "client_secret.json"


def token_path(profile: str) -> Path:
    return data_dir() / f"token_{profile}.json"


def token_meta_path(profile: str) -> Path:
    return data_dir() / f"token_{profile}.meta.json"


def audit_db_path() -> Path:
    return data_dir() / "audit.sqlite3"


def lock_path() -> Path:
    return data_dir() / "gmail-automation.lock"


def log_dir() -> Path:
    return data_dir() / "logs"


def default_config_path() -> Path:
    return PROJECT_ROOT / "config" / "rules.yaml"


def is_within(child: Path, parent: Path) -> bool:
    try:
        child.resolve(strict=False).relative_to(parent.resolve(strict=False))
        return True
    except ValueError:
        return False


def enclosing_git_root(path: Path) -> Path | None:
    p = path.resolve(strict=False)
    for candidate in [p, *p.parents]:
        if (candidate / ".git").exists():
            return candidate
    return None


def ensure_private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(path, 0o700)
