"""Lock, redaction/log injection, static gates, repository hygiene."""

import logging
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from src.errors import LockError
from src.lock import SingleInstanceLock
from src.redaction import RedactingFilter, mask_email, redact, sanitize_line

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable


# ---------------------------------------------------------------- single instance
def test_second_instance_is_refused(data_dir):
    p = data_dir / "app.lock"
    with SingleInstanceLock(p), pytest.raises(LockError):
        SingleInstanceLock(p).acquire()
    with SingleInstanceLock(p):
        pass  # released -> re-acquirable


def test_lock_is_released_when_process_dies(data_dir):
    p = data_dir / "proc.lock"
    code = (
        f"import sys; sys.path.insert(0, {str(ROOT)!r}); from src.lock import SingleInstanceLock; "
        f"SingleInstanceLock(__import__('pathlib').Path({str(p)!r})).acquire(); import os; os._exit(0)"
    )
    subprocess.run([PY, "-c", code], check=True, timeout=30)
    with SingleInstanceLock(p):
        pass


# ---------------------------------------------------------------- redaction / log injection
def test_tokens_are_redacted():
    access = "ya29." + "A" * 40
    refresh = "1//0" + "B" * 40
    secret = "GOCSPX-" + "C" * 24
    text = f'auth {access} refresh {refresh} "client_secret": "{secret}" Authorization: Bearer {"D" * 30}'
    out = redact(text)
    for s in (access, refresh, secret, "D" * 30):
        assert s not in out


def test_emails_masked_and_control_chars_neutralised():
    assert mask_email("Mail an max.mustermann@example.com") == "Mail an m***@example.com"
    line = sanitize_line("ok\r\nINFO forged entry\x1b[31m red \u202e evil\x00")
    assert "\n" not in line and "\r" not in line and "\x1b" not in line and "\u202e" not in line
    assert "\\r\\nINFO forged entry" in line


def test_logging_filter_drops_tracebacks_and_redacts():
    rec = logging.LogRecord("x", logging.ERROR, __file__, 1, "token %s for %s", ("ya29." + "z" * 30, "a@b.de"), None)
    try:
        raise RuntimeError("1//0" + "q" * 30)
    except RuntimeError:
        rec.exc_info = sys.exc_info()
    assert RedactingFilter().filter(rec)
    assert "zzzz" not in rec.msg and "a***@b.de" in rec.msg and rec.exc_info is None
    assert "RuntimeError" in rec.msg and "qqqq" not in rec.msg


# ---------------------------------------------------------------- static gates
def run_tool(name, *args):
    return subprocess.run(
        [PY, str(ROOT / "tools" / name), *map(str, args)], capture_output=True, text=True, timeout=120
    )


def test_forbidden_scan_passes_on_src():
    r = run_tool("forbidden_scan.py")
    assert r.returncode == 0, r.stdout


PLANTED = {
    "send_call.py": "def go(s):\n    return s.users().messages().send(userId='me', body={}).execute()\n",
    "batch.py": "def go(s):\n    s.users().messages().batchDelete(userId='me', body={})\n",
    "reflect.py": "def go(s):\n    return getattr(s.users().messages(), 'delete')\n",
    "defsend.py": "class C:\n    def send(self):\n        pass\n",
    "scope.py": "SCOPES = ['https://mail.' + 'google.com/']\nX = 'https://mail.google.com/'\n",
    "bypass.py": "def go(c):\n    return object.__getattribute__(c, '_g_inner')\n",
    "trash.py": "def go(s):\n    return s.users().threads().trash(userId='me', id='1')\n",
    # Red Team B M7: eight bypasses that used to pass the gate
    "rt_concat_getattr.py": "def go(m, b):\n    return getattr(m, 'se' + 'nd')(userId='me', body=b)\n",
    "rt_variable_getattr.py": "VERB = 'x'\ndef go(m):\n    name = VERB\n    return getattr(m, name)\n",
    "rt_join_getattr.py": "def go(t):\n    return getattr(t, ''.join(['tr', 'ash']))\n",
    "rt_eval.py": "def go(svc):\n    return eval('svc.users().messages().' + 'send')\n",
    "rt_dunder_getattr.py": "def go(m):\n    return m.__getattr__('send')\n",
    "rt_own_service.py": (
        "from googleapiclient.discovery import build\ndef go(c):\n    return build('gmail', 'v1', credentials=c)\n"
    ),
    "rt_raw_rest.py": (
        "from google.auth.transport.requests import AuthorizedSession\n"
        "URL = 'https://gmail.googleapis.com/gmail/v1/users/me/messages/' + 'send'\n"
        "def go(c, raw):\n    return AuthorizedSession(c).post(URL, json={'raw': raw})\n"
    ),
    "rt_scope_concat.py": "SCOPES = ['https://mail.' + 'google.com/']\n",
    "rt_requests.py": "import requests\ndef go():\n    return requests.post('https://example.invalid')\n",
    "rt_bare_google.py": "import google.auth\ndef go():\n    return google.auth\n",
    "rt_vars.py": "def go(m):\n    return vars(m)['se' 'nd']\n",
    # Fix verification C-M1: indirect transport access and aliasing
    "rc_rel_adapter_httplib2.py": "from .gmail_client import httplib2\n",
    "rc_rel_retry_socket.py": "from .retry import http, socket, ssl\n",
    "rc_abs_src_httplib2.py": "from src.gmail_client import httplib2\n",
    "rc_auth_default_request.py": "from .auth import _default_request\n",
    "rc_sys_modules.py": "import sys\nT = sys.modules['httplib2']\n",
    "rc_importlib_util.py": "import importlib.util\nS = importlib.util.find_spec('requests')\n",
    "rc_getattr_alias.py": "g = getattr\ndef go(m, n):\n    return g(m, n)\n",
    "rc_operator_alias.py": "from operator import attrgetter as ag\n",
    "rc_adapter_root.py": "def go(c):\n    return c._root\n",
    "rc_subprocess.py": "import subprocess\n",
    "rc_service_factory.py": "from .auth import build_gmail_service\n",
}


def test_forbidden_scan_exemptions_are_bound_to_repository_paths(tmp_path):
    """A planted file named like the adapter gets no adapter exemptions."""
    d = tmp_path / "src"
    d.mkdir()
    (d / "gmail_client.py").write_text("from googleapiclient.discovery import build\n", encoding="utf-8")
    (d / "auth.py").write_text("import requests\n", encoding="utf-8")
    r = run_tool("forbidden_scan.py", d)
    assert r.returncode == 1 and r.stdout.count("outside the adapter") >= 2


def test_forbidden_scan_covers_src_and_tools_by_default():
    r = run_tool("forbidden_scan.py")
    n = int(re.search(r"\((\d+) files\)", r.stdout).group(1))
    expected = len(list((ROOT / "src").rglob("*.py"))) + len(list((ROOT / "tools").rglob("*.py")))
    assert n == expected


@pytest.mark.parametrize("name", sorted(PLANTED))
def test_forbidden_scan_catches_planted_code(tmp_path, name):
    d = tmp_path / "generated src"
    d.mkdir()
    (d / name).write_text(PLANTED[name], encoding="utf-8")
    r = run_tool("forbidden_scan.py", d)
    assert r.returncode == 1 and "FAIL" in r.stdout


def test_secret_scan_repo_is_clean():
    r = run_tool("secret_scan.py", ROOT)
    assert r.returncode == 0, r.stdout


def test_secret_scan_detects_files_and_content(tmp_path):
    (tmp_path / "credentials.json").write_text("{}", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("refresh " + "1//0" + "x" * 40, encoding="utf-8")
    (tmp_path / ".env").write_text("A=1", encoding="utf-8")
    r = run_tool("secret_scan.py", tmp_path)
    assert r.returncode == 1
    for needle in ("credentials.json", "google_refresh_token", ".env"):
        assert needle in r.stdout


def test_gitignore_covers_secrets_and_state():
    gi = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for pat in (
        "credentials*.json",
        "client_secret*.json",
        "token*.json",
        ".env",
        "*.sqlite3",
        "logs/",
        "config/rules.yaml",
    ):
        assert pat in gi


def test_no_script_defaults_to_apply():
    for p in [ROOT / "START_GMAIL_AUTOMATION.cmd", *(ROOT / "scripts").glob("*.ps1")]:
        text = p.read_text(encoding="utf-8")
        assert not re.search(r"--apply", text), p.name


def test_ci_workflow_covers_required_gates():
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for needle in ("pytest", "ruff", "mypy", "secret_scan.py", "forbidden_scan.py", "config-check"):
        assert needle in ci
    assert "secrets." not in ci  # CI never needs a real Gmail account


@pytest.mark.skipif(shutil.which("git") is None, reason="git missing")
def test_project_paths_with_spaces_and_umlauts(tmp_path):
    target = tmp_path / "Mein Projekt Ü" / "GMAIL AUTOMATION"
    shutil.copytree(ROOT / "src", target / "src")
    shutil.copytree(ROOT / "config", target / "config")
    r = subprocess.run(
        [PY, "-m", "src.cli", "config-check", "--config", str(target / "config" / "rules.example.yaml")],
        cwd=target,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert r.returncode == 0 and "CONFIG = PASS" in r.stdout
