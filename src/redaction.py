"""Log minimisation, masking and log-injection defence.

Everything that reaches a console line or a log file passes through `redact()`.
"""

from __future__ import annotations

import hashlib
import logging
import re

_EMAIL_RE = re.compile(r"([A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]*@([A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+)")
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-Z\\-_]")
# C0/C1 controls (except tab), DEL, line/paragraph separators, bidi overrides/isolates.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069\ufeff]")

_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
        "[REDACTED PRIVATE KEY]",
    ),
    (re.compile(r"ya29\.[0-9A-Za-z_\-]{10,}"), "ya29.[REDACTED]"),
    (re.compile(r"1//[0-9A-Za-z_\-]{10,}"), "1//[REDACTED]"),
    (re.compile(r"GOCSPX-[0-9A-Za-z_\-]{6,}"), "GOCSPX-[REDACTED]"),
    (re.compile(r"AIza[0-9A-Za-z_\-]{30,}"), "AIza[REDACTED]"),
    (re.compile(r"(?i)\b(bearer\s+)[0-9A-Za-z._\-~+/]{8,}=*"), r"\1[REDACTED]"),
    (
        re.compile(
            r"(?i)(\"?(?:refresh_token|access_token|client_secret|id_token|token)\"?\s*[:=]\s*\"?)"
            r"[^\"\s,}]{6,}"
        ),
        r"\1[REDACTED]",
    ),
)


def redact_secrets(text: str) -> str:
    for pattern, repl in _SECRET_PATTERNS:
        text = pattern.sub(repl, text)
    return text


def mask_email(text: str) -> str:
    return _EMAIL_RE.sub(lambda m: f"{m.group(1)}***@{m.group(2)}", text)


def sanitize_line(text: str, max_len: int = 400) -> str:
    """Single-line, control-free, length-bounded text (prevents log/terminal injection)."""
    text = _ANSI_RE.sub("", text)
    text = text.replace("\r", "\\r").replace("\n", "\\n")
    text = _CONTROL_RE.sub("?", text)
    if len(text) > max_len:
        text = text[: max_len - 3] + "..."
    return text


def redact(text: object, *, mask_emails: bool = True, max_len: int = 400) -> str:
    s = redact_secrets(str(text))
    if mask_emails:
        s = mask_email(s)
    return sanitize_line(s, max_len=max_len)


def truncate_subject(subject: str, n: int = 60) -> str:
    return redact(subject, max_len=n)


def fingerprint(*parts: object, length: int = 32) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(str(p).encode("utf-8", "surrogatepass"))
        h.update(b"\x1f")
    return h.hexdigest()[:length]


class RedactingFilter(logging.Filter):
    """Applies `redact()` to every log record before any handler formats it."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001 - never let a bad log call crash the run
            msg = str(record.msg)
        record.msg = redact(msg, max_len=2000)
        record.args = ()
        if record.exc_info:
            # Tracebacks may contain tokens; keep the type only.
            exc_type = record.exc_info[0]
            record.msg += f" [exception: {exc_type.__name__ if exc_type else 'unknown'}]"
            record.exc_info = None
            record.exc_text = None
        return True
