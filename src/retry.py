"""Error classification and bounded retry policy for Gmail API calls.

401 -> exactly one explicit credential refresh, then fail (no refresh loop)
403 -> permission/scope problem: fail closed immediately (rate-limit 403s count as 429)
429 / 5xx / network -> exponential backoff with jitter, Retry-After honoured, bounded
Non-idempotent writes are never retried blindly - the caller reconciles instead.
"""

from __future__ import annotations

import json
import random
import socket
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class ErrorKind(StrEnum):
    AUTH = "AUTH"
    PERMISSION = "PERMISSION"
    RATE_LIMIT = "RATE_LIMIT"
    SERVER = "SERVER"
    NETWORK = "NETWORK"
    NOT_FOUND = "NOT_FOUND"
    CONFLICT = "CONFLICT"
    CLIENT = "CLIENT"
    UNKNOWN = "UNKNOWN"


TRANSIENT = frozenset({ErrorKind.RATE_LIMIT, ErrorKind.SERVER, ErrorKind.NETWORK})
_RATE_REASONS = {"ratelimitexceeded", "userratelimitexceeded", "quotaexceeded"}


@dataclass(frozen=True)
class ErrorInfo:
    kind: ErrorKind
    status: int | None
    reason: str
    retry_after: float | None


def _http_reason(content: Any) -> str:
    try:
        data = json.loads(content.decode("utf-8") if isinstance(content, bytes | bytearray) else content)
        err = data.get("error", {}) if isinstance(data, dict) else {}
        errors = err.get("errors") or []
        if errors and isinstance(errors[0], dict) and errors[0].get("reason"):
            return str(errors[0]["reason"])
        return str(err.get("status") or "")
    except Exception:  # noqa: BLE001 - malformed error bodies are common
        return ""


def _retry_after(resp: Any) -> float | None:
    try:
        value = resp.get("retry-after") if hasattr(resp, "get") else None
        if value is None:
            return None
        return max(0.0, float(value))
    except (TypeError, ValueError):
        return None


def classify(exc: BaseException) -> ErrorInfo:
    from google.auth.exceptions import RefreshError
    from googleapiclient.errors import HttpError

    if isinstance(exc, HttpError):
        status = int(getattr(exc.resp, "status", 0) or 0)
        reason = _http_reason(getattr(exc, "content", b""))
        ra = _retry_after(exc.resp)
        if status == 401:
            kind = ErrorKind.AUTH
        elif status == 403:
            kind = ErrorKind.RATE_LIMIT if reason.lower() in _RATE_REASONS else ErrorKind.PERMISSION
        elif status == 404:
            kind = ErrorKind.NOT_FOUND
        elif status == 409:
            kind = ErrorKind.CONFLICT
        elif status == 429:
            kind = ErrorKind.RATE_LIMIT
        elif 500 <= status <= 599:
            kind = ErrorKind.SERVER
        elif 400 <= status <= 499:
            kind = ErrorKind.CLIENT
        else:
            kind = ErrorKind.UNKNOWN
        return ErrorInfo(kind, status, reason, ra)

    if isinstance(exc, RefreshError):
        return ErrorInfo(ErrorKind.AUTH, None, "refresh_error", None)

    import httplib2

    net_types: tuple[type[BaseException], ...] = (TimeoutError, ConnectionError, socket.timeout, httplib2.HttpLib2Error)
    if isinstance(exc, net_types):
        return ErrorInfo(ErrorKind.NETWORK, None, type(exc).__name__, None)
    return ErrorInfo(ErrorKind.UNKNOWN, None, type(exc).__name__, None)


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 5
    base_delay: float = 1.0
    max_delay: float = 32.0
    max_retry_after: float = 60.0

    def delay(self, attempt: int, retry_after: float | None, jitter: float | None = None) -> float:
        j = random.random() if jitter is None else jitter  # noqa: S311 - jitter, not security
        backoff = min(self.max_delay, self.base_delay * (2 ** (attempt - 1))) * (0.5 + j / 2)
        if retry_after is not None:
            return max(backoff, min(retry_after, self.max_retry_after))
        return backoff
