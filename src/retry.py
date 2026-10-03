"""Error classification and bounded retry policy for Gmail API calls.

401 -> exactly one explicit credential refresh, then fail (no refresh loop)
403 -> permission/scope problem: fail closed immediately (rate-limit 403s count as 429,
       an exhausted daily quota is reported as QUOTA and not retried)
429 / 5xx / network -> exponential backoff with jitter, Retry-After honoured, bounded
       per call (max attempts) and per run (cumulative backoff budget)
Non-idempotent writes are never retried blindly after 5xx/network errors - the caller
reconciles instead. A 429 means "rejected, not executed" and is retried for them too.
"""

from __future__ import annotations

import errno
import http.client
import json
import random
import socket
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
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
    QUOTA = "QUOTA"
    UNKNOWN = "UNKNOWN"


TRANSIENT = frozenset({ErrorKind.RATE_LIMIT, ErrorKind.SERVER, ErrorKind.NETWORK})
_RATE_REASONS = {"ratelimitexceeded", "userratelimitexceeded", "quotaexceeded"}
_QUOTA_REASONS = {"dailylimitexceeded", "dailylimitexceededunreg"}
_NET_ERRNOS = frozenset(
    {
        errno.ENETUNREACH,
        errno.EHOSTUNREACH,
        errno.ECONNABORTED,
        errno.ECONNRESET,
        errno.ECONNREFUSED,
        errno.ETIMEDOUT,
        errno.ENETDOWN,
    }
)


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


def _retry_after(resp: Any, now: datetime | None = None) -> float | None:
    try:
        value = resp.get("retry-after") if hasattr(resp, "get") else None
        if value is None:
            return None
        try:
            return max(0.0, float(value))
        except ValueError:
            when = parsedate_to_datetime(str(value))  # HTTP-date form (RFC 9110)
            if when.tzinfo is None:
                when = when.replace(tzinfo=UTC)
            return max(0.0, (when - (now or datetime.now(UTC))).total_seconds())
    except (TypeError, ValueError, IndexError, OverflowError):
        return None


def is_network_error(exc: BaseException) -> bool:
    import httplib2

    if isinstance(
        exc,
        TimeoutError | ConnectionError | socket.timeout | socket.gaierror | ssl.SSLError | http.client.HTTPException,
    ):
        return True
    if isinstance(exc, httplib2.HttpLib2Error):
        return True
    return isinstance(exc, OSError) and exc.errno in _NET_ERRNOS


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
            low = reason.lower()
            kind = (
                ErrorKind.QUOTA
                if low in _QUOTA_REASONS
                else ErrorKind.RATE_LIMIT
                if low in _RATE_REASONS
                else ErrorKind.PERMISSION
            )
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

    if is_network_error(exc):
        return ErrorInfo(ErrorKind.NETWORK, None, type(exc).__name__, None)
    return ErrorInfo(ErrorKind.UNKNOWN, None, type(exc).__name__, None)


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 5
    base_delay: float = 1.0
    max_delay: float = 32.0
    max_retry_after: float = 60.0
    max_total_sleep: float = 300.0  # cumulative backoff budget per client (= per run)

    def delay(self, attempt: int, retry_after: float | None, jitter: float | None = None) -> float:
        j = random.random() if jitter is None else jitter  # noqa: S311 - jitter, not security
        backoff = min(self.max_delay, self.base_delay * (2 ** (attempt - 1))) * (0.5 + j / 2)
        if retry_after is not None:
            return max(backoff, min(retry_after, self.max_retry_after))
        return backoff
