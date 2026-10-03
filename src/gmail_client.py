"""Narrow Gmail adapter with an allow-listed endpoint surface.

Three independent barriers stand between a code path and a dangerous Gmail call:

1. `_GuardedResource` wraps the googleapiclient service. Every attribute access is
   checked against the profile's endpoint allow-list BEFORE the request is even built,
   so send / delete / trash / batch / settings / forwarding / filters are unreachable
   through `GmailClient`.
2. Every public mutation method calls `policy.authorize()` first.
3. `GuardedHttp` is the HTTP transport of the real service: it checks method + host +
   path of EVERY outgoing request against the same allow-list (also covers requests
   built outside `GmailClient` on the shared transport, and token refreshes).

Trust assumption: these are in-process controls. They stop accidental, generated or
naive misuse; they cannot stop malicious code running in the same interpreter (a
compromised dependency). The static gate (tools/forbidden_scan.py) keeps new transport
or reflection paths out of the code base.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import urlsplit

import httplib2

from .errors import (
    AmbiguousWriteError,
    AuthError,
    GmailApiError,
    GmailAutomationError,
    PolicyViolation,
    RunBudgetExceeded,
    ScopeError,
    TransientExhaustedError,
)
from .models import State
from .policy import ActionType, PolicyContext, Profile, authorize, is_app_label_name, is_user_label_id
from .retry import TRANSIENT, ErrorKind, RetryPolicy, classify

log = logging.getLogger("gmail_automation.client")

OBSERVE_ENDPOINTS: Final = frozenset(
    {
        "users.getProfile",
        "users.labels.list",
        "users.messages.list",
        "users.messages.get",
        "users.threads.get",
        "users.drafts.list",
        "users.drafts.get",
    }
)
APPLY_MUTATIONS: Final = frozenset({"users.labels.create", "users.messages.modify", "users.drafts.create"})
APPLY_ENDPOINTS: Final = OBSERVE_ENDPOINTS | APPLY_MUTATIONS

FORBIDDEN_ENDPOINTS: Final = frozenset(
    {
        "users.messages.send",
        "users.drafts.send",
        "users.messages.delete",
        "users.threads.delete",
        "users.messages.batchDelete",
        "users.messages.trash",
        "users.threads.trash",
        "users.messages.untrash",
        "users.threads.untrash",
        "users.messages.batchModify",
        "users.threads.modify",
        "users.messages.insert",
        "users.messages.import_",
        "users.drafts.delete",
        "users.drafts.update",
        "users.labels.delete",
        "users.labels.update",
        "users.labels.patch",
        "users.watch",
        "users.stop",
    }
)
FORBIDDEN_PREFIXES: Final = ("users.settings",)
FORBIDDEN_METHOD_NAMES: Final = frozenset(
    {
        "send",
        "delete",
        "batchDelete",
        "trash",
        "untrash",
        "batchModify",
        "insert",
        "import_",
        "watch",
        "stop",
        "settings",
        "forwardingAddresses",
        "filters",
        "sendAs",
        "delegates",
    }
)
NON_IDEMPOTENT: Final = frozenset({"users.drafts.create", "users.labels.create"})

# ---------------------------------------------------------------------- transport allow-list
_ID = r"[A-Za-z0-9_\-]{1,256}"
_BASE = r"/gmail/v1/users/me"
GMAIL_HOSTS: Final = frozenset({"gmail.googleapis.com", "gmail.mtls.googleapis.com"})
TOKEN_HOST: Final = "oauth2.googleapis.com"  # noqa: S105 - host name of the OAuth endpoint, not a secret
TRANSPORT_RULES: Final[tuple[tuple[str, str, re.Pattern[str]], ...]] = (
    ("users.getProfile", "GET", re.compile(_BASE + r"/profile")),
    ("users.labels.list", "GET", re.compile(_BASE + r"/labels")),
    ("users.labels.create", "POST", re.compile(_BASE + r"/labels")),
    ("users.messages.list", "GET", re.compile(_BASE + r"/messages")),
    ("users.messages.get", "GET", re.compile(_BASE + r"/messages/" + _ID)),
    ("users.messages.modify", "POST", re.compile(_BASE + r"/messages/" + _ID + r"/modify")),
    ("users.threads.get", "GET", re.compile(_BASE + r"/threads/" + _ID)),
    ("users.drafts.list", "GET", re.compile(_BASE + r"/drafts")),
    ("users.drafts.get", "GET", re.compile(_BASE + r"/drafts/" + _ID)),
    ("users.drafts.create", "POST", re.compile(_BASE + r"/drafts")),
)


def _json_body(body: Any) -> Any:
    try:
        text = body.decode("utf-8") if isinstance(body, bytes | bytearray) else body
        return json.loads(text) if isinstance(text, str) else None
    except (UnicodeDecodeError, ValueError):
        return None


def check_transport_body(endpoint: str, body: Any) -> None:
    """Body-level second barrier: modify may only touch user label ids, drafts must be thread-linked."""
    if endpoint == "users.messages.modify":
        data = _json_body(body)
        if not isinstance(data, dict) or set(data) - {"addLabelIds", "removeLabelIds"}:
            raise PolicyViolation("Transport: unexpected modify body", code="TRANSPORT_BODY")
        for key in ("addLabelIds", "removeLabelIds"):
            ids = data.get(key, [])
            if not isinstance(ids, list) or not all(isinstance(i, str) and is_user_label_id(i) for i in ids):
                raise PolicyViolation("Transport: system or unknown label id in modify", code="TRANSPORT_BODY")
    elif endpoint == "users.drafts.create":
        data = _json_body(body)
        msg = data.get("message") if isinstance(data, dict) else None
        if (
            not isinstance(msg, dict)
            or set(data) != {"message"}
            or not isinstance(msg.get("threadId"), str)
            or not msg.get("threadId")
            or not isinstance(msg.get("raw"), str)
        ):
            raise PolicyViolation("Transport: draft must be a raw message linked to a thread", code="TRANSPORT_BODY")
    elif endpoint == "users.labels.create":
        data = _json_body(body)
        if not isinstance(data, dict) or not isinstance(data.get("name"), str):
            raise PolicyViolation("Transport: unexpected label body", code="TRANSPORT_BODY")


def check_transport(method: str, uri: str, allowed: frozenset[str]) -> str:
    """Raise PolicyViolation unless an outgoing HTTP request maps to an allow-listed endpoint."""
    parts = urlsplit(str(uri))
    verb = str(method).upper()
    clean = parts.scheme == "https" and parts.port in (None, 443) and not parts.username and not parts.password
    if clean and parts.hostname == TOKEN_HOST and parts.path == "/token" and verb == "POST" and not parts.query:
        return "oauth2.token"  # credential refresh
    if not clean or parts.hostname not in GMAIL_HOSTS:
        raise PolicyViolation(f"Outgoing request to unexpected host blocked: {parts.hostname}", code="TRANSPORT_HOST")
    for endpoint, rule_verb, rx in TRANSPORT_RULES:
        if verb == rule_verb and rx.fullmatch(parts.path):
            if endpoint not in allowed:
                raise PolicyViolation(f"Transport: {endpoint} not allowed for this profile", code="TRANSPORT_DENIED")
            return endpoint
    raise PolicyViolation(
        f"Outgoing Gmail request blocked at transport layer: {verb} {parts.path}", code="TRANSPORT_BLOCKED"
    )


class GuardedHttp(httplib2.Http):
    """httplib2 transport that only lets allow-listed Gmail requests (and token refreshes) out."""

    def __init__(self, profile: Profile, *, timeout: float = 60.0) -> None:
        super().__init__(timeout=timeout)
        self.transport_allowed = allowed_endpoints(profile)
        self.follow_redirects = False  # a redirect could point outside the allow-list
        self.redirect_codes = frozenset(httplib2.REDIRECT_CODES) - {308}

    def request(
        self,
        uri: str,
        method: str = "GET",
        body: Any = None,
        headers: Any = None,
        redirections: int = httplib2.DEFAULT_MAX_REDIRECTS,
        connection_type: Any = None,
    ) -> Any:
        endpoint = check_transport(method, uri, self.transport_allowed)
        if any(str(k).lower() == "x-http-method-override" for k in (headers or {})):
            raise PolicyViolation("Transport: HTTP method override refused", code="TRANSPORT_METHOD_OVERRIDE")
        check_transport_body(endpoint, body)
        return super().request(
            uri, method, body=body, headers=headers, redirections=redirections, connection_type=connection_type
        )


def allowed_endpoints(profile: Profile) -> frozenset[str]:
    return APPLY_ENDPOINTS if profile is Profile.APPLY else OBSERVE_ENDPOINTS


def check_endpoint(full: str, allowed: frozenset[str]) -> None:
    last = full.rsplit(".", 1)[-1]
    if full in FORBIDDEN_ENDPOINTS or full.startswith(FORBIDDEN_PREFIXES) or last in FORBIDDEN_METHOD_NAMES:
        raise PolicyViolation(
            f"Forbidden Gmail endpoint blocked at adapter boundary: {full}", code="FORBIDDEN_ENDPOINT"
        )
    if full in allowed or any(a.startswith(full + ".") for a in allowed):
        return
    raise PolicyViolation(f"Gmail endpoint not in allow-list: {full}", code="ENDPOINT_NOT_ALLOWED")


class _GuardedResource:
    """Proxy around a googleapiclient Resource; denies everything outside the allow-list."""

    __slots__ = ("_g_allowed", "_g_inner", "_g_path")

    def __init__(self, inner: Any, path: str, allowed: frozenset[str]) -> None:
        object.__setattr__(self, "_g_inner", inner)
        object.__setattr__(self, "_g_path", path)
        object.__setattr__(self, "_g_allowed", allowed)

    def __setattr__(self, name: str, value: Any) -> None:
        raise PolicyViolation("Guarded Gmail resource is immutable", code="GUARD_IMMUTABLE")

    def __getattribute__(self, name: str) -> Any:
        # The wrapped service is never reachable through normal attribute access.
        if name.startswith("_") and not (name.startswith("__") and name.endswith("__")):
            raise AttributeError(name)
        if name.startswith("__"):
            return object.__getattribute__(self, name)
        return _GuardedResource._resolve(self, name)

    def _resolve(self, name: str) -> Any:
        path: str = object.__getattribute__(self, "_g_path")
        allowed: frozenset[str] = object.__getattribute__(self, "_g_allowed")
        full = f"{path}.{name}" if path else name
        check_endpoint(full, allowed)
        target = getattr(object.__getattribute__(self, "_g_inner"), name)
        if not callable(target):
            raise PolicyViolation(f"Non-callable Gmail attribute denied: {full}", code="ENDPOINT_NOT_ALLOWED")

        def call(*args: Any, **kwargs: Any) -> Any:
            result = target(*args, **kwargs)
            if full in allowed:
                return result  # an HttpRequest for an allow-listed endpoint
            return _GuardedResource(result, full, allowed)

        return call


def guard_self_test() -> dict[str, bool]:
    """Proves at runtime that the adapter boundary blocks send/delete even if the inner object has them."""

    class _Trap:
        def users(self) -> _Trap:
            return self

        def messages(self) -> _Trap:
            return self

        def drafts(self) -> _Trap:
            return self

        def threads(self) -> _Trap:
            return self

        def send(self, **_: Any) -> None:  # pragma: no cover - must never run
            raise AssertionError("send reached")

        def delete(self, **_: Any) -> None:  # pragma: no cover
            raise AssertionError("delete reached")

        def batchDelete(self, **_: Any) -> None:  # noqa: N802  # pragma: no cover
            raise AssertionError("batchDelete reached")

        def trash(self, **_: Any) -> None:  # pragma: no cover
            raise AssertionError("trash reached")

    root = _GuardedResource(_Trap(), "", APPLY_ENDPOINTS)
    probes: dict[str, Callable[[], Any]] = {
        "messages.send": lambda: root.users().messages().send,
        "drafts.send": lambda: root.users().drafts().send,
        "messages.delete": lambda: root.users().messages().delete,
        "threads.delete": lambda: root.users().threads().delete,
        "messages.batchDelete": lambda: root.users().messages().batchDelete,
        "messages.trash": lambda: root.users().messages().trash,
    }
    out: dict[str, bool] = {}
    for key, probe in probes.items():
        try:
            probe()
            out[key] = False
        except PolicyViolation:
            out[key] = True
    return out


@dataclass(frozen=True)
class LabelRef:
    id: str
    name: str


class GmailClient:
    def __init__(
        self,
        service: Any,
        ctx: PolicyContext,
        *,
        retry: RetryPolicy | None = None,
        sleep: Callable[[float], None] = time.sleep,
        refresh_credentials: Callable[[], None] | None = None,
        user_id: str = "me",
        deadline_seconds: float | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._ctx = ctx
        self._root = _GuardedResource(service, "", allowed_endpoints(ctx.profile))
        self._retry = retry or RetryPolicy()
        self._sleep = sleep
        self._refresh = refresh_credentials
        self._user = user_id
        self._clock = clock
        self._deadline = clock() + deadline_seconds if deadline_seconds else None
        self._slept = 0.0
        self.mutation_count = 0
        self.call_log: list[str] = []

    @property
    def context(self) -> PolicyContext:
        return self._ctx

    # ------------------------------------------------------------------ core
    def _users(self) -> Any:
        return self._root.users()

    def _execute(self, endpoint: str, factory: Callable[[], Any], *, mutating: bool = False) -> Any:
        """Run one API request with the bounded retry policy. Never retries ambiguous writes.

        Once an attempt of a mutating call failed with 5xx/network, the write may already be
        in Gmail: any later failure of that call is reported as AmbiguousWriteError, so the
        caller re-reads and settles instead of recording a terminal FAILED.
        """
        maybe_applied = [False]
        try:
            return self._execute_with_retry(endpoint, factory, mutating, maybe_applied)
        except GmailAutomationError as err:
            if mutating and maybe_applied[0] and not isinstance(err, AmbiguousWriteError | PolicyViolation):
                raise AmbiguousWriteError(
                    f"{endpoint}: outcome unknown after a transient failure ({err.code})",
                    code=f"AMBIGUOUS_{err.code}",
                    status=getattr(err, "status", None),
                ) from None
            raise

    def _execute_with_retry(
        self, endpoint: str, factory: Callable[[], Any], mutating: bool, maybe_applied: list[bool]
    ) -> Any:
        refreshed = False
        attempt = 0
        while True:
            attempt += 1
            if self._deadline is not None and self._clock() > self._deadline:
                raise RunBudgetExceeded("Run deadline exceeded - stopped before the next request", code="RUN_DEADLINE")
            request = factory()  # building the request passes the guard again
            self.call_log.append(endpoint)
            try:
                result = request.execute()
                if mutating:
                    self.mutation_count += 1
                return result
            except PolicyViolation:
                raise
            except Exception as exc:  # noqa: BLE001 - classified below, nothing is swallowed
                info = classify(exc)
                if mutating and info.kind in (ErrorKind.SERVER, ErrorKind.NETWORK):
                    maybe_applied[0] = True
                if info.kind is ErrorKind.AUTH:
                    if refreshed or self._refresh is None:
                        raise AuthError("Gmail rejected credentials (401) after refresh", code="AUTH_401") from None
                    refreshed = True
                    try:
                        self._refresh()
                    except Exception:  # noqa: BLE001
                        raise AuthError("Credential refresh failed", code="AUTH_REFRESH_FAILED") from None
                    continue
                if info.kind is ErrorKind.PERMISSION:
                    raise ScopeError(
                        f"Gmail denied {endpoint} (403 {info.reason or 'forbidden'}) - fail closed", code="AUTH_403"
                    ) from None
                if info.kind is ErrorKind.QUOTA:
                    raise GmailApiError(
                        f"Gmail API daily quota exhausted on {endpoint} - try again tomorrow",
                        code="API_QUOTA_DAILY",
                        status=info.status,
                    ) from None
                if info.kind in TRANSIENT:
                    # 429 / rate-limit 403 = rejected, not executed: safe to retry even for creates.
                    if mutating and endpoint in NON_IDEMPOTENT and info.kind is not ErrorKind.RATE_LIMIT:
                        raise AmbiguousWriteError(
                            f"{endpoint} outcome unknown ({info.kind.value})",
                            code=f"AMBIGUOUS_{info.kind.value}",
                            status=info.status,
                        ) from None
                    if attempt >= self._retry.max_attempts:
                        raise TransientExhaustedError(
                            f"{endpoint}: retries exhausted ({info.kind.value})",
                            code=f"RETRY_EXHAUSTED_{info.kind.value}",
                            status=info.status,
                        ) from None
                    delay = self._retry.delay(attempt, info.retry_after)
                    if self._slept + delay > self._retry.max_total_sleep:
                        raise TransientExhaustedError(
                            f"{endpoint}: backoff budget of the run exhausted ({info.kind.value})",
                            code=f"RETRY_BUDGET_{info.kind.value}",
                            status=info.status,
                        ) from None
                    log.warning("transient %s on %s, retry %d in %.1fs", info.kind.value, endpoint, attempt, delay)
                    self._slept += delay
                    self._sleep(delay)
                    continue
                raise GmailApiError(
                    f"{endpoint} failed ({info.status or info.kind.value} {info.reason})",
                    code=f"API_{info.kind.value}",
                    status=info.status,
                ) from None

    # ------------------------------------------------------------------ reads
    def get_profile(self) -> dict[str, Any]:
        return dict(self._execute("users.getProfile", lambda: self._users().getProfile(userId=self._user)))

    def list_labels(self) -> list[dict[str, Any]]:
        res = self._execute("users.labels.list", lambda: self._users().labels().list(userId=self._user))
        return list(res.get("labels", []) or [])

    def list_message_refs(self, query: str, limit: int, page_size: int = 100) -> tuple[list[dict[str, str]], int]:
        refs: list[dict[str, str]] = []
        token: str | None = None
        pages = 0
        max_pages = -(-limit // page_size) + 2  # bounded even if the API keeps returning tokens
        seen_tokens: set[str] = set()
        empty_pages = 0
        while len(refs) < limit and pages < max_pages:
            size = min(page_size, limit - len(refs))
            tok = token

            def factory(size: int = size, tok: str | None = tok) -> Any:
                kw: dict[str, Any] = {"userId": self._user, "q": query, "maxResults": size}
                if tok:
                    kw["pageToken"] = tok
                return self._users().messages().list(**kw)

            res = self._execute("users.messages.list", factory)
            pages += 1
            before = len(refs)
            for m in res.get("messages", []) or []:
                if isinstance(m, dict) and m.get("id") and m.get("threadId"):
                    refs.append({"id": str(m["id"]), "threadId": str(m["threadId"])})
            empty_pages = empty_pages + 1 if len(refs) == before else 0
            token = res.get("nextPageToken")
            if not token or not isinstance(token, str) or token in seen_tokens or empty_pages >= 2:
                break
            seen_tokens.add(token)
        return refs[:limit], pages

    def get_message(self, message_id: str, fmt: str = "full") -> dict[str, Any]:
        if fmt not in {"full", "metadata", "minimal"}:
            raise PolicyViolation("raw message format is not used", code="FORMAT_DENIED")
        return dict(
            self._execute(
                "users.messages.get", lambda: self._users().messages().get(userId=self._user, id=message_id, format=fmt)
            )
        )

    def get_thread(self, thread_id: str, fmt: str = "minimal") -> dict[str, Any]:
        if fmt not in {"full", "metadata", "minimal"}:
            raise PolicyViolation("unsupported thread format", code="FORMAT_DENIED")
        return dict(
            self._execute(
                "users.threads.get", lambda: self._users().threads().get(userId=self._user, id=thread_id, format=fmt)
            )
        )

    def list_drafts(self, max_results: int = 100, page_token: str | None = None) -> tuple[list[dict[str, Any]], str]:
        def factory() -> Any:
            kw: dict[str, Any] = {"userId": self._user, "maxResults": max_results}
            if page_token:
                kw["pageToken"] = page_token
            return self._users().drafts().list(**kw)

        res = self._execute("users.drafts.list", factory)
        token = res.get("nextPageToken")
        return list(res.get("drafts", []) or []), token if isinstance(token, str) else ""

    def list_all_drafts(self, max_pages: int = 40) -> list[dict[str, Any]]:
        """All drafts (paginated, bounded). Missing an own draft would create a duplicate."""
        out: list[dict[str, Any]] = []
        token: str | None = None
        seen: set[str] = set()
        for _ in range(max_pages):
            page, nxt = self.list_drafts(max_results=500, page_token=token)
            out.extend(d for d in page if isinstance(d, dict))
            if not nxt or nxt in seen:
                return out
            seen.add(nxt)
            token = nxt
        raise GmailApiError("Too many drafts to check for duplicates safely", code="DRAFTS_TOO_MANY")

    def get_draft_headers(self, draft_id: str) -> dict[str, str]:
        res = self._execute(
            "users.drafts.get", lambda: self._users().drafts().get(userId=self._user, id=draft_id, format="metadata")
        )
        headers = ((res.get("message") or {}).get("payload") or {}).get("headers") or []
        return {str(h.get("name", "")).lower(): str(h.get("value", "")) for h in headers if isinstance(h, dict)}

    # ------------------------------------------------------------------ mutations (policy-gated)
    def create_label(self, name: str) -> LabelRef:
        authorize(ActionType.LABEL_CREATE, self._ctx, label_name=name)
        body = {"name": name, "labelListVisibility": "labelShow", "messageListVisibility": "show"}
        res = self._execute(
            "users.labels.create", lambda: self._users().labels().create(userId=self._user, body=body), mutating=True
        )
        lid, lname = str(res.get("id", "")), str(res.get("name", ""))
        if not is_user_label_id(lid) or lname != name:
            raise GmailApiError("Unexpected label create response", code="LABEL_CREATE_MISMATCH")
        return LabelRef(lid, lname)

    def modify_message_labels(
        self,
        message_id: str,
        *,
        add: list[LabelRef],
        remove: list[LabelRef],
        confidence: float | None,
        origin: str = "plan",
    ) -> dict[str, Any]:
        if not add and not remove:
            raise PolicyViolation("Empty label change", code="EMPTY_CHANGE")
        for ref in add:
            self._check_label_ref(ref)
            authorize(ActionType.LABEL_ADD, self._ctx, label_name=ref.name, confidence=confidence, origin=origin)
        for ref in remove:
            self._check_label_ref(ref)
            authorize(ActionType.LABEL_REMOVE, self._ctx, label_name=ref.name, confidence=confidence, origin=origin)
        body = {"addLabelIds": [r.id for r in add], "removeLabelIds": [r.id for r in remove]}
        return dict(
            self._execute(
                "users.messages.modify",
                lambda: self._users().messages().modify(userId=self._user, id=message_id, body=body),
                mutating=True,
            )
        )

    def create_draft(self, thread_id: str, raw_b64url: str, *, confidence: float, state: State) -> dict[str, Any]:
        authorize(ActionType.DRAFT_CREATE, self._ctx, confidence=confidence, state=state)
        if not thread_id or not raw_b64url:
            raise PolicyViolation("Draft must be linked to an existing thread", code="DRAFT_UNLINKED")
        body = {"message": {"raw": raw_b64url, "threadId": thread_id}}
        return dict(
            self._execute(
                "users.drafts.create",
                lambda: self._users().drafts().create(userId=self._user, body=body),
                mutating=True,
            )
        )

    def _check_label_ref(self, ref: LabelRef) -> None:
        if not is_user_label_id(ref.id):
            raise PolicyViolation(f"System or unknown label id refused: {ref.id}", code="SYSTEM_LABEL")
        if not is_app_label_name(ref.name, self._ctx):
            raise PolicyViolation(f"Label is not an application label: {ref.name}", code="LABEL_NOT_APPROVED")
