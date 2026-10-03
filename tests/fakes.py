"""In-memory Gmail API double. It deliberately has NO send/delete/trash endpoints:
any attempt to reach them would raise AttributeError (and the adapter guard blocks first).
Faults can be injected per endpoint to simulate 401/403/429/5xx, crashes and races."""

from __future__ import annotations

import base64
import copy
import json
from collections.abc import Callable
from email import message_from_bytes
from typing import Any

import httplib2
from googleapiclient.errors import HttpError

SYSTEM_LABELS = [
    "INBOX",
    "SENT",
    "DRAFT",
    "SPAM",
    "TRASH",
    "UNREAD",
    "STARRED",
    "IMPORTANT",
    "CATEGORY_PERSONAL",
    "CATEGORY_UPDATES",
]
MUTATIONS = {"users.labels.create", "users.messages.modify", "users.drafts.create"}


def http_error(status: int, reason: str = "", retry_after: float | None = None) -> HttpError:
    headers: dict[str, Any] = {"status": status}
    if retry_after is not None:
        headers["retry-after"] = str(retry_after)
    body = {"error": {"code": status, "message": reason or "err", "errors": [{"reason": reason}] if reason else []}}
    return HttpError(httplib2.Response(headers), json.dumps(body).encode())


def b64(text: str | bytes) -> str:
    raw = text.encode("utf-8") if isinstance(text, str) else text
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def make_message(
    mid: str,
    tid: str,
    *,
    from_: str = "Alice Example <alice@example.com>",
    subject: str = "Hallo",
    plain: str | None = "Hallo, kurze Info.",
    html: str | None = None,
    labels: tuple[str, ...] = ("INBOX",),
    internal_date: int = 1_700_000_000_000,
    extra_headers: dict[str, str] | None = None,
    payload: dict[str, Any] | None = None,
    message_id_header: str | None = None,
) -> dict[str, Any]:
    headers = [
        {"name": "From", "value": from_},
        {"name": "Subject", "value": subject},
        {"name": "Message-ID", "value": message_id_header or f"<{mid}@mail.example.com>"},
    ]
    for k, v in (extra_headers or {}).items():
        headers.append({"name": k, "value": v})
    if payload is None:
        parts = []
        if plain is not None:
            parts.append(
                {
                    "mimeType": "text/plain",
                    "headers": [{"name": "Content-Type", "value": "text/plain; charset=UTF-8"}],
                    "body": {"data": b64(plain), "size": len(plain)},
                }
            )
        if html is not None:
            parts.append(
                {
                    "mimeType": "text/html",
                    "headers": [{"name": "Content-Type", "value": "text/html; charset=UTF-8"}],
                    "body": {"data": b64(html), "size": len(html)},
                }
            )
        payload = {"mimeType": "multipart/alternative", "headers": headers, "parts": parts}
    else:
        payload = {**payload, "headers": headers + list(payload.get("headers", []))}
    return {
        "id": mid,
        "threadId": tid,
        "labelIds": list(labels),
        "internalDate": str(internal_date),
        "historyId": "1000",
        "payload": payload,
        "snippet": "",
    }


class AfterApply:
    """Fault: perform the call, then raise (simulates a lost response / crash after mutation)."""

    def __init__(self, exc: BaseException) -> None:
        self.exc = exc


class FakeRequest:
    def __init__(self, fn: Callable[[], Any]) -> None:
        self._fn = fn

    def execute(self) -> Any:
        return self._fn()


class FakeGmail:
    def __init__(self) -> None:
        self.messages: dict[str, dict[str, Any]] = {}
        self.labels: dict[str, dict[str, Any]] = {
            lid: {"id": lid, "name": lid, "type": "system"} for lid in SYSTEM_LABELS
        }
        self.drafts: dict[str, dict[str, Any]] = {}
        self.calls: list[str] = []
        self.faults: dict[str, list[Any]] = {}
        self._next_label = 1
        self._next_draft = 1
        self._history = 1000
        self.extra_list_ids: list[dict[str, str]] = []  # ids returned by list without stored bodies

    # ---------------------------------------------------------------- helpers
    def add(self, msg: dict[str, Any]) -> dict[str, Any]:
        self.messages[msg["id"]] = msg
        return msg

    def add_user_label(self, name: str) -> str:
        lid = f"Label_{self._next_label}"
        self._next_label += 1
        self.labels[lid] = {"id": lid, "name": name, "type": "user"}
        return lid

    def label_id(self, name: str) -> str:
        return next(lid for lid, lab in self.labels.items() if lab["name"] == name)

    def label_names(self, mid: str) -> set[str]:
        return {self.labels[lid]["name"] for lid in self.messages[mid]["labelIds"] if lid in self.labels}

    def fault(self, endpoint: str, *items: Any) -> None:
        self.faults.setdefault(endpoint, []).extend(items)

    def mutation_calls(self) -> list[str]:
        return [c for c in self.calls if c in MUTATIONS]

    def _bump(self, msg: dict[str, Any]) -> None:
        self._history += 1
        msg["historyId"] = str(self._history)

    def _dispatch(self, endpoint: str, impl: Callable[[], Any]) -> FakeRequest:
        def run() -> Any:
            self.calls.append(endpoint)
            queue = self.faults.get(endpoint)
            if queue:
                item = queue.pop(0)
                if isinstance(item, AfterApply):
                    impl()  # the server applied the change ...
                    raise item.exc  # ... but the response was lost
                if isinstance(item, BaseException):
                    raise item
                if callable(item):
                    item(self)  # race hook: mutate the mailbox before this call is served
            return impl()

        return FakeRequest(run)

    @staticmethod
    def _minimal(m: dict[str, Any]) -> dict[str, Any]:
        return {k: copy.deepcopy(m[k]) for k in ("id", "threadId", "labelIds", "internalDate", "historyId")}

    def users(self) -> _Users:
        return _Users(self)


class _Users:
    def __init__(self, g: FakeGmail) -> None:
        self.g = g

    def getProfile(self, userId: str) -> FakeRequest:  # noqa: N802,N803
        return self.g._dispatch("users.getProfile", lambda: {"emailAddress": "me@example.com"})

    def labels(self) -> _Labels:
        return _Labels(self.g)

    def messages(self) -> _Messages:
        return _Messages(self.g)

    def threads(self) -> _Threads:
        return _Threads(self.g)

    def drafts(self) -> _Drafts:
        return _Drafts(self.g)


class _Labels:
    def __init__(self, g: FakeGmail) -> None:
        self.g = g

    def list(self, userId: str) -> FakeRequest:  # noqa: N803
        return self.g._dispatch("users.labels.list", lambda: {"labels": copy.deepcopy(list(self.g.labels.values()))})

    def create(self, userId: str, body: dict[str, Any]) -> FakeRequest:  # noqa: N803
        def impl() -> dict[str, Any]:
            if any(lab["name"] == body["name"] for lab in self.g.labels.values()):
                raise http_error(409, "duplicate")
            lid = self.g.add_user_label(body["name"])
            return copy.deepcopy(self.g.labels[lid])

        return self.g._dispatch("users.labels.create", impl)


class _Messages:
    def __init__(self, g: FakeGmail) -> None:
        self.g = g

    def list(self, userId: str, q: str = "", maxResults: int = 100, pageToken: str | None = None) -> FakeRequest:  # noqa: N803
        def impl() -> dict[str, Any]:
            stored = sorted(self.g.messages.values(), key=lambda m: int(m["internalDate"]), reverse=True)
            refs = [{"id": m["id"], "threadId": m["threadId"]} for m in stored] + self.g.extra_list_ids
            start = int(pageToken or 0)
            page = refs[start : start + maxResults]
            res: dict[str, Any] = {"messages": page, "resultSizeEstimate": len(refs)}
            if start + maxResults < len(refs):
                res["nextPageToken"] = str(start + maxResults)
            return res

        return self.g._dispatch("users.messages.list", impl)

    def get(self, userId: str, id: str, format: str = "full") -> FakeRequest:  # noqa: A002,N803
        def impl() -> dict[str, Any]:
            m = self.g.messages.get(id)
            if m is None:
                raise http_error(404, "notFound")
            return copy.deepcopy(m) if format == "full" else FakeGmail._minimal(m)

        return self.g._dispatch("users.messages.get", impl)

    def modify(self, userId: str, id: str, body: dict[str, Any]) -> FakeRequest:  # noqa: A002,N803
        def impl() -> dict[str, Any]:
            m = self.g.messages.get(id)
            if m is None:
                raise http_error(404, "notFound")
            for lid in body.get("addLabelIds", []) + body.get("removeLabelIds", []):
                if lid not in self.g.labels:
                    raise http_error(400, "invalidArgument")
            labels = [x for x in m["labelIds"] if x not in body.get("removeLabelIds", [])]
            labels += [x for x in body.get("addLabelIds", []) if x not in labels]
            m["labelIds"] = labels
            self.g._bump(m)
            return FakeGmail._minimal(m)

        return self.g._dispatch("users.messages.modify", impl)


class _Threads:
    def __init__(self, g: FakeGmail) -> None:
        self.g = g

    def get(self, userId: str, id: str, format: str = "minimal") -> FakeRequest:  # noqa: A002,N803
        def impl() -> dict[str, Any]:
            msgs = [FakeGmail._minimal(m) for m in self.g.messages.values() if m["threadId"] == id]
            if not msgs:
                raise http_error(404, "notFound")
            msgs.sort(key=lambda m: int(m["internalDate"]))
            return {"id": id, "historyId": str(max(int(m["historyId"]) for m in msgs)), "messages": msgs}

        return self.g._dispatch("users.threads.get", impl)


class _Drafts:
    def __init__(self, g: FakeGmail) -> None:
        self.g = g

    def list(self, userId: str, maxResults: int = 100, pageToken: str | None = None) -> FakeRequest:  # noqa: N803
        def impl() -> dict[str, Any]:
            all_drafts = list(self.g.drafts.values())
            start = int(pageToken or 0)
            page = all_drafts[start : start + maxResults]
            res: dict[str, Any] = {
                "drafts": [
                    {"id": d["id"], "message": {"id": d["message"]["id"], "threadId": d["message"]["threadId"]}}
                    for d in page
                ]
            }
            if start + maxResults < len(all_drafts):
                res["nextPageToken"] = str(start + maxResults)
            return res

        return self.g._dispatch("users.drafts.list", impl)

    def get(self, userId: str, id: str, format: str = "metadata") -> FakeRequest:  # noqa: A002,N803
        def impl() -> dict[str, Any]:
            d = self.g.drafts.get(id)
            if d is None:
                raise http_error(404, "notFound")
            em = message_from_bytes(base64.urlsafe_b64decode(d["message"]["raw"] + "=="))
            headers = [{"name": k, "value": str(v)} for k, v in em.items()]
            return {
                "id": id,
                "message": {
                    "id": d["message"]["id"],
                    "threadId": d["message"]["threadId"],
                    "payload": {"headers": headers},
                },
            }

        return self.g._dispatch("users.drafts.get", impl)

    def create(self, userId: str, body: dict[str, Any]) -> FakeRequest:  # noqa: N803
        def impl() -> dict[str, Any]:
            did = f"r-{self.g._next_draft}"
            self.g._next_draft += 1
            msg = body["message"]
            self.g.drafts[did] = {
                "id": did,
                "message": {"id": f"m-{did}", "threadId": msg["threadId"], "raw": msg["raw"]},
            }
            return {"id": did, "message": {"id": f"m-{did}", "threadId": msg["threadId"]}}

        return self.g._dispatch("users.drafts.create", impl)


class TrapService:
    """A service that HAS dangerous methods; reaching any of them fails the test loudly."""

    def __init__(self) -> None:
        self.reached: list[str] = []

    def users(self) -> TrapService:
        return self

    def messages(self) -> TrapService:
        return self

    def drafts(self) -> TrapService:
        return self

    def threads(self) -> TrapService:
        return self

    def labels(self) -> TrapService:
        return self

    def settings(self) -> TrapService:
        self.reached.append("settings")
        return self

    def __getattr__(self, name: str) -> Any:
        def trap(*a: Any, **k: Any) -> Any:
            self.reached.append(name)
            raise AssertionError(f"FORBIDDEN REACHED: {name}")

        return trap
