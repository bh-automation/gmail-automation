"""Gmail query, pagination and bounded fetch strategy.

messages.list (bounded by max_messages_per_run) -> unique threads -> threads.get(minimal)
-> only the newest message of each thread is fetched in full. Threads with hundreds of
replies therefore cost one metadata call plus one message fetch.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from .config import Config
from .errors import GmailApiError
from .gmail_client import GmailClient
from .mime import normalize_message
from .models import NormalizedMessage, ThreadSnapshot

log = logging.getLogger("gmail_automation.scanner")


@dataclass
class ThreadWork:
    snapshot: ThreadSnapshot
    message: NormalizedMessage


@dataclass
class ScanResult:
    messages_listed: int = 0
    pages: int = 0
    threads: list[ThreadWork] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)


def _newest(messages: list[dict[str, Any]]) -> dict[str, Any]:
    def key(m: dict[str, Any]) -> tuple[int, str]:
        try:
            return int(m.get("internalDate") or 0), str(m.get("id", ""))
        except (TypeError, ValueError):
            return 0, str(m.get("id", ""))

    return max(messages, key=key)


def _is_draft(m: dict[str, Any]) -> bool:
    labels = m.get("labelIds") or []
    return isinstance(labels, list) and "DRAFT" in labels


def snapshot_from_thread(thread: dict[str, Any], max_messages: int) -> ThreadSnapshot:
    """Newest REAL message of a thread. Draft messages (including this program's own reply
    drafts) are ignored, so a draft is never classified as if it were incoming mail."""
    msgs = [m for m in (thread.get("messages") or []) if isinstance(m, dict) and m.get("id") and not _is_draft(m)]
    if not msgs:
        raise GmailApiError("Thread without (non-draft) messages", code="EMPTY_THREAD")
    truncated = len(msgs) > max_messages
    newest = _newest(msgs)
    return ThreadSnapshot(
        thread_id=str(thread.get("id", "")),
        message_count=len(msgs),
        newest_id=str(newest["id"]),
        history_id=str(thread.get("historyId", "")),
        truncated=truncated,
    )


def scan(client: GmailClient, cfg: Config) -> ScanResult:
    result = ScanResult()
    refs, pages = client.list_message_refs(cfg.gmail_query, cfg.max_messages_per_run)
    result.messages_listed, result.pages = len(refs), pages
    thread_ids: list[str] = []
    for ref in refs:
        if ref["threadId"] not in thread_ids:
            thread_ids.append(ref["threadId"])
    for tid in thread_ids:
        try:
            thread = client.get_thread(tid, "minimal")
            snap = snapshot_from_thread(thread, cfg.max_thread_messages)
            full = client.get_message(snap.newest_id, "full")
        except GmailApiError as exc:
            if exc.code in {"API_NOT_FOUND", "EMPTY_THREAD"}:
                result.skipped.append((tid, exc.code))  # deleted between list and fetch: recorded, not silent
                continue
            raise
        msg = normalize_message(full, max_body_chars=cfg.max_body_chars, max_raw_bytes=cfg.max_raw_body_bytes)
        result.threads.append(ThreadWork(snapshot=snap, message=msg))
    return result
