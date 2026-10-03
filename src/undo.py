"""Conflict-aware reversal of an audited APPLY run.

Preflight compares the current Gmail state of every touched message with the audited
expected after-state. Any drift -> CONFLICT and the mailbox stays untouched (all-or-nothing).
Without `--apply` undo only previews. Drafts are listed for manual review: deleting a
draft is a permanent delete, which V1 never performs.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .audit import AuditLedger
from .config import Config
from .engine import new_run_id, reconcile_pending
from .errors import FailClosed, GmailApiError, GmailAutomationError
from .gmail_client import GmailClient
from .labels import LabelResolver
from .policy import PolicyContext


@dataclass
class UndoResult:
    status: str  # NOTHING | PREVIEW | CONFLICT | DONE
    run_id: str
    undo_run_id: str
    reverted: int = 0
    conflicts: list[dict[str, Any]] = field(default_factory=list)
    manual_drafts: list[str] = field(default_factory=list)
    planned: list[dict[str, Any]] = field(default_factory=list)


def _labels(state: str | None) -> tuple[str, ...]:
    try:
        return tuple(sorted(json.loads(state or "{}").get("labels", [])))
    except (ValueError, AttributeError):
        return ()


def undo_run(
    client: GmailClient,
    cfg: Config,
    ctx: PolicyContext,
    ledger: AuditLedger,
    run_id: str,
    *,
    apply: bool,
    out: Callable[[str], None] = print,
) -> UndoResult:
    undo_id = new_run_id()
    res = UndoResult(status="NOTHING", run_id=run_id, undo_run_id=undo_id)
    resolver = LabelResolver(client, cfg)
    resolver.refresh()
    if apply:
        reconcile_pending(client, ledger, resolver, undo_id, ctx)

    def audit(event: str, **kw: Any) -> None:
        ledger.append(
            run_id=undo_id, profile=ctx.profile.value, mode="APPLY" if apply else "DRY-RUN", event=event, **kw
        )

    actions = [a for a in ledger.applied_actions(run_id) if not a["undone"]]
    res.manual_drafts = [
        str(json.loads(a["after_state"] or "{}").get("draft_id", "?"))
        for a in actions
        if a["action_type"] == "DRAFT_CREATE"
    ]
    label_actions = [a for a in actions if a["action_type"] == "LABEL_CHANGE"]
    audit(
        "UNDO_START",
        detail={"target_run": run_id, "label_actions": len(label_actions), "manual_drafts": len(res.manual_drafts)},
    )
    if not label_actions:
        audit("UNDO_END", outcome="NOTHING")
        return res

    groups: dict[str, list[dict[str, Any]]] = {}
    for a in label_actions:
        groups.setdefault(a["message_id"], []).append(a)

    plan: list[tuple[str, tuple[str, ...], tuple[str, ...], list[dict[str, Any]]]] = []
    for mid, acts in groups.items():
        original = _labels(acts[0]["before_state"])
        expected_now = _labels(acts[-1]["after_state"])
        try:
            current = resolver.app_label_names(client.get_message(mid, "minimal").get("labelIds"))
        except GmailApiError as exc:
            res.conflicts.append({"message_id": mid, "reason": exc.code})
            continue
        if current != expected_now:
            res.conflicts.append(
                {"message_id": mid, "reason": "STATE_DRIFT", "expected": list(expected_now), "current": list(current)}
            )
            continue
        plan.append((mid, current, original, acts))

    if res.conflicts:
        for c in res.conflicts:
            for a in groups.get(c["message_id"], []):
                audit(
                    "UNDO_CONFLICT",
                    action_id=a["action_id"],
                    message_id=c["message_id"],
                    thread_id=a["thread_id"],
                    action_type="LABEL_CHANGE",
                    outcome="CONFLICT",
                    error_code=c["reason"],
                )
        audit("UNDO_END", outcome="CONFLICT")
        res.status = "CONFLICT"
        return res

    res.planned = [{"message_id": m, "from": list(cur), "to": list(orig)} for m, cur, orig, _ in plan]
    if not apply:
        audit("UNDO_END", outcome="PREVIEW")
        res.status = "PREVIEW"
        return res

    for mid, current, original, acts in plan:
        add = sorted(set(original) - set(current))
        remove = sorted(set(current) - set(original))
        if not add and not remove:
            continue
        try:
            add_refs = [resolver.require(n) for n in add]
            remove_refs = [resolver.require(n) for n in remove]
        except GmailAutomationError as exc:
            audit("UNDO_FAILED", message_id=mid, outcome="FAILED", error_code=exc.code)
            audit("UNDO_END", outcome="FAILED_CLOSED")
            raise FailClosed(f"Undo stopped ({exc.code})", code=exc.code) from None
        last = acts[-1]
        undo_action = last["action_id"]
        audit(
            "UNDO_PREPARE",
            action_id=undo_action,
            message_id=mid,
            thread_id=last["thread_id"],
            action_type="LABEL_CHANGE",
            before_state={"labels": list(current)},
            after_state={"labels": list(original)},
            idempotency_key="undo:" + secrets.token_hex(8),
        )
        try:
            client.modify_message_labels(mid, add=add_refs, remove=remove_refs, confidence=None, origin="undo")
            after = resolver.app_label_names(client.get_message(mid, "minimal").get("labelIds"))
        except GmailAutomationError as exc:
            audit("UNDO_FAILED", action_id=undo_action, message_id=mid, outcome="FAILED", error_code=exc.code)
            audit("UNDO_END", outcome="FAILED_CLOSED")
            raise FailClosed(f"Undo stopped ({exc.code})", code=exc.code) from None
        if after != original:
            audit(
                "UNDO_FAILED",
                action_id=undo_action,
                message_id=mid,
                outcome="FAILED",
                error_code="VERIFY_MISMATCH",
                after_state={"labels": list(after)},
            )
            audit("UNDO_END", outcome="FAILED_CLOSED")
            raise FailClosed("Undo verification mismatch", code="VERIFY_MISMATCH")
        for a in acts:
            audit(
                "UNDONE",
                action_id=a["action_id"],
                message_id=mid,
                thread_id=a["thread_id"],
                action_type="LABEL_CHANGE",
                outcome="UNDONE",
                after_state={"labels": list(after)},
            )
        res.reverted += 1
        out(f"  zurueckgesetzt: {mid[:8]}... -> {', '.join(original) or '(keine App-Labels)'}")
    audit("UNDO_END", outcome="DONE", detail={"reverted": res.reverted})
    res.status = "DONE"
    return res
