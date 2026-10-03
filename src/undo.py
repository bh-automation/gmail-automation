"""Conflict-aware reversal of an audited APPLY run.

Preflight (before ANY mutation) checks every touched message:
* the current Gmail state equals the audited after-state (else STATE_DRIFT),
* no later, not-undone run changed the same message (else LATER_RUN - undo newest first),
* every label of the original state still exists (else LABEL_MISSING),
* the policy allows each restore (APPLY profile + explicit --apply; the capability flag is
  not required, so the kill switch never blocks recovery).
Any conflict -> CONFLICT and the mailbox stays untouched.

If a Gmail call fails midway, the already-reverted messages are put back into their
pre-undo state (compensation) -> ROLLED_BACK. Only if that compensation fails too, the
result is PARTIAL with the exact message lists. Without `--apply` undo only previews.
Drafts are listed for manual review: deleting a draft is a permanent delete (never in V1).
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
from .errors import GmailApiError, GmailAutomationError
from .gmail_client import GmailClient, LabelRef
from .labels import LabelResolver
from .policy import ActionType, PolicyContext, authorize


@dataclass
class UndoResult:
    status: str  # NOTHING | PREVIEW | CONFLICT | DONE | ROLLED_BACK | PARTIAL
    run_id: str
    undo_run_id: str
    reverted: int = 0
    conflicts: list[dict[str, Any]] = field(default_factory=list)
    manual_drafts: list[str] = field(default_factory=list)
    planned: list[dict[str, Any]] = field(default_factory=list)
    error_code: str = ""
    still_reverted: list[str] = field(default_factory=list)  # PARTIAL: undone, compensation failed
    unknown: list[str] = field(default_factory=list)  # PARTIAL: state unknown (pending reconciliation)


@dataclass
class _Item:
    mid: str
    current: tuple[str, ...]  # state before undo (= audited after-state)
    original: tuple[str, ...]  # state to restore
    acts: list[dict[str, Any]]
    add: list[LabelRef] = field(default_factory=list)
    remove: list[LabelRef] = field(default_factory=list)


def _labels(state: str | None) -> tuple[str, ...]:
    try:
        return tuple(sorted(json.loads(state or "{}").get("labels", [])))
    except (ValueError, AttributeError, TypeError):
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

    def read(mid: str) -> tuple[str, ...]:
        return resolver.app_label_names(client.get_message(mid, "minimal").get("labelIds"))

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

    # ------------------------------------------------------------------ preflight (read-only)
    items: list[_Item] = []
    for mid, acts in groups.items():
        original = _labels(acts[0]["before_state"])
        expected_now = _labels(acts[-1]["after_state"])
        later = ledger.later_applied_label_actions(mid, max(a["applied_seq"] for a in acts), run_id)
        if later:
            res.conflicts.append(
                {"message_id": mid, "reason": "LATER_RUN", "later_runs": sorted({r["run_id"] for r in later})}
            )
            continue
        try:
            current = read(mid)
        except GmailApiError as exc:
            res.conflicts.append({"message_id": mid, "reason": exc.code})
            continue
        if current != expected_now:
            res.conflicts.append(
                {"message_id": mid, "reason": "STATE_DRIFT", "expected": list(expected_now), "current": list(current)}
            )
            continue
        item = _Item(mid, current, original, acts)
        try:
            item.add = [resolver.require(n) for n in sorted(set(original) - set(current))]
            item.remove = [resolver.require(n) for n in sorted(set(current) - set(original))]
        except GmailAutomationError as exc:
            res.conflicts.append({"message_id": mid, "reason": exc.code})
            continue
        items.append(item)

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

    res.planned = [{"message_id": i.mid, "from": list(i.current), "to": list(i.original)} for i in items]
    if not apply:
        audit("UNDO_END", outcome="PREVIEW")
        res.status = "PREVIEW"
        return res

    # Policy preflight: every restore must be authorised before the first mutation.
    for i in items:
        for ref in i.add:
            authorize(ActionType.LABEL_ADD, ctx, label_name=ref.name, confidence=None, origin="undo")
        for ref in i.remove:
            authorize(ActionType.LABEL_REMOVE, ctx, label_name=ref.name, confidence=None, origin="undo")

    # ------------------------------------------------------------------ apply
    done: list[_Item] = []  # messages this undo changed - compensated if a later step fails
    undone_ids: set[str] = set()
    for i in items:
        if not i.add and not i.remove:
            continue
        undo_action = i.acts[-1]["action_id"]
        audit(
            "UNDO_PREPARE",
            action_id=undo_action,
            message_id=i.mid,
            thread_id=i.acts[-1]["thread_id"],
            action_type="LABEL_CHANGE",
            before_state={"labels": list(i.current)},
            after_state={"labels": list(i.original)},
            idempotency_key="undo:" + secrets.token_hex(8),
        )
        error = ""
        try:
            client.modify_message_labels(i.mid, add=i.add, remove=i.remove, confidence=None, origin="undo")
        except GmailAutomationError as exc:
            error = exc.code
        try:
            after: tuple[str, ...] | None = read(i.mid)
        except GmailAutomationError:
            after = None
        if after == i.original:  # restored (even if the response was lost)
            _mark_undone(audit, i, i.original)
            done.append(i)
            undone_ids.add(i.mid)
            res.reverted += 1
            out(f"  zurueckgesetzt: {i.mid[:8]}... -> {', '.join(i.original) or '(keine App-Labels)'}")
            continue
        if after is None:
            res.unknown.append(i.mid)  # UNDO_PREPARE stays pending -> reconciled on the next APPLY run
            res.error_code = error or "VERIFY_UNREADABLE"
        else:
            res.error_code = error or "VERIFY_MISMATCH"
            audit(
                "UNDO_FAILED",
                action_id=undo_action,
                message_id=i.mid,
                outcome="FAILED",
                error_code=res.error_code,
                after_state={"labels": list(after)},
            )
            if after != i.current:
                done.append(i)  # changed, but not as planned: put it back as well
        break

    if not res.error_code:
        audit("UNDO_END", outcome="DONE", detail={"reverted": res.reverted})
        res.status = "DONE"
        return res

    # ------------------------------------------------------------------ compensation (all-or-nothing)
    for i in reversed(done):
        if _compensate(client, resolver, audit, i, read):
            if i.mid in undone_ids:
                res.reverted -= 1
        else:
            res.still_reverted.append(i.mid)
    res.status = "PARTIAL" if (res.still_reverted or res.unknown) else "ROLLED_BACK"
    audit(
        "UNDO_END",
        outcome=res.status,
        error_code=res.error_code,
        detail={"reverted": res.reverted, "still_reverted": len(res.still_reverted), "unknown": len(res.unknown)},
    )
    return res


def _mark_undone(audit: Callable[..., None], i: _Item, after: tuple[str, ...]) -> None:
    for a in i.acts:
        audit(
            "UNDONE",
            action_id=a["action_id"],
            message_id=i.mid,
            thread_id=a["thread_id"],
            action_type="LABEL_CHANGE",
            outcome="UNDONE",
            after_state={"labels": list(after)},
        )


def _compensate(
    client: GmailClient,
    resolver: LabelResolver,
    audit: Callable[..., None],
    i: _Item,
    read: Callable[[str], tuple[str, ...]],
) -> bool:
    """Put a message back into its pre-undo state (i.current). True when verified."""
    try:
        now = read(i.mid)
        add = [resolver.require(n) for n in sorted(set(i.current) - set(now))]
        remove = [resolver.require(n) for n in sorted(set(now) - set(i.current))]
        if add or remove:
            client.modify_message_labels(i.mid, add=add, remove=remove, confidence=None, origin="undo")
        restored = read(i.mid)
    except GmailAutomationError:
        return False
    if restored != i.current:
        return False
    for a in i.acts:
        audit(
            "UNDO_COMPENSATED",
            action_id=a["action_id"],
            message_id=i.mid,
            thread_id=a["thread_id"],
            action_type="LABEL_CHANGE",
            outcome="COMPENSATED",
            after_state={"labels": list(restored)},
        )
    return True
