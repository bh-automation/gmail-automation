"""Run orchestration: scan -> classify -> plan -> authorise -> execute -> verify -> audit.

The classifier only returns data; this module turns it into typed PlannedActions and
hands each one through the policy-gated adapter. Any mutation failure stops the run
(fail closed). Already-applied changes stay audited and undoable.
"""

from __future__ import annotations

import json
import logging
import secrets
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from . import __version__
from .audit import AuditLedger
from .classifier import classify
from .config import Config
from .drafts import build_reply_raw, drafts_in_thread, find_draft_with_key
from .errors import AmbiguousWriteError, FailClosed, GmailApiError, GmailAutomationError, PolicyViolation
from .gmail_client import GmailClient, guard_self_test
from .labels import LabelResolver
from .models import AuditAction, Band, PlannedAction, RunSummary, State
from .policy import CAPABILITY_OF, ActionType, PolicyContext, self_test
from .redaction import fingerprint, redact, truncate_subject
from .scanner import ThreadWork, scan, snapshot_from_thread

log = logging.getLogger("gmail_automation.engine")
Out = Callable[[str], None]

_CAP = {
    AuditAction.LABEL_CREATE: CAPABILITY_OF[ActionType.LABEL_CREATE],
    AuditAction.LABEL_CHANGE: CAPABILITY_OF[ActionType.LABEL_ADD],
    AuditAction.DRAFT_CREATE: CAPABILITY_OF[ActionType.DRAFT_CREATE],
}


def new_run_id() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(3)


def action_key(a: PlannedAction) -> str:
    return fingerprint(
        a.kind.value,
        a.message_id,
        a.thread_id,
        a.content_fingerprint,
        sorted(a.add),
        sorted(a.remove),
        a.template_id,
        a.label_name,
        length=64,
    )


def plan_thread(
    work: ThreadWork,
    cls_state: State,
    band: Band,
    confidence: float,
    rule_id: str,
    draft_template: str | None,
    cfg: Config,
    resolver: LabelResolver,
) -> list[PlannedAction]:
    if band is Band.REVIEW_ONLY:
        return []
    msg = work.message
    target = cfg.label_for(cls_state)
    current = set(resolver.app_label_names(msg.label_ids))
    add = () if target in current else (target,)
    remove = tuple(sorted((current & set(cfg.labels.values())) - {target}))
    base: dict[str, Any] = dict(
        thread_id=msg.thread_id,
        message_id=msg.id,
        rule_id=rule_id,
        state=cls_state,
        confidence=confidence,
        content_fingerprint=msg.fingerprint,
        before_labels=tuple(sorted(current)),
        snapshot=work.snapshot,
    )
    actions: list[PlannedAction] = []
    if add or remove:
        actions.append(PlannedAction(kind=AuditAction.LABEL_CHANGE, add=add, remove=remove, **base))
    if draft_template and band is Band.AUTO and cls_state is State.ACTION:
        actions.append(
            PlannedAction(kind=AuditAction.DRAFT_CREATE, template_id=draft_template, meta={"message": msg}, **base)
        )
    return actions


class Engine:
    def __init__(
        self,
        client: GmailClient,
        cfg: Config,
        ctx: PolicyContext,
        ledger: AuditLedger,
        *,
        out: Out = print,
        run_id: str | None = None,
    ) -> None:
        self.client, self.cfg, self.ctx, self.ledger = client, cfg, ctx, ledger
        self.out = out
        self.run_id = run_id or new_run_id()
        self.resolver = LabelResolver(client, cfg)
        self.summary = RunSummary(run_id=self.run_id, mode=ctx.mode, profile=ctx.profile.value)
        self.error: GmailAutomationError | None = None

    # ------------------------------------------------------------------ audit helper
    def _audit(self, event: str, a: PlannedAction | None = None, **fields: Any) -> int:
        if a is not None:
            fields.setdefault("message_id", a.message_id or None)
            fields.setdefault("thread_id", a.thread_id or None)
            fields.setdefault("action_type", a.kind.value)
            fields.setdefault("rule_id", a.rule_id or None)
            fields.setdefault("confidence", a.confidence if a.kind is not AuditAction.LABEL_CREATE else None)
            fields.setdefault("content_fingerprint", a.content_fingerprint or None)
        return self.ledger.append(
            run_id=self.run_id, profile=self.ctx.profile.value, mode=self.ctx.mode, event=event, **fields
        )

    # ------------------------------------------------------------------ public
    def run(self) -> RunSummary:
        s = self.summary
        self._audit(
            "RUN_START",
            detail={
                "version": __version__,
                "query_fp": fingerprint(self.cfg.gmail_query),
                "max": self.cfg.max_messages_per_run,
                "capabilities": sorted(self.ctx.capabilities),
            },
        )
        try:
            self.resolver.refresh()
            if not self.ctx.dry_run:
                s.reconciled = reconcile_pending(self.client, self.ledger, self.resolver, self.run_id, self.ctx)
            elif self.ledger.pending():
                self.out("HINWEIS: unvollstaendige Aktionen im Audit - naechster APPLY-Lauf gleicht sie ab.")
            result = scan(self.client, self.cfg)
            s.scanned, s.threads, s.read_errors = result.messages_listed, len(result.threads), len(result.skipped)
            for tid, code in result.skipped:
                self._audit("READ_SKIPPED", thread_id=tid, error_code=code)
            plans: list[PlannedAction] = []
            for work in result.threads:
                cls = classify(work.message, work.snapshot, self.cfg)
                if cls.band is Band.AUTO and cls.state is not State.REVIEW:
                    s.action_candidates += 1
                if cls.state is State.REVIEW:
                    s.review += 1
                self._audit(
                    "CLASSIFIED",
                    thread_id=work.snapshot.thread_id,
                    message_id=work.message.id,
                    rule_id=cls.rule_id,
                    confidence=cls.confidence,
                    outcome=f"{cls.state.value}/{cls.band.value}",
                    content_fingerprint=work.message.fingerprint,
                )
                self.out(
                    f"  [{cls.state.value:<9} {cls.confidence:4.2f}] {truncate_subject(work.message.subject)}"
                    f"  ({redact(cls.rule_id, max_len=40)})"
                )
                plans.extend(
                    plan_thread(
                        work,
                        cls.state,
                        cls.band,
                        cls.confidence,
                        cls.rule_id,
                        cls.draft_template,
                        self.cfg,
                        self.resolver,
                    )
                )
            needed = {n for p in plans for n in p.add}
            creates = [
                PlannedAction(kind=AuditAction.LABEL_CREATE, label_name=n) for n in self.resolver.missing(needed)
            ]
            actions = creates + plans
            s.planned_mutations = len(actions)
            for a in actions:
                if self.ctx.dry_run:
                    enabled = _CAP[a.kind] in self.ctx.capabilities
                    self._audit(
                        "PLAN",
                        a,
                        outcome="DRY_RUN" if enabled else "CAPABILITY_OFF",
                        before_state={"labels": list(a.before_labels)} if a.kind is AuditAction.LABEL_CHANGE else None,
                        after_state={"labels": list(a.expected_after_labels)}
                        if a.kind is AuditAction.LABEL_CHANGE
                        else None,
                        detail={"label": a.label_name}
                        if a.label_name
                        else {"template_id": a.template_id}
                        if a.template_id
                        else None,
                    )
                    self.out(f"  plan: {a.describe()}" + ("" if enabled else "  [capability aus]"))
                else:
                    self._execute(a)
            s.status = "OK"
        except FailClosed as exc:
            s.status, self.error = "FAILED_CLOSED", exc
        except GmailAutomationError as exc:
            s.status, self.error = f"ERROR:{exc.code}", exc
        finally:
            self._finish()
        return s

    # ------------------------------------------------------------------ finish + gates
    def _finish(self) -> None:
        s = self.summary
        s.mutations = self.client.mutation_count
        p, g = self_test(), guard_self_test()
        s.send_block = (
            "PASS"
            if (p["send"] and p["draft_send"] and p["constants"] and g["messages.send"] and g["drafts.send"])
            else "FAIL"
        )
        s.delete_block = (
            "PASS"
            if (
                p["permanent_delete"]
                and p["trash"]
                and g["messages.delete"]
                and g["threads.delete"]
                and g["messages.batchDelete"]
                and g["messages.trash"]
            )
            else "FAIL"
        )
        try:
            ok, _ = self.ledger.verify()
            s.audit = "PASS" if ok else "FAIL"
            self._audit("RUN_END", outcome=s.status, error_code=getattr(self.error, "code", None), detail=s.to_dict())
        except GmailAutomationError as exc:
            s.audit = "FAIL"
            if self.error is None:
                self.error = exc
                s.status = f"ERROR:{exc.code}"

    # ------------------------------------------------------------------ execution
    def _fail(self, a: PlannedAction, action_id: str, key: str, code: str, after: Any = None) -> FailClosed:
        self.summary.failed += 1
        self._audit(
            "FAILED",
            a,
            action_id=action_id or None,
            idempotency_key=key,
            outcome="FAILED",
            error_code=code,
            after_state=after,
        )
        return FailClosed(f"Mutation failed ({code}) - run stopped (fail closed)", code=code)

    def _execute(self, a: PlannedAction) -> None:
        s = self.summary
        if _CAP[a.kind] not in self.ctx.capabilities:
            self._audit("SKIPPED_CAPABILITY", a, outcome="SKIPPED")
            return
        key = action_key(a)
        if self.ledger.is_key_applied(key):
            s.skipped_idempotent += 1
            self._audit("SKIPPED_IDEMPOTENT", a, idempotency_key=key, outcome="SKIPPED")
            return
        if a.kind is AuditAction.LABEL_CREATE:
            self._create_label(a, key)
            return
        if not self._fresh(a):
            return
        if a.kind is AuditAction.LABEL_CHANGE:
            self._change_labels(a, key)
        else:
            self._create_draft(a, key)

    def _fresh(self, a: PlannedAction) -> bool:
        """Stale scan-to-apply race protection: thread and labels must be unchanged since the scan."""
        assert a.snapshot is not None  # noqa: S101 - planner invariant
        try:
            now = snapshot_from_thread(self.client.get_thread(a.thread_id, "minimal"), self.cfg.max_thread_messages)
            current_msg = self.client.get_message(a.message_id, "minimal")
        except GmailApiError as exc:
            if exc.code in {"API_NOT_FOUND", "EMPTY_THREAD"}:
                self.summary.stale += 1
                self._audit("STALE", a, outcome="THREAD_GONE")
                return False
            raise
        if now.newest_id != a.snapshot.newest_id or now.message_count != a.snapshot.message_count:
            self.summary.stale += 1
            self._audit("STALE", a, outcome="THREAD_CHANGED")
            self.out(f"  stale: Thread hat neue Nachrichten - uebersprungen ({a.describe()})")
            return False
        current = self.resolver.app_label_names(current_msg.get("labelIds"))
        if a.kind is AuditAction.LABEL_CHANGE and current != a.before_labels:
            if current == a.expected_after_labels:
                self.summary.skipped_noop += 1
                self._audit("SKIPPED_NOOP", a, outcome="ALREADY_IN_STATE")
            else:
                self.summary.stale += 1
                self._audit("STALE", a, outcome="LABELS_CHANGED")
            return False
        return True

    def _create_label(self, a: PlannedAction, key: str) -> None:
        if self.resolver.resolve(a.label_name):
            self.summary.skipped_noop += 1
            self._audit("SKIPPED_NOOP", a, outcome="LABEL_EXISTS", detail={"label": a.label_name})
            return
        action_id = secrets.token_hex(8)
        self._audit(
            "PREPARE",
            a,
            action_id=action_id,
            idempotency_key=key,
            detail={"label": a.label_name},
            after_state={"label": a.label_name},
        )
        try:
            ref = self.resolver.create(a.label_name)
        except GmailAutomationError as exc:
            if exc.code == "API_CONFLICT" or isinstance(exc, AmbiguousWriteError):
                self.resolver.refresh()
                ref2 = self.resolver.resolve(a.label_name)
                if ref2:
                    self._audit(
                        "RECONCILED_APPLIED",
                        a,
                        action_id=action_id,
                        idempotency_key=key,
                        after_state={"label": a.label_name, "label_id": ref2.id},
                    )
                    return
            raise self._fail(a, action_id, key, exc.code) from None
        self._audit(
            "APPLIED",
            a,
            action_id=action_id,
            idempotency_key=key,
            outcome="APPLIED",
            after_state={"label": a.label_name, "label_id": ref.id},
        )
        self.out(f"  angewendet: {a.describe()}")

    def _change_labels(self, a: PlannedAction, key: str) -> None:
        expected = a.expected_after_labels
        try:
            add_refs = [self.resolver.require(n) for n in a.add]
            remove_refs = [self.resolver.require(n) for n in a.remove]
        except GmailAutomationError as exc:
            raise self._fail(a, "", key, exc.code) from None
        action_id = secrets.token_hex(8)
        self._audit(
            "PREPARE",
            a,
            action_id=action_id,
            idempotency_key=key,
            before_state={"labels": list(a.before_labels)},
            after_state={"labels": list(expected)},
            detail={"add": list(a.add), "remove": list(a.remove)},
        )
        try:
            self.client.modify_message_labels(
                a.message_id, add=add_refs, remove=remove_refs, confidence=a.confidence, origin=a.origin
            )
        except GmailAutomationError as exc:
            raise self._fail(a, action_id, key, exc.code) from None
        try:
            after = self.resolver.app_label_names(self.client.get_message(a.message_id, "minimal").get("labelIds"))
        except GmailApiError as exc:
            raise self._fail(a, action_id, key, "VERIFY_" + exc.code) from None
        if after != expected:
            raise self._fail(a, action_id, key, "VERIFY_MISMATCH", after={"labels": list(after)})
        self._audit(
            "APPLIED",
            a,
            action_id=action_id,
            idempotency_key=key,
            outcome="APPLIED",
            before_state={"labels": list(a.before_labels)},
            after_state={"labels": list(after)},
        )
        self.out(f"  angewendet: {a.describe()}")

    def _create_draft(self, a: PlannedAction, key: str) -> None:
        if self.ledger.draft_applied(a.thread_id, a.template_id) or drafts_in_thread(self.client, a.thread_id):
            self.summary.duplicate_drafts += 1
            self._audit("SKIPPED_DUPLICATE_DRAFT", a, outcome="DRAFT_EXISTS", detail={"template_id": a.template_id})
            return
        msg = a.meta.get("message")
        template = self.cfg.draft_templates.get(a.template_id)
        if msg is None or template is None:
            raise FailClosed("Draft plan incomplete", code="DRAFT_PLAN_INVALID")
        action_id = secrets.token_hex(8)
        try:
            raw = build_reply_raw(msg, template, key)
        except PolicyViolation as exc:
            self._audit("SKIPPED_UNSAFE", a, outcome="SKIPPED", error_code=exc.code)
            return
        self._audit("PREPARE", a, action_id=action_id, idempotency_key=key, detail={"template_id": a.template_id})
        assert a.state is not None  # noqa: S101
        try:
            res = self.client.create_draft(a.thread_id, raw, confidence=a.confidence, state=a.state)
        except AmbiguousWriteError as exc:
            found = find_draft_with_key(self.client, a.thread_id, key)
            if found:
                self._audit(
                    "RECONCILED_APPLIED",
                    a,
                    action_id=action_id,
                    idempotency_key=key,
                    after_state={"draft_id": found},
                    detail={"template_id": a.template_id},
                )
                return
            raise self._fail(a, action_id, key, exc.code) from None
        except GmailAutomationError as exc:
            raise self._fail(a, action_id, key, exc.code) from None
        self._audit(
            "APPLIED",
            a,
            action_id=action_id,
            idempotency_key=key,
            outcome="APPLIED",
            after_state={"draft_id": str(res.get("id", ""))},
            detail={"template_id": a.template_id},
        )
        self.out(f"  angewendet: {a.describe()}")


def _labels_of(state_json: str | None) -> tuple[str, ...]:
    try:
        return tuple(sorted(json.loads(state_json or "{}").get("labels", [])))
    except (ValueError, AttributeError):
        return ()


def reconcile_pending(
    client: GmailClient, ledger: AuditLedger, resolver: LabelResolver, run_id: str, ctx: PolicyContext
) -> int:
    """Settle PREPARE rows without outcome (crash between prepare and audit completion)."""
    count = 0

    def note(event: str, p: dict[str, Any], **kw: Any) -> None:
        fields: dict[str, Any] = {
            "action_id": p["action_id"],
            "message_id": p["message_id"],
            "thread_id": p["thread_id"],
            "action_type": p["action_type"],
            "idempotency_key": p["idempotency_key"],
            "before_state": p["before_state"],
            "after_state": p["after_state"],
        }
        fields.update(kw)
        ledger.append(run_id=run_id, profile=ctx.profile.value, mode=ctx.mode, event=event, **fields)

    for p in ledger.pending():
        count += 1
        kind = p["action_type"]
        if kind == AuditAction.LABEL_CHANGE.value:
            try:
                cur = resolver.app_label_names(client.get_message(p["message_id"], "minimal").get("labelIds"))
            except GmailApiError:
                note("RECONCILED_DRIFT", p, outcome="MESSAGE_UNAVAILABLE")
                continue
            if cur == _labels_of(p["after_state"]):
                note("RECONCILED_APPLIED", p, outcome="APPLIED")
            elif cur == _labels_of(p["before_state"]):
                note("RECONCILED_NOT_APPLIED", p, outcome="NOT_APPLIED")
            else:
                note("RECONCILED_DRIFT", p, outcome="DRIFT")
        elif kind == AuditAction.LABEL_CREATE.value:
            label = json.loads(p["detail"] or "{}").get("label", "")
            note("RECONCILED_APPLIED" if resolver.resolve(label) else "RECONCILED_NOT_APPLIED", p)
        else:
            found = find_draft_with_key(client, p["thread_id"], p["idempotency_key"])
            note(
                "RECONCILED_APPLIED" if found else "RECONCILED_NOT_APPLIED",
                p,
                detail=p["detail"],
                after_state={"draft_id": found} if found else None,
            )
    for p in ledger.pending_undo():
        count += 1
        try:
            cur = resolver.app_label_names(client.get_message(p["message_id"], "minimal").get("labelIds"))
        except GmailApiError:
            note("UNDO_RECONCILED_DRIFT", p, outcome="MESSAGE_UNAVAILABLE")
            continue
        if cur == _labels_of(p["after_state"]):
            note("UNDO_RECONCILED_DONE", p)
        elif cur == _labels_of(p["before_state"]):
            note("UNDO_RECONCILED_NOT_DONE", p)
        else:
            note("UNDO_RECONCILED_DRIFT", p)
    return count
