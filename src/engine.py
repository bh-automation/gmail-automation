"""Run orchestration: scan -> classify -> plan -> authorise -> execute -> verify -> audit.

The classifier only returns data; this module turns it into typed PlannedActions and
hands each one through the policy-gated adapter.

Failure handling (fail closed, but no single poison message blocks everything):
* global errors (auth, scope, policy, audit, retries exhausted, budget, unknown) stop the run;
* message-scoped errors (400/404/409 for one message) are audited as FAILED and the run
  continues; after QUARANTINE_AFTER consecutive failures a message is quarantined;
* a write whose outcome is unknown is re-read and settled immediately, or left PENDING
  for reconciliation - it is never recorded as a terminal FAILED if it may have happened;
* a change the human made after this program's last change wins (SKIPPED_HUMAN_OVERRIDE).
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
from .errors import (
    AmbiguousWriteError,
    FailClosed,
    GmailApiError,
    GmailAutomationError,
    InternalError,
    PolicyViolation,
    TransientExhaustedError,
)
from .gmail_client import GmailClient, guard_self_test, transport_self_test
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
# Errors that concern exactly one message; everything else is global and stops the run.
MESSAGE_SCOPED_CODES = frozenset({"API_CLIENT", "API_NOT_FOUND", "API_CONFLICT"})
QUARANTINE_AFTER = 3
_UNKNOWN_OUTCOME = (TransientExhaustedError, AmbiguousWriteError)


def new_run_id() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(8)


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
        retry_quarantined: bool = False,
    ) -> None:
        self.client, self.cfg, self.ctx, self.ledger = client, cfg, ctx, ledger
        self.out = out
        self.retry_quarantined = retry_quarantined
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
        try:
            self._audit(
                "RUN_START",
                detail={
                    "version": __version__,
                    "query_fp": fingerprint(self.cfg.gmail_query),
                    "max": self.cfg.max_messages_per_run,
                    "capabilities": sorted(self.ctx.capabilities),
                },
            )
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
                if cls.band is not Band.REVIEW_ONLY and self._human_override(work):
                    continue
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
            s.status = "PARTIAL" if (s.message_failures or s.drift or s.quarantined) else "OK"
        except FailClosed as exc:
            s.status, self.error = "FAILED_CLOSED", exc
        except GmailAutomationError as exc:
            s.status, self.error = f"ERROR:{exc.code}", exc
        except KeyboardInterrupt:
            s.status = "ABORTED"
            self.error = FailClosed("Run aborted by the user (Ctrl+C)", code="ABORTED")
            raise  # `finally` still writes RUN_END with status ABORTED
        except Exception as exc:  # noqa: BLE001 - unexpected types are converted, never leaked as tracebacks
            name = type(exc).__name__
            log.error("internal error %s - run stopped fail-closed", name)
            s.status = "FAILED_CLOSED"
            self.error = InternalError(f"Internal error ({name}) - run stopped fail-closed", code=f"INTERNAL_{name}")
        finally:
            self._finish()
        return s

    def _human_override(self, work: ThreadWork) -> bool:
        """The human's decision wins: app labels changed since this program last set them, or app
        labels already present on first contact (set by a person or another client)."""
        last = self.ledger.last_set_labels(work.message.id)
        current = self.resolver.app_label_names(work.message.label_ids)
        if current == (last if last is not None else ()):
            return False
        self.summary.human_override += 1
        self._audit(
            "SKIPPED_HUMAN_OVERRIDE",
            thread_id=work.snapshot.thread_id,
            message_id=work.message.id,
            content_fingerprint=work.message.fingerprint,
            before_state={"labels": list(last)} if last is not None else None,
            after_state={"labels": list(current)},
            outcome="HUMAN_DECISION_WINS",
        )
        self.out("  manuell geaendert - die Entscheidung des Menschen bleibt bestehen (keine Aktion)")
        return True

    # ------------------------------------------------------------------ finish + gates
    def _finish(self) -> None:
        s = self.summary
        s.mutations = self.client.mutation_count
        p, g, t = self_test(), guard_self_test(), transport_self_test()
        s.send_block = (
            "PASS"
            if (
                p["send"]
                and p["draft_send"]
                and p["constants"]
                and g["messages.send"]
                and g["drafts.send"]
                and t["messages.send"]
                and t["drafts.send"]
            )
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
                and t["messages.delete"]
                and t["messages.trash"]
                and t["modify.TRASH"]
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
    def _app_labels_now(self, message_id: str) -> tuple[str, ...]:
        return self.resolver.app_label_names(self.client.get_message(message_id, "minimal").get("labelIds"))

    def _failed(self, a: PlannedAction, action_id: str, key: str, code: str, after: Any = None) -> None:
        """Audit FAILED. Message-scoped errors let the run continue; everything else stops it."""
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
        if code in MESSAGE_SCOPED_CODES and a.kind is not AuditAction.LABEL_CREATE:
            self.summary.message_failures += 1
            self.out(f"  FEHLER bei einer Nachricht ({code}) - uebersprungen, der Lauf geht weiter")
            return
        raise FailClosed(f"Mutation failed ({code}) - run stopped (fail closed)", code=code)

    def _execute(self, a: PlannedAction) -> None:
        s = self.summary
        if _CAP[a.kind] not in self.ctx.capabilities:
            self._audit("SKIPPED_CAPABILITY", a, outcome="SKIPPED")
            return
        key = action_key(a)
        if a.kind is AuditAction.LABEL_CREATE:
            # The mailbox is the source of truth for labels: a label the user deleted is created again.
            self._create_label(a, key)
            return
        if self.ledger.is_key_applied(key):
            s.skipped_idempotent += 1
            self._audit("SKIPPED_IDEMPOTENT", a, idempotency_key=key, outcome="SKIPPED")
            return
        if (
            not self.retry_quarantined
            and self.ledger.failure_streak(a.message_id, MESSAGE_SCOPED_CODES) >= QUARANTINE_AFTER
        ):
            s.quarantined += 1
            self._audit("SKIPPED_QUARANTINED", a, idempotency_key=key, outcome="QUARANTINED")
            self.out(f"  QUARANTAENE: Nachricht scheiterte {QUARANTINE_AFTER}x - uebersprungen ({a.describe()})")
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
            self._failed(a, action_id, key, exc.code)
            return
        self._audit(
            "APPLIED",
            a,
            action_id=action_id,
            idempotency_key=key,
            outcome="APPLIED",
            after_state={"label": a.label_name, "label_id": ref.id},
        )
        self.out(f"  angewendet: {a.describe()}")

    def _settle_observed(self, a: PlannedAction, action_id: str, key: str, current: tuple[str, ...], code: str) -> None:
        """Record what Gmail really shows after a write with unknown outcome."""
        if current == a.expected_after_labels:
            event, outcome = "RECONCILED_APPLIED", "APPLIED"
        elif current == a.before_labels:
            event, outcome = "RECONCILED_NOT_APPLIED", "NOT_APPLIED"
        else:
            event, outcome = "RECONCILED_DRIFT", "DRIFT"
        self._audit(
            event,
            a,
            action_id=action_id,
            idempotency_key=key,
            outcome=outcome,
            error_code=code,
            before_state={"labels": list(a.before_labels)},
            after_state={"labels": list(current)},
        )

    def _outcome_unknown(self, a: PlannedAction, action_id: str, key: str, code: str) -> FailClosed:
        """Leave the PREPARE pending (non-terminal); the next APPLY run reconciles it."""
        self._audit("OUTCOME_UNKNOWN", a, action_id=action_id, idempotency_key=key, outcome="PENDING", error_code=code)
        return FailClosed(f"Outcome unknown ({code}) - left pending for reconciliation", code=code)

    def _change_labels(self, a: PlannedAction, key: str) -> None:
        expected = a.expected_after_labels
        try:
            add_refs = [self.resolver.require(n) for n in a.add]
            remove_refs = [self.resolver.require(n) for n in a.remove]
        except GmailAutomationError as exc:
            self._failed(a, "", key, exc.code)
            return
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
            resp = self.client.modify_message_labels(
                a.message_id, add=add_refs, remove=remove_refs, confidence=a.confidence, origin=a.origin
            )
        except _UNKNOWN_OUTCOME as exc:
            # The request may have reached Gmail (5xx / network): look, record the truth, then stop.
            try:
                current = self._app_labels_now(a.message_id)
            except GmailAutomationError:
                raise self._outcome_unknown(a, action_id, key, exc.code) from None
            self._settle_observed(a, action_id, key, current, exc.code)
            raise FailClosed(
                f"Gmail unstable ({exc.code}) - run stopped after settling the change", code=exc.code
            ) from None
        except GmailAutomationError as exc:  # rejected before or by Gmail: definitely not applied
            self._failed(a, action_id, key, exc.code)
            return
        verify_error: GmailAutomationError | None = None
        try:
            after = self._app_labels_now(a.message_id)
            source = "read"
        except GmailAutomationError as exc:
            resp_labels = resp.get("labelIds") if isinstance(resp, dict) else None
            if not isinstance(resp_labels, list):
                raise self._outcome_unknown(a, action_id, key, "VERIFY_" + exc.code) from None
            after, source, verify_error = self.resolver.app_label_names(resp_labels), "response", exc
        if after == expected:
            self._audit(
                "APPLIED",
                a,
                action_id=action_id,
                idempotency_key=key,
                outcome="APPLIED",
                before_state={"labels": list(a.before_labels)},
                after_state={"labels": list(after)},
                detail={"verified_by": source},
            )
            self.out(f"  angewendet: {a.describe()}")
        else:
            # Gmail accepted the write, but the labels differ (filter / second client): applied with drift.
            self.summary.drift += 1
            self._audit(
                "APPLIED_DRIFT",
                a,
                action_id=action_id,
                idempotency_key=key,
                outcome="VERIFY_MISMATCH",
                error_code="VERIFY_MISMATCH",
                before_state={"labels": list(a.before_labels)},
                after_state={"labels": list(after)},
                detail={"verified_by": source, "expected": list(expected)},
            )
            self.out(f"  ABWEICHUNG: Labels nach dem Schreiben anders als erwartet ({a.describe()})")
        if verify_error is not None and verify_error.code not in MESSAGE_SCOPED_CODES:
            raise FailClosed(f"Verification read failed ({verify_error.code}) - run stopped", code=verify_error.code)

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
            try:
                found = find_draft_with_key(self.client, a.thread_id, key)
            except GmailAutomationError:
                raise self._outcome_unknown(a, action_id, key, exc.code) from None
            self._audit(
                "RECONCILED_APPLIED" if found else "RECONCILED_NOT_APPLIED",
                a,
                action_id=action_id,
                idempotency_key=key,
                outcome="APPLIED" if found else "NOT_APPLIED",
                error_code=exc.code,
                after_state={"draft_id": found} if found else None,
                detail={"template_id": a.template_id},
            )
            if found:
                return
            raise FailClosed(f"Draft creation failed ({exc.code}) - run stopped", code=exc.code) from None
        except GmailAutomationError as exc:
            self._failed(a, action_id, key, exc.code)
            return
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
            except GmailApiError as exc:
                if exc.code != "API_NOT_FOUND":
                    raise  # transient/auth: the row stays pending, the run fails closed
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
        except GmailApiError as exc:
            if exc.code != "API_NOT_FOUND":
                raise
            note("UNDO_RECONCILED_DRIFT", p, outcome="MESSAGE_UNAVAILABLE")
            continue
        if cur == _labels_of(p["after_state"]):
            note("UNDO_RECONCILED_DONE", p)
        elif cur == _labels_of(p["before_state"]):
            note("UNDO_RECONCILED_NOT_DONE", p)
        else:
            note("UNDO_RECONCILED_DRIFT", p)
    return count
