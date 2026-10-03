"""Typed data model shared by scanner, classifier, planner, executor and audit."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class State(StrEnum):
    ACTION = "ACTION"
    WAITING = "WAITING"
    PROJECT = "PROJECT"
    REFERENCE = "REFERENCE"
    DONE = "DONE"
    REVIEW = "REVIEW"


class Band(StrEnum):
    """Confidence band. Only AUTO may lead to a state label or draft."""

    AUTO = "AUTO"  # >= auto threshold (default 0.85)
    REVIEW_LABEL = "REVIEW_LABEL"  # review..auto: REVIEW label only
    REVIEW_ONLY = "REVIEW_ONLY"  # < review threshold: REVIEW, no mutation at all


class AuditAction(StrEnum):
    LABEL_CREATE = "LABEL_CREATE"
    LABEL_CHANGE = "LABEL_CHANGE"
    DRAFT_CREATE = "DRAFT_CREATE"


@dataclass(frozen=True)
class NormalizedMessage:
    id: str
    thread_id: str
    internal_date: int
    label_ids: tuple[str, ...]
    from_address: str
    from_domain: str
    reply_to: str
    subject: str
    message_id_header: str
    references: str
    headers_present: frozenset[str]
    body_text: str
    newest_text: str
    body_source: str  # plain | html | none
    parse_errors: tuple[str, ...]
    fingerprint: str
    guard_text: str = ""  # all parts incl. quoted + hidden text: input for safety guards only

    @property
    def is_sent(self) -> bool:
        return "SENT" in self.label_ids


@dataclass(frozen=True)
class ThreadSnapshot:
    thread_id: str
    message_count: int
    newest_id: str
    history_id: str
    truncated: bool


@dataclass(frozen=True)
class Classification:
    state: State
    confidence: float
    band: Band
    rule_id: str
    reasons: tuple[str, ...]
    draft_template: str | None = None


@dataclass
class PlannedAction:
    kind: AuditAction
    thread_id: str = ""
    message_id: str = ""
    label_name: str = ""  # LABEL_CREATE
    add: tuple[str, ...] = ()  # LABEL_CHANGE (label names)
    remove: tuple[str, ...] = ()
    template_id: str = ""  # DRAFT_CREATE
    rule_id: str = ""
    state: State | None = None
    confidence: float = 0.0
    content_fingerprint: str = ""
    before_labels: tuple[str, ...] = ()
    snapshot: ThreadSnapshot | None = None
    origin: str = "plan"  # plan | undo
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def expected_after_labels(self) -> tuple[str, ...]:
        after = (set(self.before_labels) | set(self.add)) - set(self.remove)
        return tuple(sorted(after))

    def describe(self) -> str:
        if self.kind is AuditAction.LABEL_CREATE:
            return f"create label {self.label_name}"
        if self.kind is AuditAction.LABEL_CHANGE:
            parts = []
            if self.add:
                parts.append("+" + ",".join(self.add))
            if self.remove:
                parts.append("-" + ",".join(self.remove))
            return "labels " + " ".join(parts)
        return f"draft '{self.template_id}' (send blocked)"


@dataclass
class RunSummary:
    run_id: str
    mode: str
    profile: str
    scanned: int = 0
    threads: int = 0
    action_candidates: int = 0
    review: int = 0
    planned_mutations: int = 0
    mutations: int = 0
    skipped_idempotent: int = 0
    skipped_noop: int = 0
    stale: int = 0
    duplicate_drafts: int = 0
    failed: int = 0
    message_failures: int = 0
    quarantined: int = 0
    human_override: int = 0
    drift: int = 0
    read_errors: int = 0
    reconciled: int = 0
    status: str = "RUNNING"
    send_block: str = "UNKNOWN"
    delete_block: str = "UNKNOWN"
    audit: str = "UNKNOWN"

    def gate_lines(self) -> list[str]:
        return [
            f"MODE = {self.mode}",
            f"SCANNED = {self.scanned}",
            f"ACTION_CANDIDATES = {self.action_candidates}",
            f"REVIEW = {self.review}",
            f"MUTATIONS = {self.mutations}",
            f"SEND_BLOCK = {self.send_block}",
            f"DELETE_BLOCK = {self.delete_block}",
            f"AUDIT = {self.audit}",
        ]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
