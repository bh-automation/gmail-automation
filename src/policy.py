"""Central capability policy (safety kernel).

Every state-changing operation is authorised here - by the executor AND again by the
Gmail adapter (defence in depth). Unknown actions are denied. SEND and permanent
DELETE are hard invariants that no configuration, flag or message content can lift.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

from .errors import PolicyViolation
from .models import State

ALLOW_SEND: Final[bool] = False
ALLOW_PERMANENT_DELETE: Final[bool] = False

if ALLOW_SEND or ALLOW_PERMANENT_DELETE:  # pragma: no cover - tamper tripwire
    raise RuntimeError("Safety invariant tampered: send/permanent-delete must stay disabled in V1")


class Profile(StrEnum):
    OBSERVE = "observe"
    APPLY = "apply"


class ActionType(StrEnum):
    LABEL_CREATE = "label_create"
    LABEL_ADD = "label_add"
    LABEL_REMOVE = "label_remove"
    DRAFT_CREATE = "draft_create"
    # Always forbidden in V1:
    SEND = "send"
    DRAFT_SEND = "draft_send"
    PERMANENT_DELETE = "permanent_delete"
    TRASH = "trash"
    FORWARD = "forward"
    FILTER_CREATE = "filter_create"
    SETTINGS_CHANGE = "settings_change"


MUTATION_ALLOWLIST_V1: Final = frozenset(
    {ActionType.LABEL_CREATE, ActionType.LABEL_ADD, ActionType.LABEL_REMOVE, ActionType.DRAFT_CREATE}
)
FORBIDDEN_ALWAYS: Final = frozenset(
    {
        ActionType.SEND,
        ActionType.DRAFT_SEND,
        ActionType.PERMANENT_DELETE,
        ActionType.TRASH,
        ActionType.FORWARD,
        ActionType.FILTER_CREATE,
        ActionType.SETTINGS_CHANGE,
    }
)
CAPABILITY_OF: Final = {
    ActionType.LABEL_CREATE: "labels",
    ActionType.LABEL_ADD: "labels",
    ActionType.LABEL_REMOVE: "labels",
    ActionType.DRAFT_CREATE: "drafts",
}

# Gmail system labels. Adding TRASH/SPAM via modify would be a destructive move - never allowed.
SYSTEM_LABEL_IDS: Final = frozenset(
    {
        "INBOX",
        "SPAM",
        "TRASH",
        "UNREAD",
        "STARRED",
        "IMPORTANT",
        "SENT",
        "DRAFT",
        "CHAT",
        "CATEGORY_PERSONAL",
        "CATEGORY_SOCIAL",
        "CATEGORY_PROMOTIONS",
        "CATEGORY_UPDATES",
        "CATEGORY_FORUMS",
    }
)
USER_LABEL_ID_RE: Final = re.compile(r"Label_[0-9]+")


@dataclass(frozen=True)
class PolicyContext:
    profile: Profile = Profile.OBSERVE
    apply_flag: bool = False  # only the explicit CLI flag `--apply` may set this
    capabilities: frozenset[str] = field(default_factory=frozenset)
    auto_threshold: float = 0.85
    review_threshold: float = 0.60
    label_prefix: str = "JARVIS/"
    review_label: str = "JARVIS/REVIEW"

    @property
    def dry_run(self) -> bool:
        return not (self.profile is Profile.APPLY and self.apply_flag)

    @property
    def mode(self) -> str:
        return "DRY-RUN" if self.dry_run else "APPLY"


def is_app_label_name(name: str, ctx: PolicyContext) -> bool:
    return (
        bool(ctx.label_prefix)
        and name.startswith(ctx.label_prefix)
        and len(name) > len(ctx.label_prefix)
        and name.upper() not in SYSTEM_LABEL_IDS
    )


def is_user_label_id(label_id: str) -> bool:
    return label_id not in SYSTEM_LABEL_IDS and USER_LABEL_ID_RE.fullmatch(label_id) is not None


def authorize(
    action: ActionType | str,
    ctx: PolicyContext,
    *,
    label_name: str | None = None,
    confidence: float | None = None,
    state: State | None = None,
    origin: str = "plan",
) -> ActionType:
    """Raise PolicyViolation unless `action` is permitted right now. Returns the typed action."""
    try:
        act = ActionType(action)
    except ValueError:
        raise PolicyViolation(f"Unknown action denied: {action!r}", code="UNKNOWN_ACTION") from None

    if act in FORBIDDEN_ALWAYS:
        raise PolicyViolation(f"Forbidden invariant: {act.value}", code="FORBIDDEN_ACTION")
    if act not in MUTATION_ALLOWLIST_V1:  # pragma: no cover - enum is exhaustive today
        raise PolicyViolation(f"Action not in V1 allow-list: {act.value}", code="NOT_ALLOWLISTED")
    if ctx.profile is not Profile.APPLY:
        raise PolicyViolation("OBSERVE profile cannot mutate the mailbox", code="OBSERVE_READ_ONLY")
    if not ctx.apply_flag:
        raise PolicyViolation("Mutation denied: explicit --apply gate not satisfied", code="APPLY_GATE")
    if ctx.dry_run:  # pragma: no cover - implied by the two checks above
        raise PolicyViolation("Mutation denied in DRY-RUN", code="DRY_RUN")
    cap = CAPABILITY_OF[act]
    # Undo restores an audited earlier state of application labels. It still needs APPLY
    # profile + explicit --apply, but not the capability flag: switching capabilities off
    # (kill switch) must never block the recovery of a bad run.
    if cap not in ctx.capabilities and origin != "undo":
        raise PolicyViolation(f"Capability '{cap}' is not enabled in config", code="CAPABILITY_GATE")

    if act in (ActionType.LABEL_CREATE, ActionType.LABEL_ADD, ActionType.LABEL_REMOVE) and (
        label_name is None or not is_app_label_name(label_name, ctx)
    ):
        raise PolicyViolation(
            f"Only application labels ({ctx.label_prefix}*) may be touched", code="LABEL_NOT_APPROVED"
        )

    if origin == "undo":
        if act not in (ActionType.LABEL_ADD, ActionType.LABEL_REMOVE):
            raise PolicyViolation("Undo may only restore application labels", code="UNDO_SCOPE")
        return act
    if origin != "plan":
        raise PolicyViolation(f"Unknown action origin {origin!r}", code="UNKNOWN_ORIGIN")

    if act is ActionType.DRAFT_CREATE:
        if state is not State.ACTION or confidence is None or confidence < ctx.auto_threshold:
            raise PolicyViolation("Draft requires state ACTION with auto-level confidence", code="CONFIDENCE_GATE")
    elif act is ActionType.LABEL_ADD:
        needed = ctx.review_threshold if label_name == ctx.review_label else ctx.auto_threshold
        if confidence is None or confidence < needed:
            raise PolicyViolation("Confidence below threshold for this label", code="CONFIDENCE_GATE")
    elif act is ActionType.LABEL_REMOVE and (confidence is None or confidence < ctx.review_threshold):
        raise PolicyViolation("Confidence below review threshold", code="CONFIDENCE_GATE")
    return act


def self_test() -> dict[str, bool]:
    """Runtime proof that the hard blocks hold. Used in every gate summary."""
    strongest = PolicyContext(profile=Profile.APPLY, apply_flag=True, capabilities=frozenset({"labels", "drafts"}))
    results: dict[str, bool] = {}
    for key, act in (
        ("send", ActionType.SEND),
        ("draft_send", ActionType.DRAFT_SEND),
        ("permanent_delete", ActionType.PERMANENT_DELETE),
        ("trash", ActionType.TRASH),
    ):
        try:
            authorize(act, strongest, confidence=1.0, state=State.ACTION)
            results[key] = False
        except PolicyViolation:
            results[key] = True
    results["constants"] = (ALLOW_SEND is False) and (ALLOW_PERMANENT_DELETE is False)
    return results
