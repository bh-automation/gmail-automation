import pytest

from src.errors import PolicyViolation
from src.models import State
from src.policy import (
    ALLOW_PERMANENT_DELETE,
    ALLOW_SEND,
    FORBIDDEN_ALWAYS,
    ActionType,
    PolicyContext,
    Profile,
    authorize,
    self_test,
)

FULL = PolicyContext(profile=Profile.APPLY, apply_flag=True, capabilities=frozenset({"labels", "drafts"}))


# --- the four original starter tests (kept verbatim in spirit) -------------------------------
def test_send_hard_block():
    with pytest.raises(PolicyViolation) as e:
        authorize(ActionType.SEND, FULL, confidence=1.0, state=State.ACTION)
    assert e.value.code == "FORBIDDEN_ACTION"


def test_delete_hard_block():
    with pytest.raises(PolicyViolation):
        authorize(ActionType.PERMANENT_DELETE, FULL)


def test_dry_run_blocks_mutation():
    ctx = PolicyContext(profile=Profile.APPLY, apply_flag=False, capabilities=frozenset({"labels"}))
    assert ctx.dry_run
    with pytest.raises(PolicyViolation) as e:
        authorize(ActionType.LABEL_ADD, ctx, label_name="JARVIS/ACTION", confidence=0.99)
    assert e.value.code == "APPLY_GATE"


def test_apply_allows_approved_action():
    authorize(ActionType.LABEL_ADD, FULL, label_name="JARVIS/ACTION", confidence=0.9)


# --- extended invariants ----------------------------------------------------------------------
@pytest.mark.parametrize("act", sorted(FORBIDDEN_ALWAYS))
def test_every_forbidden_action_denied_even_with_all_gates_open(act):
    with pytest.raises(PolicyViolation):
        authorize(act, FULL, label_name="JARVIS/ACTION", confidence=1.0, state=State.ACTION)


@pytest.mark.parametrize("name", ["cleanup", "delete_all", "archive", "", "SEND"])
def test_unknown_or_disguised_actions_denied(name):
    with pytest.raises(PolicyViolation) as e:
        authorize(name, FULL)
    assert e.value.code == "UNKNOWN_ACTION"


def test_observe_profile_never_mutates_even_with_apply_flag():
    ctx = PolicyContext(profile=Profile.OBSERVE, apply_flag=True, capabilities=frozenset({"labels"}))
    assert ctx.dry_run
    with pytest.raises(PolicyViolation) as e:
        authorize(ActionType.LABEL_ADD, ctx, label_name="JARVIS/ACTION", confidence=1.0)
    assert e.value.code == "OBSERVE_READ_ONLY"


def test_capability_gate_is_separate_from_apply_flag():
    ctx = PolicyContext(profile=Profile.APPLY, apply_flag=True, capabilities=frozenset())
    with pytest.raises(PolicyViolation) as e:
        authorize(ActionType.LABEL_ADD, ctx, label_name="JARVIS/ACTION", confidence=1.0)
    assert e.value.code == "CAPABILITY_GATE"
    ctx2 = PolicyContext(profile=Profile.APPLY, apply_flag=True, capabilities=frozenset({"labels"}))
    with pytest.raises(PolicyViolation):
        authorize(ActionType.DRAFT_CREATE, ctx2, confidence=1.0, state=State.ACTION)


@pytest.mark.parametrize("label", ["INBOX", "TRASH", "SPAM", "Privat/Steuer", "JARVIS/", "jarvis/action", None])
def test_only_application_labels(label):
    with pytest.raises(PolicyViolation):
        authorize(ActionType.LABEL_ADD, FULL, label_name=label, confidence=1.0)


def test_confidence_thresholds():
    with pytest.raises(PolicyViolation):  # 0.84 < auto for a state label
        authorize(ActionType.LABEL_ADD, FULL, label_name="JARVIS/ACTION", confidence=0.84)
    authorize(ActionType.LABEL_ADD, FULL, label_name="JARVIS/REVIEW", confidence=0.60)  # review label at 0.60
    with pytest.raises(PolicyViolation):
        authorize(ActionType.LABEL_ADD, FULL, label_name="JARVIS/REVIEW", confidence=0.59)
    with pytest.raises(PolicyViolation):
        authorize(ActionType.DRAFT_CREATE, FULL, confidence=0.99, state=State.WAITING)
    with pytest.raises(PolicyViolation):
        authorize(ActionType.DRAFT_CREATE, FULL, confidence=0.80, state=State.ACTION)
    authorize(ActionType.DRAFT_CREATE, FULL, confidence=0.86, state=State.ACTION)


def test_undo_origin_is_label_only():
    authorize(ActionType.LABEL_REMOVE, FULL, label_name="JARVIS/ACTION", origin="undo")
    with pytest.raises(PolicyViolation):
        authorize(ActionType.DRAFT_CREATE, FULL, origin="undo", state=State.ACTION, confidence=1)
    with pytest.raises(PolicyViolation):
        authorize(ActionType.LABEL_ADD, FULL, label_name="JARVIS/ACTION", origin="llm")


def test_invariant_constants_and_self_test():
    assert ALLOW_SEND is False and ALLOW_PERMANENT_DELETE is False
    assert all(self_test().values())
