import pytest

from src.errors import (
    AmbiguousWriteError,
    AuthError,
    GmailApiError,
    PolicyViolation,
    ScopeError,
    TransientExhaustedError,
)
from src.gmail_client import (
    APPLY_ENDPOINTS,
    OBSERVE_ENDPOINTS,
    GmailClient,
    LabelRef,
    _GuardedResource,
    guard_self_test,
)
from src.models import State
from src.retry import RetryPolicy
from tests.conftest import client_for, ctx_for, make_config
from tests.fakes import FakeGmail, TrapService, http_error, make_message

CFG = make_config(capabilities={"labels": True, "drafts": True})


@pytest.mark.parametrize(
    "path",
    [
        "users.messages.send",
        "users.drafts.send",
        "users.messages.delete",
        "users.threads.delete",
        "users.messages.batchDelete",
        "users.messages.trash",
        "users.threads.trash",
        "users.messages.batchModify",
        "users.messages.insert",
        "users.messages.import_",
        "users.labels.delete",
        "users.drafts.delete",
    ],
)
def test_guard_blocks_forbidden_endpoints_before_reaching_service(path):
    trap = TrapService()
    root = _GuardedResource(trap, "", APPLY_ENDPOINTS)
    *resources, method = path.split(".")
    node = root
    with pytest.raises(PolicyViolation):
        for r in resources:
            node = getattr(node, r)()
        getattr(node, method)
    assert trap.reached == []


def test_guard_blocks_settings_forwarding_and_filters():
    trap = TrapService()
    root = _GuardedResource(trap, "", APPLY_ENDPOINTS)
    with pytest.raises(PolicyViolation):
        root.users().settings
    assert trap.reached == []


def test_guard_denies_private_access_and_is_immutable():
    root = _GuardedResource(TrapService(), "", APPLY_ENDPOINTS)
    with pytest.raises(AttributeError):
        root._g_inner  # noqa: B018
    with pytest.raises(PolicyViolation):
        root.users = lambda: None


def test_observe_allowlist_excludes_every_mutation():
    assert not {"users.messages.modify", "users.labels.create", "users.drafts.create"} & OBSERVE_ENDPOINTS


def test_runtime_guard_self_test_passes():
    assert all(guard_self_test().values())


def test_observe_client_cannot_mutate_and_never_reaches_fake():
    g = FakeGmail()
    g.add(make_message("m1", "t1"))
    lid = g.add_user_label("JARVIS/ACTION")
    client = client_for(g, CFG, apply=False)
    with pytest.raises(PolicyViolation):
        client.modify_message_labels("m1", add=[LabelRef(lid, "JARVIS/ACTION")], remove=[], confidence=1.0)
    with pytest.raises(PolicyViolation):
        client.create_label("JARVIS/NEW")
    with pytest.raises(PolicyViolation):
        client.create_draft("t1", "cmF3", confidence=1.0, state=State.ACTION)
    # even bypassing the public method, the OBSERVE guard has no modify endpoint
    with pytest.raises(PolicyViolation):
        client._users().messages().modify
    assert g.mutation_calls() == [] and client.mutation_count == 0


def test_monkeypatched_send_method_still_blocked(monkeypatch):
    g = FakeGmail()
    client = client_for(g, CFG, apply=True)

    def send(self, raw):  # an attacker/bug adds a send path to the adapter
        return self._users().messages().send(userId="me", body={"raw": raw}).execute()

    monkeypatch.setattr(GmailClient, "send", send, raising=False)
    with pytest.raises(PolicyViolation) as e:
        client.send("cmF3")
    assert e.value.code == "FORBIDDEN_ENDPOINT"


@pytest.mark.parametrize(
    "ref",
    [
        LabelRef("TRASH", "JARVIS/ACTION"),
        LabelRef("INBOX", "INBOX"),
        LabelRef("Label_7", "Privat"),
        LabelRef("SPAM", "SPAM"),
    ],
)
def test_system_and_foreign_labels_refused(ref):
    g = FakeGmail()
    g.add(make_message("m1", "t1"))
    client = client_for(g, CFG, apply=True)
    with pytest.raises(PolicyViolation):
        client.modify_message_labels("m1", add=[ref], remove=[], confidence=1.0)
    with pytest.raises(PolicyViolation):
        client.modify_message_labels("m1", add=[], remove=[ref], confidence=1.0)
    assert g.mutation_calls() == []


# ---------------------------------------------------------------------------- retry policy
def test_429_honours_retry_after_then_succeeds():
    g = FakeGmail()
    g.fault("users.labels.list", http_error(429, "rateLimitExceeded", retry_after=7))
    slept = []
    client = GmailClient(g, ctx_for(CFG, apply=False), retry=RetryPolicy(max_attempts=3), sleep=slept.append)
    assert client.list_labels()
    assert len(slept) == 1 and slept[0] >= 7


def test_403_rate_limit_is_retried_but_403_permission_fails_closed():
    g = FakeGmail()
    g.fault("users.labels.list", http_error(403, "userRateLimitExceeded"))
    client = client_for(g, CFG, apply=False)
    assert client.list_labels()
    g.fault("users.labels.list", http_error(403, "insufficientPermissions"), http_error(403, "x"))
    with pytest.raises(ScopeError) as e:
        client.list_labels()
    assert e.value.code == "AUTH_403"
    assert g.calls.count("users.labels.list") == 3  # no retry on the permission error


def test_5xx_and_network_retries_are_bounded():
    g = FakeGmail()
    g.fault("users.labels.list", *[http_error(503, "backendError")] * 10)
    client = client_for(g, CFG, apply=False)
    with pytest.raises(TransientExhaustedError):
        client.list_labels()
    assert g.calls.count("users.labels.list") == 4
    g2 = FakeGmail()
    g2.fault("users.labels.list", TimeoutError("timed out"), ConnectionResetError())
    assert client_for(g2, CFG, apply=False).list_labels()


def test_401_refreshes_exactly_once_no_loop():
    g = FakeGmail()
    refreshes = []
    g.fault("users.labels.list", http_error(401, "authError"))
    client = client_for(g, CFG, apply=False, refresh=lambda: refreshes.append(1))
    assert client.list_labels()
    assert refreshes == [1]
    g.fault("users.labels.list", http_error(401), http_error(401), http_error(401))
    refreshes.clear()
    with pytest.raises(AuthError) as e:
        client.list_labels()
    assert e.value.code == "AUTH_401" and refreshes == [1]


def test_non_idempotent_write_is_never_blindly_retried():
    g = FakeGmail()
    g.add(make_message("m1", "t1"))
    g.fault("users.drafts.create", http_error(503, "backendError"))
    client = client_for(g, CFG, apply=True)
    with pytest.raises(AmbiguousWriteError):
        client.create_draft("t1", "cmF3", confidence=0.9, state=State.ACTION)
    assert g.calls.count("users.drafts.create") == 1


def test_404_is_not_retried():
    g = FakeGmail()
    client = client_for(g, CFG, apply=False)
    with pytest.raises(GmailApiError) as e:
        client.get_message("nope")
    assert e.value.code == "API_NOT_FOUND"
    assert g.calls.count("users.messages.get") == 1


def test_pagination_is_bounded_by_limit():
    g = FakeGmail()
    g.extra_list_ids = [{"id": f"x{i}", "threadId": f"t{i}"} for i in range(50_000)]
    client = client_for(g, CFG, apply=False)
    refs, pages = client.list_message_refs("in:inbox", limit=250, page_size=100)
    assert len(refs) == 250 and pages == 3


def test_raw_format_denied():
    with pytest.raises(PolicyViolation):
        client_for(FakeGmail(), CFG, apply=False).get_message("m1", fmt="raw")
