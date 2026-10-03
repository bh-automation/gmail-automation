from src.undo import undo_run
from tests.conftest import client_for, ctx_for, run_engine
from tests.fakes import FakeGmail, make_message


def mailbox():
    g = FakeGmail()
    g.add(
        make_message(
            "m1", "t1", subject="News", extra_headers={"List-Unsubscribe": "<x>"}, internal_date=1_700_000_002_000
        )
    )
    g.add(
        make_message("m2", "t2", subject="Vertrag", plain="Bitte unterschreiben Sie.", internal_date=1_700_000_001_000)
    )
    return g


def app_labels(g, mid):
    return sorted(n for n in g.label_names(mid) if n.startswith("JARVIS/"))


def do_undo(g, cfg, ledger, run_id, apply):
    return undo_run(
        client_for(g, cfg, apply=apply), cfg, ctx_for(cfg, apply=apply), ledger, run_id, apply=apply, out=lambda s: None
    )


def test_undo_preview_then_apply_restores_exact_state(cfg_apply, ledger):
    g = mailbox()
    s, _ = run_engine(g, cfg_apply, ledger, apply=True)
    assert app_labels(g, "m1") == ["JARVIS/REFERENCE"] and app_labels(g, "m2") == ["JARVIS/ACTION"]
    calls = len(g.mutation_calls())
    prev = do_undo(g, cfg_apply, ledger, s.run_id, apply=False)
    assert prev.status == "PREVIEW" and len(g.mutation_calls()) == calls  # preview never mutates
    res = do_undo(g, cfg_apply, ledger, s.run_id, apply=True)
    assert res.status == "DONE" and res.reverted == 2
    assert app_labels(g, "m1") == [] and app_labels(g, "m2") == []
    assert "INBOX" in g.label_names("m1")
    assert res.manual_drafts and len(g.drafts) == 1  # drafts are never deleted automatically
    assert ledger.last_undoable_run() is None
    assert ledger.verify()[0]


def test_undo_conflict_leaves_mailbox_untouched(cfg_apply, ledger):
    g = mailbox()
    s, _ = run_engine(g, cfg_apply, ledger, apply=True)
    g.messages["m1"]["labelIds"].append(g.add_user_label("JARVIS/DONE"))  # the human moved on
    before = {mid: list(m["labelIds"]) for mid, m in g.messages.items()}
    calls = len(g.mutation_calls())
    res = do_undo(g, cfg_apply, ledger, s.run_id, apply=True)
    assert res.status == "CONFLICT" and res.conflicts[0]["reason"] == "STATE_DRIFT"
    assert len(g.mutation_calls()) == calls
    assert {mid: list(m["labelIds"]) for mid, m in g.messages.items()} == before  # all-or-nothing
    assert [r for r in ledger.rows() if r["event"] == "UNDO_CONFLICT"]


def test_undo_conflict_when_message_disappeared(cfg_apply, ledger):
    g = mailbox()
    s, _ = run_engine(g, cfg_apply, ledger, apply=True)
    del g.messages["m2"]
    res = do_undo(g, cfg_apply, ledger, s.run_id, apply=True)
    assert res.status == "CONFLICT" and res.conflicts[0]["reason"] == "API_NOT_FOUND"


def test_undo_non_latest_run(cfg_apply, ledger):
    g = mailbox()
    s1, _ = run_engine(g, cfg_apply, ledger, apply=True)
    g.add(
        make_message(
            "m3", "t3", subject="News 2", extra_headers={"List-Unsubscribe": "<y>"}, internal_date=1_700_000_009_000
        )
    )
    s2, _ = run_engine(g, cfg_apply, ledger, apply=True)
    assert app_labels(g, "m3") == ["JARVIS/REFERENCE"]
    res = do_undo(g, cfg_apply, ledger, s1.run_id, apply=True)
    assert res.status == "DONE"
    assert app_labels(g, "m1") == [] and app_labels(g, "m3") == ["JARVIS/REFERENCE"]  # run 2 untouched
    assert ledger.last_undoable_run() == s2.run_id


def test_undo_twice_is_nothing(cfg_apply, ledger):
    g = mailbox()
    s, _ = run_engine(g, cfg_apply, ledger, apply=True)
    assert do_undo(g, cfg_apply, ledger, s.run_id, apply=True).status == "DONE"
    calls = len(g.mutation_calls())
    assert do_undo(g, cfg_apply, ledger, s.run_id, apply=True).status == "NOTHING"
    assert len(g.mutation_calls()) == calls


def test_undo_requires_apply_profile_to_mutate(cfg_apply, ledger):
    g = mailbox()
    s, _ = run_engine(g, cfg_apply, ledger, apply=True)
    res = do_undo(g, cfg_apply, ledger, s.run_id, apply=False)
    assert res.status == "PREVIEW" and app_labels(g, "m1") == ["JARVIS/REFERENCE"]


def test_undo_after_later_run_changed_same_message_is_conflict(cfg_apply, ledger):
    g = mailbox()
    s1, _ = run_engine(g, cfg_apply, ledger, apply=True)
    # content of m1 changes -> reclassified by a later run (now a signature request)
    g.messages["m1"]["payload"] = make_message("m1", "t1", plain="Bitte unterschreiben")["payload"]
    run_engine(g, cfg_apply, ledger, apply=True)
    assert app_labels(g, "m1") == ["JARVIS/ACTION"]
    res = do_undo(g, cfg_apply, ledger, s1.run_id, apply=True)
    assert res.status == "CONFLICT"
