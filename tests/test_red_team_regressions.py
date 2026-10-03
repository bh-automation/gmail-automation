"""Regression tests for every Red Team A/B finding (docs/RED_TEAM_A_REPORT.md, RED_TEAM_B_REPORT.md).

Each test is the inverted proof of concept: it reproduces the attack/fault and asserts the
secure behaviour. IDs in the test names map to the report findings.
"""

from __future__ import annotations

import errno
import http.client
import json
import os
import shutil
import socket
import sqlite3
import ssl
from pathlib import Path

import httplib2
import pytest
import yaml

from src import cli
from src.audit import AuditLedger
from src.auth import validate_scopes
from src.classifier import classify
from src.config import load_config
from src.drafts import build_reply_raw, drafts_in_thread, find_draft_with_key
from src.engine import Engine, new_run_id
from src.errors import (
    EXIT_INTERNAL,
    AuditIntegrityError,
    AuditUnavailableError,
    ConfigError,
    GmailApiError,
    PolicyViolation,
    ScopeError,
    TransientExhaustedError,
)
from src.gmail_client import GuardedHttp, check_transport
from src.mime import decode_header_value, normalize_message, strip_quoted_text
from src.policy import Profile
from src.redaction import sanitize_line
from src.retry import ErrorKind, RetryPolicy, _retry_after
from src.retry import classify as classify_error
from src.scanner import snapshot_from_thread
from src.undo import undo_run
from tests.conftest import BASE_CONFIG, client_for, ctx_for, make_config, run_engine
from tests.fakes import AfterApply, FakeGmail, http_error, make_message

SIGN = "Hallo, bitte unterschreiben Sie den Vertrag."
N = {"max_body_chars": 100_000, "max_raw_bytes": 2_000_000}
LABELS_ONLY = make_config(capabilities={"labels": True})


def mailbox() -> FakeGmail:
    g = FakeGmail()
    g.add(
        make_message(
            "m1", "t1", subject="Newsletter", extra_headers={"List-Unsubscribe": "<x>"}, internal_date=1_700_000_003_000
        )
    )
    g.add(make_message("m2", "t2", subject="Vertrag", plain=SIGN, internal_date=1_700_000_002_000))
    return g


def app(g: FakeGmail, mid: str) -> list[str]:
    return sorted(n for n in g.label_names(mid) if n.startswith("JARVIS/"))


def undo(g, cfg, led, run_id, apply=True):
    return undo_run(
        client_for(g, cfg, apply=apply), cfg, ctx_for(cfg, apply=apply), led, run_id, apply=apply, out=lambda s: None
    )


def events(led, name):
    return [r for r in led.rows() if r["event"] == name]


def write_cfg(tmp_path: Path, **over) -> str:
    data = json.loads(json.dumps(BASE_CONFIG))
    data.update(over)
    p = tmp_path / "rules.yaml"
    p.write_text(yaml.safe_dump(data), encoding="utf-8")
    return str(p)


# ====================================================================== Red Team A
@pytest.mark.parametrize("sep", ["\u2028", "\u2029", "\x85", "\x0b", "\x1c"])
def test_A_F1_unicode_line_separator_in_subject_never_crashes(cfg_apply, ledger, sep):
    g = FakeGmail()
    g.add(make_message("m1", "t1", subject="Vertrag" + sep + "x", plain="bitte unterschreiben", internal_date=9))
    g.add(make_message("m2", "t2", subject="News", extra_headers={"List-Unsubscribe": "<x>"}, internal_date=1))
    for _ in range(2):  # used to crash every APPLY run (persistent DoS)
        s, eng = run_engine(g, cfg_apply, ledger, apply=True)
        assert s.status == "OK" and eng.error is None
    assert len(g.drafts) == 1 and app(g, "m2") == ["JARVIS/REFERENCE"]
    assert len(decode_header_value("a" + sep + "b").splitlines()) == 1


def test_A_F1_header_encoder_errors_become_policy_violation(monkeypatch):
    from src import drafts

    msg = normalize_message(make_message("m1", "t1", plain="x"), **N)
    monkeypatch.setattr(drafts, "_safe_subject", lambda s: "a\u2028b")  # bypass the normaliser on purpose
    with pytest.raises(PolicyViolation) as e:
        build_reply_raw(msg, "Hallo", "k" * 64)
    assert e.value.code == "DRAFT_HEADER_INVALID"


def test_A_F2_cross_domain_reply_to_is_ignored_same_domain_kept():
    hostile = normalize_message(
        make_message(
            "m1",
            "t1",
            from_="Partner <partner@trusted.example>",
            plain="x",
            extra_headers={"Reply-To": "collect@attacker.example"},
        ),
        **N,
    )
    raw = build_reply_raw(hostile, "Hallo", "k" * 64)
    import base64
    from email import message_from_bytes

    to = message_from_bytes(base64.urlsafe_b64decode(raw))["To"]
    assert to == "partner@trusted.example"
    friendly = normalize_message(
        make_message(
            "m2", "t2", from_="a@trusted.example", plain="x", extra_headers={"Reply-To": "team@trusted.example"}
        ),
        **N,
    )
    to2 = message_from_bytes(base64.urlsafe_b64decode(build_reply_raw(friendly, "Hallo", "k" * 64)))["To"]
    assert to2 == "team@trusted.example"


def test_A_F3_unexpected_exception_type_fails_closed_with_run_end(cfg_apply, ledger):
    g = mailbox()
    g.labels["broken"] = None  # malformed labels.list entry -> AttributeError deep inside
    s, eng = run_engine(g, cfg_apply, ledger, apply=True)
    assert s.status == "FAILED_CLOSED" and eng.error is not None
    assert eng.error.code == "INTERNAL_AttributeError" and eng.error.exit_code == EXIT_INTERNAL
    ends = events(ledger, "RUN_END")
    assert ends and ends[-1]["outcome"] == "FAILED_CLOSED" and g.mutation_calls() == []


def test_A_F3_cli_last_line_of_defence(data_dir, tmp_path, capsys):
    def factory(profile):
        raise RuntimeError("ya29." + "x" * 40)

    rc = cli.main(["scan", "--config", write_cfg(tmp_path)], service_factory=factory)
    out = capsys.readouterr()
    assert rc == EXIT_INTERNAL and "INTERNAL_RuntimeError" in out.out
    assert "ya29." not in out.out + out.err and "Traceback" not in out.err


@pytest.mark.parametrize("granted", [5, {"scope": "x"}, [1, 2], b"gmail.readonly"])
def test_A_F3_scope_report_with_wrong_type_fails_closed(granted):
    with pytest.raises(ScopeError) as e:
        validate_scopes(Profile.OBSERVE, granted)
    assert e.value.code == "SCOPE_FORMAT"


@pytest.mark.parametrize("pattern", [r"(a+)+$", r"(a*)*b", r"(\w+\s*)*$", r"(?:x+y*)+z", r"((ab)+)+"])
def test_A_F4_catastrophic_regex_is_rejected_at_config_load(pattern):
    rules = [{"id": "bad", "state": "ACTION", "confidence": 0.9, "when": {"body_regex": pattern}}]
    with pytest.raises(ConfigError) as e:
        make_config(rules=rules)
    assert "nests unbounded quantifiers" in str(e.value)


def test_A_F4_safe_and_possessive_regexes_are_accepted():
    for pattern in (r"(?i)\b(bitte (unterschreiben|unterzeichnen))\b", r"(?:x++)+", r"(?>a+)+", r"a{1,5}b+"):
        make_config(rules=[{"id": "ok", "state": "ACTION", "confidence": 0.9, "when": {"body_regex": pattern}}])


@pytest.mark.parametrize(
    "marker",
    [
        "Le lun. 3 oct. 2026, Max <max@x.fr> a écrit :",
        "El lun, 3 oct 2026, Max escribió:",
        "Il giorno lun 3 ott 2026, Max ha scritto:",
        "Op ma 3 okt. 2026 schreef Max <max@x.nl>:",
        "Em seg., 3 de out. de 2026, Max escreveu:",
        "-----Message d'origine-----",
        "-------- Mensaje original --------",
    ],
)
def test_A_F5_locale_reply_markers_strip_quoted_text(marker):
    assert strip_quoted_text(f"Merci\n{marker}\nbitte unterschreiben") == "Merci"


@pytest.mark.parametrize("money", ["wire transfer", "bitte bezahlen", "gift cards", "Bitcoin", "IBAN DE00", "Passwort"])
def test_A_F6_builtin_money_guard_blocks_auto_action_and_draft(money):
    cfg = make_config(capabilities={"labels": True, "drafts": True})
    msg = normalize_message(make_message("m1", "t1", plain=f"{SIGN} Danach bitte {money} erledigen."), **N)
    c = classify(msg, None, cfg)
    assert c.state.value == "REVIEW" and c.draft_template is None
    assert c.rule_id in {"builtin:money-guard", "money-review"}  # built-in guard or operator force_review


def test_A_F7_bidi_and_zero_width_characters_are_stripped():
    line = sanitize_line("a\u200bb\u200ec\u200fd\u061ce\u2060f\u180eg\u200dh")
    assert line == "abcdefgh"


def test_A_I1_hidden_html_text_never_drives_rules(cfg_apply):
    html = (
        "<p>Newsletter</p><div style='display:none'>bitte unterschreiben</div><span hidden>signature requested</span>"
    )
    msg = normalize_message(make_message("m1", "t1", plain=None, html=html), **N)
    assert "unterschreiben" not in msg.newest_text and "signature" not in msg.body_text
    assert classify(msg, None, cfg_apply).state.value != "ACTION"


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_A_I3_token_in_world_writable_folder_is_refused(tmp_path):
    from src.auth import check_secret_location
    from src.errors import SecretLocationError

    d = tmp_path / "shared"
    d.mkdir()
    os.chmod(d, 0o777)  # noqa: S103 - the attack setup: a world-writable token folder
    tok = d / "token_observe.json"
    tok.write_text("{}")
    os.chmod(tok, 0o600)
    with pytest.raises(SecretLocationError) as e:
        check_secret_location(tok, project_root=tmp_path / "proj")
    assert e.value.code == "SECRET_DIR_PERMISSIONS"


@pytest.mark.parametrize("abbrev", ["--app", "--a", "--appl"])
def test_A_I8_apply_flag_cannot_be_abbreviated(abbrev, tmp_path, capsys):
    with pytest.raises(SystemExit) as e:
        cli.main(["run", abbrev, "--config", write_cfg(tmp_path)])
    assert e.value.code == 2


# ====================================================================== Red Team B
def test_B_M1_write_with_lost_response_and_exhausted_retries_is_settled_and_undoable(ledger):
    g = mailbox()
    g.faults["users.messages.modify"] = [AfterApply(http_error(503, "backendError"))] + [http_error(503)] * 3
    s, eng = run_engine(g, LABELS_ONLY, ledger, apply=True)
    assert s.status == "FAILED_CLOSED" and eng.error.code == "AMBIGUOUS_RETRY_EXHAUSTED_SERVER"
    assert app(g, "m1") == ["JARVIS/REFERENCE"]
    assert [r["outcome"] for r in events(ledger, "RECONCILED_APPLIED")] == ["APPLIED"]
    assert ledger.pending() == [] and not events(ledger, "FAILED")
    r = undo(g, LABELS_ONLY, ledger, s.run_id)
    assert r.status == "DONE" and app(g, "m1") == []


def test_B_M1_verify_read_failure_uses_modify_response_and_stays_undoable(ledger):
    g = mailbox()
    # messages.get order: scan m1, scan m2, freshness m1, VERIFY m1 <- fails 4x
    g.faults["users.messages.get"] = [lambda gm: None] * 3 + [http_error(503)] * 4
    s, eng = run_engine(g, LABELS_ONLY, ledger, apply=True)
    assert s.status == "FAILED_CLOSED" and eng.error.code == "RETRY_EXHAUSTED_SERVER"
    applied = events(ledger, "APPLIED")
    assert applied and json.loads(applied[-1]["detail"])["verified_by"] == "response"
    assert undo(g, LABELS_ONLY, ledger, s.run_id).reverted == 1 and app(g, "m1") == []


def test_B_M1_transient_error_during_reconcile_keeps_row_pending(ledger):
    g = mailbox()
    g.faults["users.messages.modify"] = [AfterApply(KeyboardInterrupt("power loss"))]
    with pytest.raises(KeyboardInterrupt):
        run_engine(g, LABELS_ONLY, ledger, apply=True)
    run1 = ledger.pending()[0]["run_id"]
    g.faults["users.messages.get"] = [http_error(503)] * 4  # 503 burst exactly during reconcile
    s2, _ = run_engine(g, LABELS_ONLY, ledger, apply=True)
    assert s2.status.startswith(("FAILED_CLOSED", "ERROR:")) and len(ledger.pending()) == 1  # stays pending
    assert not events(ledger, "RECONCILED_DRIFT")
    s3, _ = run_engine(g, LABELS_ONLY, ledger, apply=True)
    assert s3.reconciled == 1 and ledger.pending() == []
    assert undo(g, LABELS_ONLY, ledger, run1).status == "DONE" and app(g, "m1") == []


def test_B_M1_I4_ctrl_c_writes_run_end_aborted(ledger):
    g = mailbox()
    g.faults["users.messages.modify"] = [KeyboardInterrupt("ctrl+c")]
    with pytest.raises(KeyboardInterrupt):
        run_engine(g, LABELS_ONLY, ledger, apply=True)
    assert events(ledger, "RUN_END")[-1]["outcome"] == "ABORTED"


def test_B_M2_undo_with_deleted_restore_label_is_conflict_and_untouched(ledger):
    g = mailbox()
    rules = json.loads(json.dumps(BASE_CONFIG["rules"]))
    rules[1]["state"], rules[1]["draft_template"] = "PROJECT", None  # run 1 files m2 into PROJECT
    run_engine(g, make_config(capabilities={"labels": True}, rules=rules), ledger, apply=True)
    assert app(g, "m2") == ["JARVIS/PROJECT"]
    s, _ = run_engine(g, LABELS_ONLY, ledger, apply=True)  # run 2: PROJECT -> ACTION
    assert app(g, "m2") == ["JARVIS/ACTION"]
    del g.labels[g.label_id("JARVIS/PROJECT")]  # the user deletes the now unused label
    calls = len(g.mutation_calls())
    r = undo(g, LABELS_ONLY, ledger, s.run_id)
    assert r.status == "CONFLICT" and any(c["reason"] == "LABEL_MISSING" for c in r.conflicts)
    assert len(g.mutation_calls()) == calls
    assert app(g, "m1") == ["JARVIS/REFERENCE"] and app(g, "m2") == ["JARVIS/ACTION"]


def test_B_M2_mid_loop_api_error_is_compensated(ledger):
    g = mailbox()
    s, _ = run_engine(g, LABELS_ONLY, ledger, apply=True)
    g.faults["users.messages.modify"] = [lambda gm: None, http_error(403, "insufficientPermissions")]
    r = undo(g, LABELS_ONLY, ledger, s.run_id)
    assert r.status == "ROLLED_BACK" and r.error_code == "AUTH_403" and r.reverted == 0
    assert app(g, "m1") == ["JARVIS/REFERENCE"] and app(g, "m2") == ["JARVIS/ACTION"]  # all-or-nothing
    assert events(ledger, "UNDO_COMPENSATED") and ledger.pending_undo() == []
    assert ledger.last_undoable_run() == s.run_id  # still fully undoable later
    assert undo(g, LABELS_ONLY, ledger, s.run_id).status == "DONE"
    assert app(g, "m1") == [] and app(g, "m2") == []


def test_B_M2_failed_compensation_reports_partial_with_message_list(data_dir, ledger):
    g = mailbox()
    s, _ = run_engine(g, LABELS_ONLY, ledger, apply=True)
    g.faults["users.messages.modify"] = [lambda gm: None, http_error(403), http_error(403)]
    r = undo(g, LABELS_ONLY, ledger, s.run_id)
    assert r.status == "PARTIAL" and r.still_reverted == ["m1"]


def test_B_M2_cli_partial_and_rolled_back_exit_codes(data_dir, tmp_path, capsys):
    from src.errors import EXIT_PARTIAL

    g = mailbox()
    cfg = write_cfg(tmp_path, capabilities={"labels": True})
    assert cli.main(["run", "--apply", "--config", cfg], service_factory=lambda p: (g, None)) == 0
    g.faults["users.messages.modify"] = [lambda gm: None, http_error(403)]
    rc = cli.main(["undo", "--last-run", "--apply", "--config", cfg], service_factory=lambda p: (g, None))
    assert rc == 8 and "ROLLED_BACK" in capsys.readouterr().out
    g.faults["users.messages.modify"] = [lambda gm: None, http_error(403), http_error(403)]
    rc = cli.main(["undo", "--last-run", "--apply", "--config", cfg], service_factory=lambda p: (g, None))
    assert rc == EXIT_PARTIAL and "UNDO TEILWEISE" in capsys.readouterr().out


def test_B_M3_missing_anchor_is_refused_until_explicit_rebaseline(data_dir):
    db = data_dir / "audit.sqlite3"
    led = AuditLedger(db)
    led.append(run_id="r", profile="apply", mode="APPLY", event="X")
    anchor = led.head_path
    led.close()
    assert not anchor.is_relative_to(data_dir)  # the anchor lives OUTSIDE the data folder
    anchor.unlink()
    with pytest.raises(AuditIntegrityError) as e:
        AuditLedger(db)
    assert e.value.code == "AUDIT_ANCHOR_MISSING"
    with AuditLedger(db, check_anchor=False) as led2:
        led2.rebaseline(run_id=new_run_id(), reason="test")
    with AuditLedger(db) as led3:
        assert led3.verify()[0] and events(led3, "HEAD_REBASELINE")


def test_B_M3_whole_data_folder_restore_is_detected(data_dir, tmp_path):
    g = mailbox()
    db = data_dir / "audit.sqlite3"
    with AuditLedger(db) as led:
        run_engine(g, LABELS_ONLY, led, apply=True)
    backup = tmp_path / "backup"
    shutil.copytree(data_dir, backup)
    with AuditLedger(db) as led:
        g.add(make_message("m3", "t3", subject="N", extra_headers={"List-Unsubscribe": "<q>"}, internal_date=9))
        run_engine(g, LABELS_ONLY, led, apply=True)
    shutil.rmtree(data_dir)
    shutil.copytree(backup, data_dir)  # restore the WHOLE folder (DB and everything next to it)
    with pytest.raises(AuditIntegrityError) as e:
        AuditLedger(db)
    assert e.value.code == "AUDIT_ROLLBACK"


def test_B_M3_anchor_ahead_of_db_is_rollback(data_dir):
    db = data_dir / "audit.sqlite3"
    with AuditLedger(db) as led:
        for _ in range(3):
            led.append(run_id="r", profile="apply", mode="APPLY", event="X")
        anchor = led.head_path
    head = json.loads(anchor.read_text())
    anchor.write_text(json.dumps({"seq": head["seq"] + 1, "hash": head["hash"]}))
    with pytest.raises(AuditIntegrityError) as e:
        AuditLedger(db)
    assert e.value.code == "AUDIT_ROLLBACK"


def test_B_M4_label_deleted_by_user_is_recreated(ledger):
    g = mailbox()
    run_engine(g, LABELS_ONLY, ledger, apply=True)
    ref = g.label_id("JARVIS/REFERENCE")
    del g.labels[ref]
    for m in g.messages.values():
        m["labelIds"] = [x for x in m["labelIds"] if x != ref]
    g.add(make_message("m3", "t3", subject="N2", extra_headers={"List-Unsubscribe": "<q>"}, internal_date=9))
    for _ in range(2):
        s, eng = run_engine(g, LABELS_ONLY, ledger, apply=True)
        assert eng.error is None and s.status == "OK"
    assert app(g, "m3") == ["JARVIS/REFERENCE"]


def test_B_M8_locked_db_is_reported_as_locked_not_corrupt(data_dir):
    p = data_dir / "locked.sqlite3"
    AuditLedger(p).close()
    other = sqlite3.connect(str(p), isolation_level=None)
    other.execute("BEGIN EXCLUSIVE")
    try:
        with pytest.raises(AuditUnavailableError) as e:
            AuditLedger(p, timeout=0.1)
        assert e.value.code == "AUDIT_LOCKED"
    finally:
        other.execute("ROLLBACK")
        other.close()


def test_B_M8_lock_taken_mid_run_is_mapped_not_raw(data_dir):
    p = data_dir / "mid.sqlite3"
    led = AuditLedger(p, timeout=0.1)
    led.append(run_id="r", profile="p", mode="m", event="E")
    other = sqlite3.connect(str(p), isolation_level=None)
    other.execute("BEGIN EXCLUSIVE")
    try:
        for call in (
            lambda: led.append(run_id="r", profile="p", mode="m", event="E"),
            led.pending,
            led.verify,
            lambda: led.is_key_applied("k"),
        ):
            with pytest.raises(AuditUnavailableError) as e:
                call()
            assert e.value.code == "AUDIT_LOCKED"
    finally:
        other.execute("ROLLBACK")
        other.close()
        led.close()


def test_B_M8_disk_full_is_reported_as_full(data_dir):
    led = AuditLedger(data_dir / "full.sqlite3")
    pages = led.raw.execute("PRAGMA page_count").fetchone()[0]
    led.raw.execute(f"PRAGMA max_page_count = {pages}")
    with pytest.raises(AuditUnavailableError) as e:
        for _ in range(50):
            led.append(run_id="r", profile="p", mode="m", event="E", detail={"pad": "x" * 4000})
    assert e.value.code == "AUDIT_FULL"
    assert not led.raw.in_transaction
    led.close()


def test_B_M8_read_only_db_is_reported_as_read_only(data_dir):
    led = AuditLedger(data_dir / "ro.sqlite3")
    led.raw.execute("PRAGMA query_only = 1")
    with pytest.raises(AuditUnavailableError) as e:
        led.append(run_id="r", profile="p", mode="m", event="E")
    assert e.value.code == "AUDIT_READONLY"
    led.close()


def test_B_M8_unwritable_data_dir_gives_clean_error(tmp_path, monkeypatch, capsys):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x")
    monkeypatch.setenv("GMAIL_AUTOMATION_HOME", str(blocker))
    assert cli.main(["status"]) == 5
    rc = cli.main(["run", "--config", write_cfg(tmp_path)], service_factory=lambda p: (FakeGmail(), None))
    out = capsys.readouterr()
    assert rc == 6 and "LOCK_UNAVAILABLE" in out.out and "Traceback" not in out.err


def test_B_I8_schema_without_ledger_table_is_integrity_error(data_dir):
    p = data_dir / "schema.sqlite3"
    con = sqlite3.connect(str(p))
    con.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
    con.execute("INSERT INTO schema_version VALUES (2)")
    con.commit()
    con.close()
    with pytest.raises(AuditIntegrityError) as e:
        AuditLedger(p)
    assert e.value.code == "AUDIT_SCHEMA_INVALID"


def test_B_L2_backoff_budget_and_deadline(cfg):
    g = mailbox()
    g.faults["users.labels.list"] = [http_error(429, retry_after=86400)] * 20
    slept: list[float] = []
    from src.gmail_client import GmailClient

    client = GmailClient(g, ctx_for(cfg, apply=False), retry=RetryPolicy(max_attempts=100), sleep=slept.append)
    with pytest.raises(TransientExhaustedError) as e:
        client.list_labels()
    assert e.value.code == "RETRY_BUDGET_RATE_LIMIT" and sum(slept) <= RetryPolicy().max_total_sleep
    now = [0.0]
    late = GmailClient(g, ctx_for(cfg, apply=False), deadline_seconds=10, clock=lambda: now[0])
    now[0] = 11.0
    from src.errors import RunBudgetExceeded

    with pytest.raises(RunBudgetExceeded) as e2:
        late.get_profile()
    assert e2.value.code == "RUN_DEADLINE"


def test_B_L2_pagination_is_bounded_on_endless_tokens(cfg):
    class Endless:
        def __init__(self):
            self.calls = 0

        def users(self):
            return self

        def messages(self):
            return self

        def list(self, **kw):
            self.calls += 1
            from tests.fakes import FakeRequest

            return FakeRequest(lambda: {"messages": [], "nextPageToken": f"t{self.calls}"})

    svc = Endless()
    from src.gmail_client import GmailClient

    refs, pages = GmailClient(svc, ctx_for(cfg, apply=False)).list_message_refs("q", 1000)
    assert refs == [] and pages <= 3 and svc.calls == pages


def test_B_L4_429_on_draft_create_is_retried_not_fatal(cfg_apply, ledger):
    g = mailbox()
    g.faults["users.drafts.create"] = [http_error(429, retry_after=1)]
    s, eng = run_engine(g, cfg_apply, ledger, apply=True)
    assert s.status == "OK" and eng.error is None and len(g.drafts) == 1


@pytest.mark.parametrize(
    "exc",
    [
        ssl.SSLEOFError(8, "EOF occurred in violation of protocol"),
        socket.gaierror(-3, "Temporary failure in name resolution"),
        OSError(errno.ENETUNREACH, "Network is unreachable"),
        http.client.IncompleteRead(b"partial"),
        http.client.RemoteDisconnected("closed"),
    ],
    ids=["SSLEOFError", "gaierror", "ENETUNREACH", "IncompleteRead", "RemoteDisconnected"],
)
def test_B_L5_transient_network_errors_are_retried(exc):
    assert classify_error(exc).kind is ErrorKind.NETWORK
    assert classify_error(PermissionError(errno.EACCES, "denied")).kind is ErrorKind.UNKNOWN


def test_B_L6_undo_works_with_capabilities_switched_off(ledger):
    g = mailbox()
    s, _ = run_engine(g, LABELS_ONLY, ledger, apply=True)
    kill_switch = make_config(capabilities={"labels": False, "drafts": False})
    r = undo(g, kill_switch, ledger, s.run_id)
    assert r.status == "DONE" and app(g, "m1") == []


def test_B_L7_undo_of_older_run_refused_while_later_run_is_active(ledger):
    g = mailbox()
    rules = json.loads(json.dumps(BASE_CONFIG["rules"]))
    cfg_ref = make_config(capabilities={"labels": True}, rules=rules)
    rules_project = json.loads(json.dumps(rules))
    rules_project[0]["state"] = "PROJECT"
    cfg_proj = make_config(capabilities={"labels": True}, rules=rules_project)
    s1, _ = run_engine(g, cfg_ref, ledger, apply=True)  # {} -> REFERENCE
    s2, _ = run_engine(g, cfg_proj, ledger, apply=True)  # REFERENCE -> PROJECT
    s3, _ = run_engine(g, cfg_ref, ledger, apply=True)  # PROJECT -> REFERENCE (coincides with run 1)
    assert app(g, "m1") == ["JARVIS/REFERENCE"]
    r = undo(g, cfg_ref, ledger, s1.run_id)
    assert r.status == "CONFLICT" and r.conflicts[0]["reason"] == "LATER_RUN"
    assert app(g, "m1") == ["JARVIS/REFERENCE"]
    for run in (s3, s2, s1):  # newest first restores the exact history
        assert undo(g, cfg_ref, ledger, run.run_id).status == "DONE"
    assert app(g, "m1") == []


def test_B_L8_head_write_retries_sharing_violation_and_maps_errors(data_dir, monkeypatch):
    led = AuditLedger(data_dir / "h.sqlite3")
    real_replace = os.replace
    fails = {"n": 2}

    def flaky_replace(src, dst):
        if fails["n"]:
            fails["n"] -= 1
            raise PermissionError(13, "file in use (AV scanner)")
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", flaky_replace)
    led.append(run_id="r", profile="p", mode="m", event="E")  # survives two sharing violations
    monkeypatch.setattr(os, "replace", lambda s, d: (_ for _ in ()).throw(PermissionError(13, "locked")))
    with pytest.raises(AuditUnavailableError) as e:
        led.append(run_id="r", profile="p", mode="m", event="E")
    assert e.value.code == "AUDIT_HEAD_WRITE"
    monkeypatch.setattr(os, "replace", real_replace)
    assert not list(led.head_path.parent.glob(".head-*.tmp"))  # no temp litter
    led.close()
    with AuditLedger(data_dir / "h.sqlite3") as again:  # lagging anchor is caught up, not an alarm
        assert again.verify()[0]


def test_B_L9_zero_byte_anchor_has_an_audited_repair_path(data_dir, tmp_path, capsys):
    with cli._open_ledger() as led:
        led.append(run_id="r", profile="p", mode="m", event="E")
        anchor = led.head_path
    anchor.write_bytes(b"")
    assert cli.main(["status"]) == 5
    assert "AUDIT_HEAD_CORRUPT" in capsys.readouterr().out
    assert cli.main(["audit-rebaseline"]) == 2  # preview only without --confirm
    assert cli.main(["audit-rebaseline", "--confirm"]) == 0
    assert cli.main(["status"]) == 0


def test_B_L10_drafts_are_paginated(cfg_apply):
    g = FakeGmail()
    for i in range(1200):
        g.drafts[f"r-x{i}"] = {"id": f"r-x{i}", "message": {"id": f"mx{i}", "threadId": f"tx{i}", "raw": "eA"}}
    g.drafts["r-own"] = {"id": "r-own", "message": {"id": "mo", "threadId": "t-own", "raw": "eA"}}
    client = client_for(g, cfg_apply, apply=False)
    assert drafts_in_thread(client, "t-own") == ["r-own"]
    assert g.calls.count("users.drafts.list") == 3
    assert find_draft_with_key(client, "t-none", "k") is None


def test_B_L11_duplicate_yaml_keys_are_rejected(tmp_path):
    base = yaml.safe_dump(BASE_CONFIG)
    p = tmp_path / "rules.yaml"
    p.write_text(base + "capabilities:\n  labels: true\n  drafts: true\n", encoding="utf-8")
    with pytest.raises(ConfigError) as e:
        load_config(p)
    assert e.value.code == "CONFIG_MALFORMED" and "duplicate key" in str(e.value)
    dup_in_rule = base.replace("- confidence: 0.9\n", "- confidence: 0.9\n  confidence: 0.1\n", 1)
    assert dup_in_rule != base
    p.write_text(dup_in_rule, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(p)


def test_B_L13_windows_scripts_have_crlf_line_endings():
    root = Path(__file__).resolve().parents[1]
    for rel in ("START_GMAIL_AUTOMATION.cmd", "scripts/bootstrap.ps1", "scripts/verify.ps1"):
        data = (root / rel).read_bytes()
        assert data.count(b"\n") == data.count(b"\r\n") > 0, rel
        assert data.isascii(), rel  # Windows PowerShell 5.1 reads BOM-less files as ANSI


def test_B_I3_own_draft_is_never_the_newest_message():
    thread = {
        "id": "t1",
        "historyId": "5",
        "messages": [
            {"id": "m1", "internalDate": "1", "labelIds": ["INBOX"]},
            {"id": "d1", "internalDate": "9", "labelIds": ["DRAFT"]},
        ],
    }
    snap = snapshot_from_thread(thread, 200)
    assert snap.newest_id == "m1" and snap.message_count == 1
    with pytest.raises(GmailApiError):
        snapshot_from_thread({"id": "t2", "messages": [{"id": "d", "labelIds": ["DRAFT"]}]}, 200)


def test_B_I6_daily_quota_and_http_date_retry_after(cfg):
    from src.gmail_client import GmailClient

    g = mailbox()
    g.faults["users.labels.list"] = [http_error(403, "dailyLimitExceeded")]

    with pytest.raises(GmailApiError) as e:
        GmailClient(g, ctx_for(cfg, apply=False), sleep=lambda s: None).list_labels()
    assert e.value.code == "API_QUOTA_DAILY"
    from datetime import UTC, datetime

    resp = httplib2.Response({"status": 429, "retry-after": "Sat, 03 Oct 2026 12:00:30 GMT"})
    assert _retry_after(resp, now=datetime(2026, 10, 3, 12, 0, 0, tzinfo=UTC)) == 30.0


def test_B_I7_run_id_has_64_random_bits():
    rid = new_run_id()
    assert len(rid.split("-")[1]) == 16 and len({new_run_id() for _ in range(2000)}) == 2000


def test_B_I10_start_menu_uses_pushd_for_unc_paths():
    text = (Path(__file__).resolve().parents[1] / "START_GMAIL_AUTOMATION.cmd").read_text(encoding="ascii")
    assert 'pushd "%~dp0"' in text and "cd /d" not in text


# ====================================================================== transport guard (M7 defence in depth)
@pytest.mark.parametrize(
    ("method", "uri", "profile", "ok"),
    [
        ("GET", "https://gmail.googleapis.com/gmail/v1/users/me/messages?q=x", Profile.OBSERVE, True),
        ("GET", "https://gmail.googleapis.com/gmail/v1/users/me/threads/abc", Profile.OBSERVE, True),
        ("POST", "https://oauth2.googleapis.com/token", Profile.OBSERVE, True),
        ("POST", "https://gmail.googleapis.com/gmail/v1/users/me/messages/abc/modify", Profile.APPLY, True),
        ("POST", "https://gmail.googleapis.com/gmail/v1/users/me/drafts", Profile.APPLY, True),
        ("POST", "https://gmail.googleapis.com/gmail/v1/users/me/messages/abc/modify", Profile.OBSERVE, False),
        ("POST", "https://gmail.googleapis.com/gmail/v1/users/me/messages/send", Profile.APPLY, False),
        ("POST", "https://gmail.googleapis.com/upload/gmail/v1/users/me/messages/send", Profile.APPLY, False),
        ("POST", "https://gmail.googleapis.com/gmail/v1/users/me/drafts/send", Profile.APPLY, False),
        ("POST", "https://gmail.googleapis.com/gmail/v1/users/me/messages/abc/trash", Profile.APPLY, False),
        ("DELETE", "https://gmail.googleapis.com/gmail/v1/users/me/messages/abc", Profile.APPLY, False),
        ("POST", "https://gmail.googleapis.com/gmail/v1/users/me/messages/batchDelete", Profile.APPLY, False),
        ("POST", "https://gmail.googleapis.com/gmail/v1/users/me/settings/forwardingAddresses", Profile.APPLY, False),
        ("POST", "https://gmail.googleapis.com/batch/gmail/v1", Profile.APPLY, False),
        ("GET", "https://gmail.googleapis.com/gmail/v1/users/me/messages/../settings/filters", Profile.APPLY, False),
        ("GET", "http://gmail.googleapis.com/gmail/v1/users/me/labels", Profile.APPLY, False),
        ("GET", "https://evil.example/gmail/v1/users/me/labels", Profile.APPLY, False),
        ("GET", "https://user:pw@gmail.googleapis.com/gmail/v1/users/me/labels", Profile.APPLY, False),
    ],
)
def test_transport_allow_list(method, uri, profile, ok):
    from src.gmail_client import allowed_endpoints

    if ok:
        check_transport(method, uri, allowed_endpoints(profile))
    else:
        with pytest.raises(PolicyViolation):
            check_transport(method, uri, allowed_endpoints(profile))


def test_real_googleapiclient_service_cannot_send_even_without_the_adapter(monkeypatch):
    """Code that obtains the raw service (bypassing GmailClient) still cannot send/trash/delete."""
    from google.oauth2.credentials import Credentials

    from src.auth import build_gmail_service

    sent: list[tuple[str, str]] = []

    def fake_request(self, uri, method="GET", body=None, headers=None, redirections=5, connection_type=None):
        sent.append((method, uri))
        return httplib2.Response({"status": "200"}), b'{"messages": [], "labels": []}'

    monkeypatch.setattr(httplib2.Http, "request", fake_request)
    svc = build_gmail_service(Credentials(token="test-token"), Profile.APPLY)  # noqa: S106 - dummy
    assert svc.users().labels().list(userId="me").execute() == {"messages": [], "labels": []}
    assert len(sent) == 1
    for build in (
        lambda: svc.users().messages().send(userId="me", body={"raw": "eA"}),
        lambda: svc.users().drafts().send(userId="me", body={"id": "r1"}),
        lambda: svc.users().messages().trash(userId="me", id="m1"),
        lambda: svc.users().messages().delete(userId="me", id="m1"),
        lambda: svc.users().threads().delete(userId="me", id="t1"),
        lambda: svc.users().messages().batchDelete(userId="me", body={"ids": ["m1"]}),
        lambda: svc.users().settings().forwardingAddresses().create(userId="me", body={}),
    ):
        with pytest.raises(PolicyViolation):
            build().execute()
    assert len(sent) == 1  # nothing else ever reached the network layer
    observe = build_gmail_service(Credentials(token="test-token"), Profile.OBSERVE)  # noqa: S106
    with pytest.raises(PolicyViolation):
        observe.users().messages().modify(userId="me", id="m1", body={}).execute()


def test_guarded_http_never_follows_redirects():
    h = GuardedHttp(Profile.OBSERVE)
    assert h.follow_redirects is False and 308 not in h.redirect_codes


def test_dry_run_stays_mutation_free_with_all_new_checks(cfg, ledger):
    g = mailbox()
    s, eng = run_engine(g, cfg, ledger, apply=False)
    assert s.status == "OK" and eng.error is None and g.mutation_calls() == [] and s.mutations == 0


# ====================================================================== Fix verification (Red Team C)
def test_C_M1_transport_refuses_system_labels_in_modify_body_and_method_override(monkeypatch):
    from google.oauth2.credentials import Credentials

    from src.auth import build_gmail_service

    sent: list[str] = []

    def fake_request(self, uri, method="GET", body=None, headers=None, redirections=5, connection_type=None):
        sent.append(method)
        return httplib2.Response({"status": "200"}), b"{}"

    monkeypatch.setattr(httplib2.Http, "request", fake_request)
    svc = build_gmail_service(Credentials(token="test-token"), Profile.APPLY)  # noqa: S106 - dummy
    for body in ({"addLabelIds": ["TRASH"]}, {"addLabelIds": ["SPAM"]}, {"removeLabelIds": ["INBOX"]}, {"x": 1}):
        with pytest.raises(PolicyViolation) as e:
            svc.users().messages().modify(userId="me", id="m1", body=body).execute()
        assert e.value.code == "TRANSPORT_BODY"
    with pytest.raises(PolicyViolation):
        svc.users().drafts().create(userId="me", body={"message": {"raw": "eA"}}).execute()  # not thread-linked
    svc.users().messages().modify(userId="me", id="m1", body={"addLabelIds": ["Label_7"]}).execute()
    assert sent == ["POST"]
    h = GuardedHttp(Profile.APPLY)
    with pytest.raises(PolicyViolation) as e2:
        h.request(
            "https://gmail.googleapis.com/gmail/v1/users/me/labels", "GET", headers={"X-HTTP-Method-Override": "DELETE"}
        )
    assert e2.value.code == "TRANSPORT_METHOD_OVERRIDE"


def test_C_M1_refresh_transport_reaches_only_the_token_endpoint():
    from src.auth import _default_request

    req = _default_request()
    for method, url in (
        ("GET", "https://oauth2.googleapis.com/token"),
        ("POST", "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"),
        ("POST", "https://evil.example/token"),
    ):
        with pytest.raises(PolicyViolation):
            req.session.request(method, url)


def _deadline_client(g, cfg, clock):
    from src.gmail_client import GmailClient

    def sleep(seconds):
        clock[0] += 1_000  # every backoff crosses the deadline

    return GmailClient(
        g,
        ctx_for(cfg, apply=True),
        retry=RetryPolicy(max_attempts=4),
        sleep=sleep,
        deadline_seconds=500,
        clock=lambda: clock[0],
    )


def test_C_L1_deadline_after_applied_5xx_is_never_a_terminal_failure(ledger):
    g = mailbox()
    g.faults["users.messages.modify"] = [AfterApply(http_error(503, "backendError"))]
    clock = [0.0]
    eng = Engine(_deadline_client(g, LABELS_ONLY, clock), LABELS_ONLY, ctx_for(LABELS_ONLY, apply=True), ledger,
                 out=lambda s: None)  # fmt: skip
    s = eng.run()
    assert s.status == "FAILED_CLOSED" and app(g, "m1") == ["JARVIS/REFERENCE"]
    assert not events(ledger, "FAILED") and len(ledger.pending()) == 1  # left for reconciliation
    s2, _ = run_engine(g, LABELS_ONLY, ledger, apply=True)
    assert s2.reconciled == 1 and ledger.pending() == []
    assert undo(g, LABELS_ONLY, ledger, s.run_id).status == "DONE" and app(g, "m1") == []


def test_C_L1_failed_refresh_after_applied_5xx_is_settled(ledger):
    from src.gmail_client import GmailClient

    g = mailbox()
    g.faults["users.messages.modify"] = [AfterApply(http_error(503)), http_error(401)]

    def broken_refresh():
        raise RuntimeError("refresh endpoint down")

    client = GmailClient(
        g, ctx_for(LABELS_ONLY, apply=True), retry=RetryPolicy(max_attempts=4), sleep=lambda s: None,
        refresh_credentials=broken_refresh,
    )  # fmt: skip
    s = Engine(client, LABELS_ONLY, ctx_for(LABELS_ONLY, apply=True), ledger, out=lambda s: None).run()
    assert s.status == "FAILED_CLOSED"
    assert [r["outcome"] for r in events(ledger, "RECONCILED_APPLIED")] == ["APPLIED"] and not events(ledger, "FAILED")
    assert undo(g, LABELS_ONLY, ledger, s.run_id).status == "DONE"


def test_C_L2_message_that_always_gets_5xx_is_quarantined(ledger, monkeypatch):
    from tests import fakes

    g = mailbox()
    original_modify = fakes._Messages.modify

    def modify(self, userId, id, body):  # noqa: A002
        if id == "m1":

            def backend_error():
                raise http_error(500, "backendError")

            return self.g._dispatch("users.messages.modify", backend_error)
        return original_modify(self, userId, id, body)

    monkeypatch.setattr(fakes._Messages, "modify", modify)
    for _ in range(3):
        s, _ = run_engine(g, LABELS_ONLY, ledger, apply=True)
        assert s.status == "FAILED_CLOSED"  # still stops the run (could be a Gmail outage)
    s4, eng = run_engine(g, LABELS_ONLY, ledger, apply=True)
    assert s4.quarantined == 1 and s4.status == "PARTIAL" and eng.error is None
    assert app(g, "m2") == ["JARVIS/ACTION"]  # the rest of the mailbox is processed again


def test_C_L5_noop_undo_item_is_marked_undone_no_deadlock(ledger):
    g = mailbox()
    rules_project = json.loads(json.dumps(BASE_CONFIG["rules"]))
    rules_project[0]["state"] = "PROJECT"
    cfg_proj = make_config(capabilities={"labels": True}, rules=rules_project)
    s_a, _ = run_engine(g, LABELS_ONLY, ledger, apply=True)  # {} -> REFERENCE

    def second_client_reverts(gm):
        lab = gm.messages["m1"]["labelIds"]
        proj = gm.label_id("JARVIS/PROJECT")
        if proj in lab:
            lab.remove(proj)
            lab.append(gm.label_id("JARVIS/REFERENCE"))

    # messages.get in run B: scan m1, scan m2, fresh m1, VERIFY m1 <- the second client acted first
    g.faults["users.messages.get"] = [lambda gm: None] * 3 + [second_client_reverts]
    s_b, _ = run_engine(g, cfg_proj, ledger, apply=True)
    assert events(ledger, "APPLIED_DRIFT") and app(g, "m1") == ["JARVIS/REFERENCE"]
    assert undo(g, LABELS_ONLY, ledger, s_b.run_id).status == "DONE"
    assert ledger.last_undoable_run() == s_a.run_id  # B is fully undone
    assert undo(g, LABELS_ONLY, ledger, s_a.run_id).status == "DONE" and app(g, "m1") == []


def test_C_L6_rebaseline_shows_verdict_and_needs_distinct_flags(data_dir, capsys):
    with cli._open_ledger() as led:
        for _ in range(3):
            led.append(run_id="r", profile="p", mode="m", event="E")
        anchor = led.head_path
    head = json.loads(anchor.read_text())
    anchor.write_text(json.dumps({"seq": head["seq"] + 5, "hash": head["hash"]}))  # looks like a rollback
    assert cli.main(["audit-rebaseline", "--confirm"]) == 2
    out = capsys.readouterr().out
    assert "AUDIT_ROLLBACK" in out and "--accept-rollback" in out
    assert cli.main(["audit-rebaseline", "--confirm", "--accept-rollback"]) == 0
    with cli._open_ledger() as led:
        detail = json.loads(events(led, "HEAD_REBASELINE")[-1]["detail"])
    assert detail["verdict"] == "AUDIT_ROLLBACK"
    assert cli.main(["audit-rebaseline"]) == 0 and "Nichts zu tun" in capsys.readouterr().out


@pytest.mark.parametrize(
    "html",
    [
        f"<p>{SIGN}</p><p style='display:none'><div>Bitte Zahlung an IBAN DE00 0000 leisten.</div>",
        f"<p>{SIGN}</p><div style='visibility:hidden'><span style='visibility:visible'>"
        "Bitte Zahlung an IBAN DE00 0000 leisten.</span></div>",
        f"<p>{SIGN}</p><div style='font-size:0'><span style='font-size:14px'>"
        "Bitte Zahlung an IBAN DE00 0000 leisten.</span></div>",
        f"<p>{SIGN}</p><div style='display:none'>Bitte Zahlung an IBAN DE00 0000 leisten.</div>",  # really hidden
    ],
    ids=["implicit-p-close", "visibility-override", "font-size-override", "hidden-payment"],
)
def test_C_L7_visible_and_hidden_payment_wording_both_reach_the_guards(cfg_apply, html):
    c = classify(normalize_message(make_message("m1", "t1", plain=None, html=html), **N), None, cfg_apply)
    assert c.state.value == "REVIEW" and c.draft_template is None


@pytest.mark.parametrize(
    ("plain", "html"),
    [
        (f"{SIGN}\n\nAm Montag schrieb Buchhaltung:\nBitte ueberweisen Sie 4.800 EUR an IBAN DE00 0000.", None),
        (SIGN, f"<p>{SIGN}</p><p>Bitte Zahlung von 4.800 EUR an IBAN DE00 0000 leisten.</p>"),
        (f"{SIGN}\nBitte senden Sie mir 500 Euro Geld per Lastschrift.", None),
        (f"{SIGN}\nBitte begleichen Sie den offenen Betrag per SEPA.", None),
        (f"{SIGN}\nKaufen Sie bitte drei Amazon-Guthabenkarten und schicken Sie die Codes.", None),
    ],
    ids=["below-fake-reply-marker", "html-alternative-only", "geld-euro", "betrag-sepa", "guthabenkarten"],
)
def test_C_L8_money_guard_sees_all_parts_quotes_and_wording(cfg_apply, plain, html):
    c = classify(normalize_message(make_message("m1", "t1", plain=plain, html=html), **N), None, cfg_apply)
    assert c.state.value == "REVIEW" and c.draft_template is None


@pytest.mark.parametrize("pattern", [r"(a|a)+$", r"(a{1,10})+$", r"(a+){1,40}$", r"(?:ab|a)*c"])
def test_C_L9_more_catastrophic_shapes_are_rejected(pattern):
    with pytest.raises(ConfigError):
        make_config(rules=[{"id": "bad", "state": "ACTION", "confidence": 0.9, "when": {"body_regex": pattern}}])


def test_C_I1_unreadable_anchor_location_is_not_called_corrupt(data_dir, tmp_path, monkeypatch):
    blocker = tmp_path / "anchor-is-a-file"
    blocker.write_text("x")
    db = data_dir / "a.sqlite3"
    with AuditLedger(db, head_path=blocker / "sub" / "x.head.json", check_anchor=False) as led:
        with pytest.raises(AuditUnavailableError) as e:
            led.append(run_id="r", profile="p", mode="m", event="E")
        assert e.value.code == "AUDIT_HEAD_WRITE"
    with pytest.raises(AuditUnavailableError) as e2:
        AuditLedger(db, head_path=blocker / "x.head.json")
    assert e2.value.code == "AUDIT_ANCHOR_UNREADABLE"


def test_B_M3_concurrent_reader_never_raises_a_false_anchor_alarm(tmp_path):
    """status/doctor take no lock: opening the ledger while a run writes must never report tampering
    (the anchor is written after COMMIT - the very first rows of a fresh ledger are the critical window)."""
    import subprocess
    import sys
    import textwrap

    root = Path(__file__).resolve().parents[1]
    db = tmp_path / "audit.sqlite3"
    env = {**os.environ, "GMAIL_AUTOMATION_ANCHOR_DIR": str(tmp_path / "anchors"), "PYTHONPATH": str(root)}
    writer = textwrap.dedent(f"""
        from pathlib import Path
        from src.audit import AuditLedger
        led = AuditLedger(Path({str(db)!r}))
        for i in range(400):
            led.append(run_id="w", profile="apply", mode="APPLY", event="PLAN", message_id=f"m{{i}}")
        led.close()
    """)
    reader = textwrap.dedent(f"""
        import json, time
        from pathlib import Path
        from src.audit import AuditLedger
        from src.errors import GmailAutomationError
        alarms, opens, t_end = [], 0, time.time() + 3
        while time.time() < t_end:
            try:
                led = AuditLedger(Path({str(db)!r}))
                ok, msg = led.verify()
                if not ok:
                    alarms.append(msg)
                led.close()
                opens += 1
            except GmailAutomationError as exc:
                if exc.code != "AUDIT_LOCKED":
                    alarms.append(exc.code)
        print(json.dumps({{"opens": opens, "alarms": alarms}}))
    """)
    w = subprocess.Popen([sys.executable, "-c", writer], env=env)
    r = subprocess.run([sys.executable, "-c", reader], env=env, capture_output=True, text=True, timeout=120)
    assert w.wait(timeout=120) == 0
    stats = json.loads(r.stdout.strip().splitlines()[-1])
    assert stats["opens"] > 5 and stats["alarms"] == [], stats


def test_transport_self_test_is_part_of_every_gate_summary(cfg, ledger):
    from src.gmail_client import transport_self_test

    assert all(transport_self_test().values())
    s, _ = run_engine(mailbox(), cfg, ledger, apply=False)
    assert s.send_block == "PASS" and s.delete_block == "PASS"
