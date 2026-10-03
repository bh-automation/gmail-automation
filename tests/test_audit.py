import shutil
import sqlite3
import time

import pytest

from src.audit import AuditLedger
from src.errors import AuditIntegrityError, AuditUnavailableError
from tests.conftest import run_engine
from tests.fakes import FakeGmail, make_message


def fill(led, n=3):
    for i in range(n):
        led.append(
            run_id="r1",
            profile="apply",
            mode="APPLY",
            event="PLAN",
            message_id=f"m{i}",
            before_state={"labels": []},
            after_state={"labels": ["JARVIS/ACTION"]},
            confidence=0.9,
        )


def test_chain_verifies_and_rows_have_required_schema(ledger):
    fill(ledger)
    ok, msg = ledger.verify()
    assert ok, msg
    row = ledger.rows()[0]
    for col in (
        "run_id",
        "ts",
        "profile",
        "message_id",
        "thread_id",
        "action_type",
        "rule_id",
        "confidence",
        "before_state",
        "after_state",
        "outcome",
        "error_code",
        "content_fingerprint",
    ):
        assert col in row


def test_ledger_is_append_only(ledger):
    fill(ledger)
    with pytest.raises(sqlite3.DatabaseError):
        ledger.raw.execute("UPDATE ledger SET outcome='X' WHERE seq=1")
    with pytest.raises(sqlite3.DatabaseError):
        ledger.raw.execute("DELETE FROM ledger WHERE seq=1")


def test_tampering_is_detected(ledger):
    fill(ledger)
    ledger.raw.execute("DROP TRIGGER ledger_no_update")
    ledger.raw.execute("UPDATE ledger SET outcome='FORGED' WHERE seq=2")
    ok, msg = ledger.verify()
    assert not ok and "seq 2" in msg


def test_deleted_row_is_detected(data_dir):
    led = AuditLedger(data_dir / "a.sqlite3")
    fill(led, 4)
    led.raw.execute("DROP TRIGGER ledger_no_delete")
    led.raw.execute("DELETE FROM ledger WHERE seq=2")
    assert not led.verify()[0]
    led.close()


def test_stale_backup_restore_is_detected(data_dir):
    db = data_dir / "audit.sqlite3"
    led = AuditLedger(db)
    fill(led, 2)
    led.close()
    shutil.copy(db, data_dir / "backup.sqlite3")
    led = AuditLedger(db)
    fill(led, 3)
    led.close()
    shutil.copy(data_dir / "backup.sqlite3", db)  # restore old copy, head file stays current
    with pytest.raises(AuditIntegrityError) as e:
        AuditLedger(db)
    assert e.value.code == "AUDIT_ROLLBACK"


def test_rewritten_history_is_detected_via_head(data_dir):
    db = data_dir / "audit.sqlite3"
    led = AuditLedger(db)
    fill(led, 2)
    led.close()
    forged = data_dir / "forged.sqlite3"
    other = AuditLedger(forged, head_path=data_dir / "forged.head.json")
    for i in range(2):  # same length, different (but internally consistent) history
        other.append(run_id="rX", profile="apply", mode="APPLY", event="FORGED", message_id=f"x{i}")
    other.close()
    assert AuditLedger(forged, head_path=data_dir / "forged.head.json").verify()[0]
    __import__("os").replace(forged, db)
    with pytest.raises(AuditIntegrityError) as e:
        AuditLedger(db)
    assert e.value.code == "AUDIT_HEAD_MISMATCH"


def test_corrupt_db_fails_closed(data_dir):
    p = data_dir / "corrupt.sqlite3"
    p.write_bytes(b"this is not a database" * 100)
    with pytest.raises(AuditIntegrityError) as e:
        AuditLedger(p)
    assert e.value.code == "AUDIT_CORRUPT"


def test_locked_db_fails_closed_quickly(data_dir):
    p = data_dir / "locked.sqlite3"
    AuditLedger(p).close()
    other = sqlite3.connect(str(p), isolation_level=None)
    other.execute("BEGIN EXCLUSIVE")
    led = AuditLedger.__new__(AuditLedger)
    t0 = time.monotonic()
    with pytest.raises((AuditUnavailableError, AuditIntegrityError)):
        AuditLedger.__init__(led, p, timeout=0.2)
        led.append(run_id="r", profile="p", mode="m", event="E")
    assert time.monotonic() - t0 < 5
    other.execute("ROLLBACK")
    other.close()


def test_interrupted_migration_rolls_back_and_recovers(data_dir):
    p = data_dir / "mig.sqlite3"
    with pytest.raises(AuditUnavailableError) as e:
        AuditLedger(p, _fail_migration_after=3)
    assert e.value.code == "MIGRATION_INTERRUPTED"
    con = sqlite3.connect(str(p))
    tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    con.close()
    assert "ledger" not in tables and "schema_version" not in tables  # nothing half-applied
    led = AuditLedger(p)
    fill(led, 1)
    assert led.verify()[0]
    led.close()


def test_newer_schema_is_refused(data_dir):
    p = data_dir / "new.sqlite3"
    AuditLedger(p).close()
    con = sqlite3.connect(str(p))
    con.execute("INSERT INTO schema_version(version) VALUES (99)")
    con.commit()
    con.close()
    with pytest.raises(AuditIntegrityError) as e:
        AuditLedger(p)
    assert e.value.code == "AUDIT_SCHEMA_NEWER"


def test_timestamps_are_utc_regardless_of_timezone(data_dir, monkeypatch):
    monkeypatch.setenv("TZ", "Pacific/Kiritimati")
    if hasattr(time, "tzset"):
        time.tzset()
    led = AuditLedger(data_dir / "tz.sqlite3")
    led.append(run_id="r", profile="p", mode="m", event="E")
    ts = led.rows()[0]["ts"]
    led.close()
    monkeypatch.delenv("TZ")
    if hasattr(time, "tzset"):
        time.tzset()
    assert ts.endswith("Z")
    assert abs(time.time() - time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")) + time.timezone) < 120


def test_unknown_fields_rejected(ledger):
    with pytest.raises(ValueError):
        ledger.append(run_id="r", profile="p", mode="m", event="E", body="secret mail text")


def test_no_body_subject_or_address_stored(cfg_apply, ledger):
    g = FakeGmail()
    g.add(
        make_message(
            "m1",
            "t1",
            from_="Geheim <secret.person@private.example>",
            subject="SUBJ-MARKER-4711",
            plain="Bitte unterschreiben BODY-MARKER-0815",
        )
    )
    run_engine(g, cfg_apply, ledger, apply=True)
    dump = "\n".join(str(v) for r in ledger.rows() for v in r.values())
    for marker in ("BODY-MARKER-0815", "SUBJ-MARKER-4711", "secret.person", "private.example"):
        assert marker not in dump
