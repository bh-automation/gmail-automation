"""SQLite audit ledger: append-only, hash-chained, rollback-detecting.

* Write-ahead: PREPARE is committed before any Gmail mutation, the outcome after it.
* UPDATE/DELETE on the ledger are blocked by triggers; every row carries
  row_hash = sha256(prev_hash | canonical row). `verify()` recomputes the chain.
* A head file (last seq + hash) outside the DB detects restore of a stale backup.
* No message bodies are stored - only IDs, label names, rule ids and fingerprints.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .errors import AuditIntegrityError, AuditUnavailableError

GENESIS = "0" * 64
SCHEMA_VERSION = 1
APPLIED_EVENTS = frozenset({"APPLIED", "RECONCILED_APPLIED"})
TERMINAL_EVENTS = frozenset({"APPLIED", "FAILED", "RECONCILED_APPLIED", "RECONCILED_NOT_APPLIED", "RECONCILED_DRIFT"})
UNDO_TERMINAL = frozenset(
    {"UNDONE", "UNDO_FAILED", "UNDO_RECONCILED_DONE", "UNDO_RECONCILED_NOT_DONE", "UNDO_RECONCILED_DRIFT"}
)
HASHED_FIELDS = (
    "ts",
    "run_id",
    "profile",
    "mode",
    "event",
    "action_id",
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
    "idempotency_key",
    "detail",
)

MIGRATIONS: dict[int, list[str]] = {
    1: [
        """CREATE TABLE ledger (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL, run_id TEXT NOT NULL, profile TEXT NOT NULL, mode TEXT NOT NULL,
            event TEXT NOT NULL, action_id TEXT, message_id TEXT, thread_id TEXT, action_type TEXT,
            rule_id TEXT, confidence REAL, before_state TEXT, after_state TEXT, outcome TEXT,
            error_code TEXT, content_fingerprint TEXT, idempotency_key TEXT, detail TEXT,
            prev_hash TEXT NOT NULL, row_hash TEXT NOT NULL)""",
        "CREATE INDEX ix_ledger_run ON ledger(run_id)",
        "CREATE INDEX ix_ledger_action ON ledger(action_id)",
        "CREATE INDEX ix_ledger_key ON ledger(idempotency_key)",
        "CREATE INDEX ix_ledger_thread ON ledger(thread_id)",
        """CREATE TRIGGER ledger_no_update BEFORE UPDATE ON ledger
           BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END""",
        """CREATE TRIGGER ledger_no_delete BEFORE DELETE ON ledger
           BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END""",
    ],
}


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _canon(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _row_hash(prev: str, row: dict[str, Any]) -> str:
    payload = json.dumps(
        {k: row.get(k) for k in HASHED_FIELDS}, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    return hashlib.sha256((prev + "|" + payload).encode("utf-8")).hexdigest()


class AuditLedger:
    def __init__(
        self,
        db_path: Path,
        *,
        head_path: Path | None = None,
        timeout: float = 5.0,
        now: Callable[[], str] = utc_now,
        _fail_migration_after: int | None = None,
    ) -> None:
        self.path = Path(db_path)
        self.head_path = Path(head_path) if head_path else self.path.with_suffix(".head.json")
        self._now = now
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(str(self.path), timeout=timeout, isolation_level=None)
            self._db.row_factory = sqlite3.Row
            self._db.execute("PRAGMA synchronous=FULL")
            check = self._db.execute("PRAGMA quick_check").fetchone()[0]
        except sqlite3.DatabaseError as exc:
            raise AuditIntegrityError(
                f"Audit DB unreadable or corrupt ({exc.__class__.__name__})", code="AUDIT_CORRUPT"
            ) from None
        except OSError as exc:
            raise AuditUnavailableError(
                f"Audit DB location not writable ({exc.__class__.__name__})", code="AUDIT_UNWRITABLE"
            ) from None
        if check != "ok":
            raise AuditIntegrityError("Audit DB failed quick_check", code="AUDIT_CORRUPT")
        self._migrate(_fail_migration_after)
        self._check_head()

    # ------------------------------------------------------------------ lifecycle
    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> AuditLedger:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        try:
            self._db.execute("BEGIN IMMEDIATE")
        except sqlite3.OperationalError as exc:
            raise AuditUnavailableError(f"Audit DB locked/unavailable ({exc})", code="AUDIT_LOCKED") from None
        try:
            yield self._db
        except BaseException:
            self._db.execute("ROLLBACK")
            raise
        else:
            try:
                self._db.execute("COMMIT")
            except sqlite3.OperationalError as exc:
                self._db.execute("ROLLBACK")
                raise AuditUnavailableError(f"Audit commit failed ({exc})", code="AUDIT_COMMIT") from None

    def _version(self) -> int:
        row = self._db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'").fetchone()
        if row is None:
            return 0
        v = self._db.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
        return int(v or 0)

    def _migrate(self, fail_after: int | None) -> None:
        current = self._version()
        if current > SCHEMA_VERSION:
            raise AuditIntegrityError(
                f"Audit DB schema {current} is newer than this program ({SCHEMA_VERSION})", code="AUDIT_SCHEMA_NEWER"
            )
        for version in range(current + 1, SCHEMA_VERSION + 1):
            with self._tx() as db:
                if version == 1:
                    db.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
                for i, stmt in enumerate(MIGRATIONS[version]):
                    if fail_after is not None and i >= fail_after:
                        raise AuditUnavailableError(
                            "simulated interruption during migration", code="MIGRATION_INTERRUPTED"
                        )
                    db.execute(stmt)
                db.execute("INSERT INTO schema_version(version) VALUES (?)", (version,))

    # ------------------------------------------------------------------ head / rollback detection
    def head(self) -> tuple[int, str]:
        row = self._db.execute("SELECT seq, row_hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
        return (int(row["seq"]), str(row["row_hash"])) if row else (0, GENESIS)

    def _read_head_file(self) -> tuple[int, str] | None:
        try:
            data = json.loads(self.head_path.read_text(encoding="utf-8"))
            return int(data["seq"]), str(data["hash"])
        except FileNotFoundError:
            return None
        except (OSError, ValueError, KeyError, TypeError):
            raise AuditIntegrityError("Audit head file is corrupt", code="AUDIT_HEAD_CORRUPT") from None

    def _write_head_file(self, seq: int, h: str) -> None:
        tmp = self.head_path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"seq": seq, "hash": h}), encoding="utf-8")
        os.replace(tmp, self.head_path)

    def _check_head(self) -> None:
        file_head = self._read_head_file()
        db_seq, db_hash = self.head()
        if file_head is None:
            if db_seq:
                self._write_head_file(db_seq, db_hash)  # first open after upgrade: adopt current head
            return
        f_seq, f_hash = file_head
        if f_seq > db_seq:
            raise AuditIntegrityError(
                f"Audit DB is older than its last known head (seq {db_seq} < {f_seq}): stale backup restored?",
                code="AUDIT_ROLLBACK",
            )
        if f_seq:
            row = self._db.execute("SELECT row_hash FROM ledger WHERE seq=?", (f_seq,)).fetchone()
            if row is None or row["row_hash"] != f_hash:
                raise AuditIntegrityError(
                    "Audit head mismatch - ledger history was rewritten", code="AUDIT_HEAD_MISMATCH"
                )

    # ------------------------------------------------------------------ write
    def append(self, *, run_id: str, profile: str, mode: str, event: str, **fields: Any) -> int:
        unknown = set(fields) - set(HASHED_FIELDS)
        if unknown:
            raise ValueError(f"unknown audit fields {sorted(unknown)}")
        row: dict[str, Any] = {k: None for k in HASHED_FIELDS}
        row.update({"ts": self._now(), "run_id": run_id, "profile": profile, "mode": mode, "event": event})
        for key, value in fields.items():
            if key == "confidence" and value is not None:
                row[key] = round(float(value), 4)
            elif key in ("before_state", "after_state", "detail"):
                row[key] = _canon(value)
            else:
                row[key] = value
        with self._tx() as db:
            last = db.execute("SELECT row_hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
            prev = str(last["row_hash"]) if last else GENESIS
            h = _row_hash(prev, row)
            cols = ", ".join([*HASHED_FIELDS, "prev_hash", "row_hash"])
            marks = ", ".join("?" * (len(HASHED_FIELDS) + 2))
            cur = db.execute(
                f"INSERT INTO ledger ({cols}) VALUES ({marks})",  # noqa: S608 - fixed columns
                [row[k] for k in HASHED_FIELDS] + [prev, h],
            )
            seq = int(cur.lastrowid or 0)
        self._write_head_file(seq, h)
        return seq

    # ------------------------------------------------------------------ verify
    def verify(self) -> tuple[bool, str]:
        prev = GENESIS
        count = 0
        for row in self._db.execute("SELECT * FROM ledger ORDER BY seq"):
            d = dict(row)
            if d["prev_hash"] != prev:
                return False, f"chain break at seq {d['seq']}"
            if _row_hash(prev, d) != d["row_hash"]:
                return False, f"row hash mismatch at seq {d['seq']}"
            prev = d["row_hash"]
            count += 1
        try:
            self._check_head()
        except AuditIntegrityError as exc:
            return False, str(exc)
        return True, f"{count} rows verified"

    # ------------------------------------------------------------------ queries
    def rows(self, run_id: str | None = None) -> list[dict[str, Any]]:
        if run_id is None:
            cur = self._db.execute("SELECT * FROM ledger ORDER BY seq")
        else:
            cur = self._db.execute("SELECT * FROM ledger WHERE run_id=? ORDER BY seq", (run_id,))
        return [dict(r) for r in cur]

    def _events_for(self, action_id: str) -> list[dict[str, Any]]:
        return [dict(r) for r in self._db.execute("SELECT * FROM ledger WHERE action_id=? ORDER BY seq", (action_id,))]

    def is_key_applied(self, key: str) -> bool:
        row = self._db.execute(
            "SELECT 1 FROM ledger WHERE idempotency_key=? AND event IN ('APPLIED','RECONCILED_APPLIED') LIMIT 1", (key,)
        ).fetchone()
        return row is not None

    def pending(self) -> list[dict[str, Any]]:
        out = []
        for prep in self._db.execute("SELECT * FROM ledger WHERE event='PREPARE' ORDER BY seq"):
            events = {e["event"] for e in self._events_for(prep["action_id"])}
            if not events & TERMINAL_EVENTS:
                out.append(dict(prep))
        return out

    def pending_undo(self) -> list[dict[str, Any]]:
        out = []
        for prep in self._db.execute("SELECT * FROM ledger WHERE event='UNDO_PREPARE' ORDER BY seq"):
            later = [e for e in self._events_for(prep["action_id"]) if e["seq"] > prep["seq"]]
            if not {e["event"] for e in later} & UNDO_TERMINAL:
                out.append(dict(prep))
        return out

    def applied_actions(self, run_id: str) -> list[dict[str, Any]]:
        out = []
        for prep in self._db.execute("SELECT * FROM ledger WHERE run_id=? AND event='PREPARE' ORDER BY seq", (run_id,)):
            events = self._events_for(prep["action_id"])
            applied = [e for e in events if e["event"] in APPLIED_EVENTS]
            if not applied:
                continue
            item = dict(prep)
            item["after_state"] = applied[-1]["after_state"] or prep["after_state"]
            item["undone"] = any(e["event"] in {"UNDONE", "UNDO_RECONCILED_DONE"} for e in events)
            out.append(item)
        return out

    def runs(self, limit: int = 10) -> list[dict[str, Any]]:
        starts = [
            dict(r)
            for r in self._db.execute(
                "SELECT * FROM ledger WHERE event='RUN_START' ORDER BY seq DESC LIMIT ?", (limit,)
            )
        ]
        for s in starts:
            end = self._db.execute(
                "SELECT * FROM ledger WHERE run_id=? AND event='RUN_END' ORDER BY seq DESC LIMIT 1", (s["run_id"],)
            ).fetchone()
            s["end"] = dict(end) if end else None
        return starts

    def last_undoable_run(self) -> str | None:
        for r in self._db.execute(
            "SELECT DISTINCT run_id, MAX(seq) AS m FROM ledger WHERE mode='APPLY' AND "
            "event='PREPARE' GROUP BY run_id ORDER BY m DESC"
        ):
            acts = [a for a in self.applied_actions(r["run_id"]) if a["action_type"] == "LABEL_CHANGE"]
            if any(not a["undone"] for a in acts):
                return str(r["run_id"])
        return None

    def draft_applied(self, thread_id: str, template_id: str) -> bool:
        for r in self._db.execute(
            "SELECT detail FROM ledger WHERE thread_id=? AND action_type='DRAFT_CREATE' AND "
            "event IN ('APPLIED','RECONCILED_APPLIED')",
            (thread_id,),
        ):
            try:
                if json.loads(r["detail"] or "{}").get("template_id") == template_id:
                    return True
            except ValueError:
                continue
        return False

    # test/diagnostic helper - raw connection for tamper simulations only
    @property
    def raw(self) -> sqlite3.Connection:
        return self._db
