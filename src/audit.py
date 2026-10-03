"""SQLite audit ledger: append-only, hash-chained, rollback-detecting.

* Write-ahead: PREPARE is committed before any Gmail mutation, the outcome after it.
* UPDATE/DELETE on the ledger are blocked by triggers; every row carries
  row_hash = sha256(prev_hash | canonical row). `verify()` recomputes the chain.
* A rollback anchor (last seq + hash) is kept OUTSIDE the data folder (paths.anchor_dir).
  Restoring an older DB - alone or together with its whole folder - is detected
  (AUDIT_ROLLBACK). A ledger with rows but without anchor is refused (AUDIT_ANCHOR_MISSING)
  until the operator explicitly runs `audit-rebaseline --confirm` (audited HEAD_REBASELINE).
* Every SQLite error is mapped to a precise, stable code (LOCKED / FULL / READONLY /
  CORRUPT / IO) - a locked DB is never reported as corrupt.
* No message bodies are stored - only IDs, label names, rule ids and fingerprints.
"""

from __future__ import annotations

import contextlib
import functools
import hashlib
import json
import os
import sqlite3
import tempfile
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import paths
from .errors import AuditIntegrityError, AuditUnavailableError, GmailAutomationError

GENESIS = "0" * 64
SCHEMA_VERSION = 2
APPLIED_EVENTS = frozenset({"APPLIED", "RECONCILED_APPLIED", "APPLIED_DRIFT"})
TERMINAL_EVENTS = APPLIED_EVENTS | {"FAILED", "RECONCILED_NOT_APPLIED", "RECONCILED_DRIFT"}
UNDO_DONE_EVENTS = frozenset({"UNDONE", "UNDO_RECONCILED_DONE"})
UNDO_TERMINAL = UNDO_DONE_EVENTS | {
    "UNDO_FAILED",
    "UNDO_RECONCILED_NOT_DONE",
    "UNDO_RECONCILED_DRIFT",
    "UNDO_COMPENSATED",
}
LABEL_STATE_EVENTS = APPLIED_EVENTS | UNDO_DONE_EVENTS | {"UNDO_COMPENSATED"}
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
    2: [
        "CREATE INDEX ix_ledger_message ON ledger(message_id)",
        "CREATE INDEX ix_ledger_event ON ledger(event)",
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


def _labels(state_json: str | None) -> tuple[str, ...]:
    try:
        return tuple(sorted(json.loads(state_json or "{}").get("labels", [])))
    except (ValueError, AttributeError, TypeError):
        return ()


def map_sqlite_error(exc: sqlite3.Error, during: str = "") -> GmailAutomationError:
    """Precise, stable error codes instead of raw tracebacks (and never 'corrupt' for a lock)."""
    name = str(getattr(exc, "sqlite_errorname", "") or "")
    where = f" ({during})" if during else ""
    if name.startswith(("SQLITE_BUSY", "SQLITE_LOCKED")):
        return AuditUnavailableError(
            f"Audit DB is locked by another program{where} - close DB viewers/backup tools and retry",
            code="AUDIT_LOCKED",
        )
    if name.startswith("SQLITE_FULL"):
        return AuditUnavailableError(f"Disk full - the audit DB cannot be written{where}", code="AUDIT_FULL")
    if name.startswith(("SQLITE_READONLY", "SQLITE_CANTOPEN", "SQLITE_PERM", "SQLITE_AUTH")):
        return AuditUnavailableError(f"Audit DB is read-only or cannot be opened{where}", code="AUDIT_READONLY")
    if name.startswith(("SQLITE_CORRUPT", "SQLITE_NOTADB")):
        return AuditIntegrityError(f"Audit DB is corrupt or not a database{where}", code="AUDIT_CORRUPT")
    if name.startswith("SQLITE_IOERR"):
        return AuditUnavailableError(f"Audit DB I/O error{where}", code="AUDIT_IO")
    return AuditUnavailableError(f"Audit DB error {name or exc.__class__.__name__}{where}", code="AUDIT_UNAVAILABLE")


def _db_guard[**P, R](fn: Callable[P, R]) -> Callable[P, R]:
    @functools.wraps(fn)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return fn(*args, **kwargs)
        except sqlite3.Error as exc:
            raise map_sqlite_error(exc, fn.__name__) from None

    return wrapper


def _fsync_dir(directory: Path) -> None:
    if os.name != "posix":
        return
    with contextlib.suppress(OSError):
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


class AuditLedger:
    def __init__(
        self,
        db_path: Path,
        *,
        head_path: Path | None = None,
        timeout: float = 5.0,
        now: Callable[[], str] = utc_now,
        check_anchor: bool = True,
        _fail_migration_after: int | None = None,
    ) -> None:
        self.path = Path(db_path)
        self.head_path = Path(head_path) if head_path else paths.anchor_path_for(self.path)
        self._now = now
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise AuditUnavailableError(
                f"Audit DB location not writable ({exc.__class__.__name__})", code="AUDIT_UNWRITABLE"
            ) from None
        try:
            self._db = sqlite3.connect(str(self.path), timeout=timeout, isolation_level=None)
        except sqlite3.Error as exc:
            raise map_sqlite_error(exc, "open") from None
        try:
            self._db.row_factory = sqlite3.Row
            self._db.execute("PRAGMA synchronous=FULL")
            check = self._db.execute("PRAGMA quick_check").fetchone()[0]
            if check != "ok":
                raise AuditIntegrityError("Audit DB failed quick_check", code="AUDIT_CORRUPT")
            self._migrate(_fail_migration_after)
            self._check_schema()
            if check_anchor:
                self._check_head(update=True)
        except sqlite3.Error as exc:
            self._db.close()
            raise map_sqlite_error(exc, "open") from None
        except BaseException:
            self._db.close()
            raise

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
        except sqlite3.Error as exc:
            raise map_sqlite_error(exc, "begin") from None
        try:
            yield self._db
        except BaseException:
            if self._db.in_transaction:
                with contextlib.suppress(sqlite3.Error):
                    self._db.execute("ROLLBACK")
            raise
        try:
            self._db.execute("COMMIT")
        except sqlite3.Error as exc:
            if self._db.in_transaction:
                with contextlib.suppress(sqlite3.Error):
                    self._db.execute("ROLLBACK")
            raise map_sqlite_error(exc, "commit") from None

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

    def _check_schema(self) -> None:
        objs = {
            (r[0], r[1])
            for r in self._db.execute("SELECT type, name FROM sqlite_master WHERE type IN ('table','trigger')")
        }
        required = {("table", "ledger"), ("trigger", "ledger_no_update"), ("trigger", "ledger_no_delete")}
        if not required <= objs:
            missing = sorted(n for _, n in required - objs)
            raise AuditIntegrityError(f"Audit DB schema incomplete (missing {missing})", code="AUDIT_SCHEMA_INVALID")

    # ------------------------------------------------------------------ head / rollback anchor
    def head(self) -> tuple[int, str]:
        row = self._db.execute("SELECT seq, row_hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
        return (int(row["seq"]), str(row["row_hash"])) if row else (0, GENESIS)

    def _read_head_file(self) -> tuple[int, str] | None:
        try:
            data = json.loads(self.head_path.read_text(encoding="utf-8"))
            seq, h = int(data["seq"]), str(data["hash"])
        except FileNotFoundError:
            return None
        except (OSError, ValueError, KeyError, TypeError):
            raise AuditIntegrityError(
                "Audit anchor file is corrupt - check the ledger, then run `audit-rebaseline --confirm`",
                code="AUDIT_HEAD_CORRUPT",
            ) from None
        if seq < 0 or len(h) != 64:
            raise AuditIntegrityError("Audit anchor file is corrupt", code="AUDIT_HEAD_CORRUPT")
        return seq, h

    def _write_head_file(self, seq: int, h: str) -> None:
        """Atomic, fsync'ed, unique temp file; retries Windows sharing violations (AV scanner, indexer)."""
        directory = self.head_path.parent
        tmp = ""
        try:
            paths.ensure_private_dir(directory)
            fd, tmp = tempfile.mkstemp(prefix=".head-", suffix=".tmp", dir=directory)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"seq": seq, "hash": h, "v": 1}))
                fh.flush()
                os.fsync(fh.fileno())
            for attempt in range(6):
                try:
                    os.replace(tmp, self.head_path)
                    tmp = ""
                    break
                except PermissionError:
                    if attempt == 5:
                        raise
                    time.sleep(0.05 * (attempt + 1))
            _fsync_dir(directory)
        except OSError as exc:
            raise AuditUnavailableError(
                f"Audit anchor not writable ({exc.__class__.__name__})", code="AUDIT_HEAD_WRITE"
            ) from None
        finally:
            if tmp:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)

    def _check_head(self, *, update: bool) -> None:
        # Read the anchor BEFORE the DB head: anchors are written after COMMIT, so anchor <= head
        # always holds for a consistent ledger (no false AUDIT_ROLLBACK under concurrent writers).
        for attempt in range(6):
            file_head = self._read_head_file()
            db_seq, db_hash = self.head()
            if file_head is not None or not db_seq:
                break
            time.sleep(0.1 * (attempt + 1))  # a writer may sit between its first COMMIT and its anchor write
        if file_head is None:
            if db_seq:
                raise AuditIntegrityError(
                    f"Audit rollback anchor missing although the ledger has {db_seq} rows (restored backup, "
                    "new user profile or deleted anchor?) - check, then run `audit-rebaseline --confirm`",
                    code="AUDIT_ANCHOR_MISSING",
                )
            return
        f_seq, f_hash = file_head
        if f_seq > db_seq:
            raise AuditIntegrityError(
                f"Audit DB is older than its last known head (seq {db_seq} < {f_seq}): stale backup restored "
                "or ledger replaced?",
                code="AUDIT_ROLLBACK",
            )
        if f_seq:
            row = self._db.execute("SELECT row_hash FROM ledger WHERE seq=?", (f_seq,)).fetchone()
            if row is None or row["row_hash"] != f_hash:
                raise AuditIntegrityError(
                    "Audit head mismatch - ledger history was rewritten", code="AUDIT_HEAD_MISMATCH"
                )
        if update and f_seq < db_seq:
            self._write_head_file(db_seq, db_hash)  # anchor lagged (crash between commit and anchor write)

    # ------------------------------------------------------------------ write
    @_db_guard
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

    @_db_guard
    def rebaseline(self, *, run_id: str, reason: str = "operator") -> int:
        """Explicit operator repair after AUDIT_ANCHOR_MISSING / AUDIT_HEAD_CORRUPT / AUDIT_ROLLBACK.

        Only a ledger whose hash chain is intact can be re-anchored; the act itself is audited."""
        ok, msg = self.verify_chain()
        if not ok:
            raise AuditIntegrityError(f"Hash chain broken ({msg}) - refusing to re-anchor", code="AUDIT_CHAIN_BROKEN")
        try:
            previous: Any = self._read_head_file()
        except AuditIntegrityError:
            previous = "corrupt"
        db_seq, db_hash = self.head()
        return self.append(
            run_id=run_id,
            profile="operator",
            mode="DRY-RUN",
            event="HEAD_REBASELINE",
            outcome="REBASELINED",
            detail={"previous_anchor": previous, "db_head": [db_seq, db_hash], "reason": reason[:100]},
        )

    # ------------------------------------------------------------------ verify
    @_db_guard
    def verify_chain(self) -> tuple[bool, str]:
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
        return True, f"{count} rows verified"

    @_db_guard
    def verify(self) -> tuple[bool, str]:
        ok, msg = self.verify_chain()
        if not ok:
            return ok, msg
        try:
            self._check_head(update=False)
        except AuditIntegrityError as exc:
            return False, str(exc)
        return True, msg

    # ------------------------------------------------------------------ queries
    @_db_guard
    def rows(self, run_id: str | None = None) -> list[dict[str, Any]]:
        if run_id is None:
            cur = self._db.execute("SELECT * FROM ledger ORDER BY seq")
        else:
            cur = self._db.execute("SELECT * FROM ledger WHERE run_id=? ORDER BY seq", (run_id,))
        return [dict(r) for r in cur]

    def _events_for(self, action_id: str) -> list[dict[str, Any]]:
        return [dict(r) for r in self._db.execute("SELECT * FROM ledger WHERE action_id=? ORDER BY seq", (action_id,))]

    @staticmethod
    def _in(values: Iterable[str]) -> tuple[str, list[str]]:
        vals = sorted(values)
        return ",".join("?" * len(vals)), vals

    @_db_guard
    def is_key_applied(self, key: str) -> bool:
        marks, vals = self._in(APPLIED_EVENTS)
        row = self._db.execute(
            f"SELECT 1 FROM ledger WHERE idempotency_key=? AND event IN ({marks}) LIMIT 1",  # noqa: S608
            [key, *vals],
        ).fetchone()
        return row is not None

    @_db_guard
    def pending(self) -> list[dict[str, Any]]:
        marks, vals = self._in(TERMINAL_EVENTS)
        cur = self._db.execute(
            "SELECT p.* FROM ledger p WHERE p.event='PREPARE' AND NOT EXISTS ("  # noqa: S608 - fixed markers
            f"SELECT 1 FROM ledger t WHERE t.action_id=p.action_id AND t.event IN ({marks})) ORDER BY p.seq",
            vals,
        )
        return [dict(r) for r in cur]

    @_db_guard
    def pending_undo(self) -> list[dict[str, Any]]:
        marks, vals = self._in(UNDO_TERMINAL)
        cur = self._db.execute(
            "SELECT p.* FROM ledger p WHERE p.event='UNDO_PREPARE' AND NOT EXISTS ("  # noqa: S608 - fixed markers
            f"SELECT 1 FROM ledger t WHERE t.action_id=p.action_id AND t.seq>p.seq AND t.event IN ({marks})) "
            "ORDER BY p.seq",
            vals,
        )
        return [dict(r) for r in cur]

    @staticmethod
    def _undone(events: list[dict[str, Any]]) -> bool:
        undone = False
        for e in events:  # ordered by seq: the latest undo-related event wins
            if e["event"] in UNDO_DONE_EVENTS:
                undone = True
            elif e["event"] == "UNDO_COMPENSATED":
                undone = False
        return undone

    @_db_guard
    def applied_actions(self, run_id: str) -> list[dict[str, Any]]:
        out = []
        for prep in self._db.execute("SELECT * FROM ledger WHERE run_id=? AND event='PREPARE' ORDER BY seq", (run_id,)):
            events = self._events_for(prep["action_id"])
            applied = [e for e in events if e["event"] in APPLIED_EVENTS]
            if not applied:
                continue
            item = dict(prep)
            item["after_state"] = applied[-1]["after_state"] or prep["after_state"]
            item["applied_seq"] = applied[-1]["seq"]
            item["undone"] = self._undone(events)
            out.append(item)
        return out

    @_db_guard
    def later_applied_label_actions(self, message_id: str, after_seq: int, exclude_run: str) -> list[dict[str, Any]]:
        """Applied, not undone LABEL_CHANGE actions of OTHER runs on the same message after `after_seq`."""
        marks, vals = self._in(APPLIED_EVENTS)
        out = []
        for r in self._db.execute(
            f"SELECT DISTINCT action_id, run_id FROM ledger WHERE message_id=? AND seq>? AND run_id<>? "  # noqa: S608
            f"AND action_type='LABEL_CHANGE' AND event IN ({marks})",
            [message_id, after_seq, exclude_run, *vals],
        ):
            if r["action_id"] and not self._undone(self._events_for(r["action_id"])):
                out.append(dict(r))
        return out

    @_db_guard
    def last_set_labels(self, message_id: str) -> tuple[str, ...] | None:
        """App labels this program last put on a message (apply, undo or compensation), or None."""
        marks, vals = self._in(LABEL_STATE_EVENTS)
        row = self._db.execute(
            f"SELECT after_state FROM ledger WHERE message_id=? AND action_type='LABEL_CHANGE' "  # noqa: S608
            f"AND event IN ({marks}) ORDER BY seq DESC LIMIT 1",
            [message_id, *vals],
        ).fetchone()
        return None if row is None else _labels(row["after_state"])

    @_db_guard
    def failure_streak(self, message_id: str, codes: Iterable[str]) -> int:
        """Message-scoped FAILED rows for a message since its last successful mutation."""
        a_marks, a_vals = self._in(APPLIED_EVENTS)
        c_marks, c_vals = self._in(codes)
        if not c_vals:
            return 0
        last = self._db.execute(
            f"SELECT MAX(seq) FROM ledger WHERE message_id=? AND event IN ({a_marks})",  # noqa: S608
            [message_id, *a_vals],
        ).fetchone()[0]
        row = self._db.execute(
            f"SELECT COUNT(*) FROM ledger WHERE message_id=? AND event='FAILED' AND seq>? "  # noqa: S608
            f"AND error_code IN ({c_marks})",
            [message_id, int(last or 0), *c_vals],
        ).fetchone()
        return int(row[0])

    @_db_guard
    def quarantined(self, codes: Iterable[str], threshold: int) -> list[str]:
        ids = [
            str(r[0])
            for r in self._db.execute(
                "SELECT DISTINCT message_id FROM ledger WHERE event='FAILED' AND message_id IS NOT NULL"
            )
        ]
        codes = list(codes)
        return [m for m in ids if self.failure_streak(m, codes) >= threshold]

    @_db_guard
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

    @_db_guard
    def last_undoable_run(self) -> str | None:
        for r in self._db.execute(
            "SELECT DISTINCT run_id, MAX(seq) AS m FROM ledger WHERE mode='APPLY' AND "
            "event='PREPARE' GROUP BY run_id ORDER BY m DESC"
        ):
            acts = [a for a in self.applied_actions(r["run_id"]) if a["action_type"] == "LABEL_CHANGE"]
            if any(not a["undone"] for a in acts):
                return str(r["run_id"])
        return None

    @_db_guard
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
