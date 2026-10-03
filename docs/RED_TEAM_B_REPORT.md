# Red Team B Report: Reliability, Recovery & Operations

> **Hinweis (Release-Zyklus 1.0.0rc1):** Dies ist der unveränderte Originalbericht des Red-Team-Durchgangs. Die genannten `/tmp/claude-0/...`-Pfade beziehen sich auf den damaligen Prüf-Arbeitsbereich. Alle Proofs of Concept wurden umgekehrt als Regressionstests übernommen: `tests/test_red_team_regressions.py`. Der Fix-Status steht am Ende des Berichts.

Target: `/home/claude/GMAIL-AUTOMATION` (gmail-automation 1.0.0rc1, git HEAD `a46e2b0`), reviewed read-only.
Date: 2026-10-03. Reviewer: Red Team B (did not write the code).

## 1. Result

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 0 |
| Medium | 8 |
| Low | 15 |
| Info | 12 |

**Release rule (docs/RED_TEAM_B.md): no unresolved Critical or High finding, so this review does not block release.**
The 8 Medium findings should still be fixed before S3 (controlled label apply on the real mailbox) and S6 (scheduled runs). Several of them break invariants the project states about itself:
- "already-applied changes stay audited and undoable" (engine.py docstring) is broken by M1.
- "all-or-nothing" undo (undo.py docstring) is broken by M2.
- "the human decision wins; no ping-pong" (comment in test_engine.py) is broken by M6.
- "stale backup detection" is broken by M3.
- "no code path in src/ may reach a forbidden Gmail capability" (forbidden_scan.py docstring) is broken by M7.

What held up well:
- **Crash recovery:** 13 hard-kill points in apply and 6 in undo, each a real `os._exit(137)` with mailbox state persisted. Every one recovered with no duplicate, no pending rows and a complete undo.
- **Single-instance lock:** works as designed.
- **Hash chain:** stays intact under concurrent writers.
- **Interrupted migration:** a real kill mid-migration recovers cleanly.
- **Retries:** 401 and 5xx handling is bounded.
- **Bootstrap and verify:** both run end to end under PowerShell 7.4 with Python 3.13 in a path containing spaces, `ü` and parentheses.

## 2. Method, environment, how to rerun

- **PoCs:** all live in `/tmp/claude-0/redteam-b/`. Nothing under the project was modified. Runtime artefacts go to `scratch/` or pytest tmp dirs.
- **Python:** project venv (Python 3.12.3), with the pinned versions from `requirements-lock.txt`.
- **Test doubles:** `tests/fakes.py` (FakeGmail) via `conftest.py` (`pytest_plugins = ["tests.conftest"]`).
- **Crash harness:** `crashlib.py` and `crash_run.py`. PersistentFake saves the mailbox to JSON after every served request. Kill points can be placed in the Gmail double (before/after the n-th call of an endpoint) and inside `AuditLedger.append` (after INSERT/before COMMIT, after COMMIT/before head write, after head tmp/before replace).
- **Non-admin user simulation:** `setpriv --bounding-set -dac_override,-dac_read_search,-fowner,-chown`, i.e. root without permission override.
- **PowerShell 7.4.6 for Linux:** used for `scripts/bootstrap.ps1` and `scripts/verify.ps1` in a copy (`scratch/Mein Projekt ü (privat)/GMAIL-AUTOMATION`). `cmd.exe` and Windows PowerShell 5.1 are not executable here; those items are static review only.
- **Run everything (112 PoC tests, ~2 min):**
  ```
  cd /home/claude/GMAIL-AUTOMATION && PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. .venv/bin/python -m pytest \
     /tmp/claude-0/redteam-b/ -c /tmp/claude-0/redteam-b/pytest.ini --rootdir=/tmp/claude-0/redteam-b -q -s
  /tmp/claude-0/redteam-b/poc_ci_green_with_send.sh
  /tmp/claude-0/redteam-b/poc_interrupted_bootstrap.sh
  /home/claude/GMAIL-AUTOMATION/.venv/bin/python /tmp/claude-0/redteam-b/poc_head_tmp_race.py
  ```
  Last full run: `poc_run.log`, 112 passed. Each PoC asserts the **observed** behaviour. A test that demonstrates a weakness therefore passes while the weakness exists. Once fixed, invert its final assertions and it becomes a regression test.
- **Project baseline:** 208 tests green before and after the review.

| PoC file | Area |
|---|---|
| `test_b01_crash_matrix.py` | hard-kill crash matrix: apply (13 points) and undo (6 points) |
| `test_b02_concurrency.py` | two instances, readers during writes, lock bypass, deleted lock file |
| `test_b03_idempotency.py` | duplicate events, manual relabel, deleted app label, poison message |
| `test_b04_undo.py` | partial undo, kill-switch coupling, coincident state, applied-but-FAILED, reconcile on transient errors |
| `test_b05_audit_storage.py` | locked/corrupt/full/read-only/unwritable SQLite, head file, stale backup, real migration kill |
| `test_b06_retry.py` | 401/403/429/5xx/network, Retry-After, endless pagination |
| `test_b07_config.py` | missing/malformed/partial-upgrade config, BOM/UTF-16/cp1252, duplicate keys |
| `test_b08_scale.py` | 50k candidates, 300-reply thread, ledger growth, >500 drafts, drafts inside threads |
| `test_b09_static_gate.py` + `poc_ci_green_with_send.sh` | forbidden-method gate bypasses, full CI green with a send path |
| `test_b10_real_client.py` | engine and undo through the **real** googleapiclient (static discovery) via an offline HTTP router |
| `test_b11_clock.py` | timezones, clock jumping back, run-id entropy |
| `test_b12_races_drafts.py` | scan/apply races, edited/discarded drafts, multi-label messages, HTML/empty/payload-less |
| `test_b13_windows_ci_static.py` | `.cmd`/`.ps1` static checks, CI matrix and pinning |
| `poc_interrupted_bootstrap.sh` | first-time setup interrupted after `venv` creation |
| `poc_head_tmp_race.py` | concurrent head-file writers |

## 3. Attack matrix (docs/RED_TEAM_B.md)

Verdict key:
- **PASS:** the invariant holds.
- **PARTIAL:** the core holds, but a variant breaks it.
- **FAIL:** the invariant is broken.
- **N/A:** future stage.

| # | Item | PoC | Expected invariant | Observed | Verdict | Mitigation / residual |
|---|---|---|---|---|---|---|
| 1 | Process crashes after Gmail mutation but before audit completion | `test_b01::test_apply_crash_then_recover[G2,G4,G5,L1,L2,L3,L5,L7,L8]`; `test_b04::test_applied_change_recorded_as_failed_*`, `::test_transient_error_during_reconcile_finalises_pending_as_drift` | The change is applied exactly once, ends up audited as applied, and stays undoable. | All 9 hard-kill variants recover (RECONCILED_APPLIED, no duplicate, undo complete). **But** there are 3 non-crash error paths after a mutation that really reached Gmail: (a) lost response followed by exhausted retries, (b) the verify read fails, (c) a transient error during reconcile. Each is recorded as terminal `FAILED` / `RECONCILED_DRIFT`. Gmail keeps the change and undo never sees it. | PARTIAL → **M1** | Write "outcome unknown" (non-terminal) instead of FAILED. In reconcile, do not finalise on transient or auth errors. |
| 2 | Crash after audit PREPARE, before Gmail mutation | `test_b01[G1,G3,L4]` + existing `test_crash_after_prepare_before_mutation_*` | No mutation; the next APPLY run reconciles NOT_APPLIED and then applies once. | As expected. A PREPARE killed before COMMIT is rolled back by the SQLite hot journal. | PASS | none |
| 3 | Two instances start simultaneously | `test_b02::test_two_apply_runs_started_simultaneously`, `::test_lock_timing_window_menu_scan_vs_scheduled_run`, `::test_status_reader_during_apply_writer_no_false_alarm` | Exactly one instance mutates; the other is refused cleanly. Concurrent read-only commands never raise a false tamper alarm. | Exit codes `[0, 6]`; a menu scan during an apply run is refused with exit 6. 223 concurrent `AuditLedger()`+`verify()` opens during 1,500 writes gave 0 false alarms. | PASS | I1: on POSIX, deleting the lock file lets a second instance in. L8: head-file write race. |
| 4 | Same Gmail event appears twice | `test_b03::test_same_message_listed_twice_and_across_pages_is_processed_once` + existing idempotency tests | One action per message; the second run makes 0 mutations. | 2 modifies and 1 draft, even with the ids repeated across pages; run 2 made 0 mutations. | PASS | none |
| 5 | Thread receives a new message between scan and apply | existing `test_stale_scan_to_apply_new_message_in_thread`; `test_b12::test_reply_arriving_between_freshness_check_and_modify_is_not_detected`, `::test_label_change_on_other_message_in_thread_is_ignored_by_freshness` | Stale plans are skipped. | Detected when the reply arrives before the freshness check. A reply in the window between freshness check and modify is labelled anyway. `historyId` is captured but never compared. | PASS (residual) | I2 |
| 6 | Labels changed manually before undo | existing `test_undo_conflict_*` | Undo refuses (CONFLICT) and the mailbox stays untouched. | As expected. | PASS | Related weaknesses: M6 (apply overrides manual relabel), L7 (coincident state) |
| 7 | Draft manually edited before automated reconciliation | `test_b12::test_draft_edited_by_user_before_reconcile_no_duplicate_but_untracked`, `::test_draft_discarded_by_user_in_crash_window_is_recreated`; `test_b08::test_more_than_500_drafts_*` | No duplicate draft; the ledger reflects reality. | No duplicate (SKIPPED_DUPLICATE_DRAFT). But: the ledger says NOT_APPLIED and undo's manual-draft list omits the draft; a draft discarded in the crash window is re-created; with >500 drafts a **duplicate** is created. | PARTIAL | L15, L10 |
| 8 | SQLite locked / corrupt / unwritable | `test_b05::*` | Fail closed with a precise, stable error code; no mutation; no misleading diagnosis. | Corrupt page or truncated file → AUDIT_CORRUPT. 0-byte DB with head present → AUDIT_ROLLBACK. **Locked DB → reported as `AUDIT_CORRUPT` after 5 s.** A lock taken mid-run, disk full, a read-only DB file or an unwritable data dir all escape as **raw tracebacks** (exit 1, no RUN_END). For disk full, the root cause is masked by `cannot rollback - no transaction is active`. Mutations stay blocked in every case. | FAIL → **M8** | Map all sqlite/OS errors; distinguish BUSY from CORRUPT. |
| 9 | Network fails mid-page | `test_b06::test_5xx_storm_*`, `::test_ssl_eof_mid_pagination_*`, `::test_empty_pages_with_next_token_loop_forever` | Bounded retry with the same pageToken; otherwise fail closed with no partial processing. | 429/5xx/ConnectionError are retried, then the run errors with 0 mutations. SSL EOF, DNS `gaierror`, ENETUNREACH and IncompleteRead are classified UNKNOWN → immediate abort, no retry. Empty pages carrying a `nextPageToken` loop forever (5,001 pages before the PoC guard stopped it). | PARTIAL | L5, L2 |
| 10 | 401 refresh path loops | `test_b06::test_401_refreshes_once_per_call_never_loops` + existing | At most one explicit refresh, then AUTH_401. | 1 refresh, 2 calls, `ERROR:AUTH_401`. | PASS | I11: the transport adds bounded implicit refreshes. |
| 11 | 403 scope mismatch | existing `test_403_on_mutation_*`; `test_b10::test_real_403_insufficient_permissions_fails_closed` | Audited FAILED AUTH_403; fail closed; scopes validated at load. | As expected, also with a real `HttpError`. | PASS | I6: `dailyLimitExceeded` is shown as a scope problem. |
| 12 | 429 burst with Retry-After | `test_b06::test_429_huge_retry_after_has_no_run_level_budget`, `::test_429_on_draft_create_aborts_whole_run`; `test_b10::test_real_429_retry_after_header_is_honoured` | Retry-After honoured and capped; the run stays bounded. | A real 7 s header is honoured; the cap is 60 s per attempt. **No run budget:** a storm kept one run alive for 10.0 h (600 sleeps) with the lock held. A 429 on `drafts.create`/`labels.create` aborts the whole run (treated as ambiguous). | PARTIAL | L2, L4 |
| 13 | 5xx transient failure | `test_b06::test_5xx_storm_is_bounded_and_fails_closed` | Bounded retries, then fail closed. | 4 retries (~12 s), `ERROR:RETRY_EXHAUSTED_SERVER`, 0 mutations. | PASS | none |
| 14 | Clock / timezone variation | `test_b11::*` | All timestamps UTC; ordering by sequence, not wall clock. | Identical UTC run-id/ts under Kiritimati, Adak, Berlin and UTC. With the clock 400 days back, `last_undoable_run` still picks the newest run by seq. | PASS | I7: run-id entropy is 24 bit per second. |
| 15 | Windows path contains spaces / non-ASCII | bootstrap + verify executed in `scratch/Mein Projekt ü (privat)/GMAIL-AUTOMATION`, data dir `bootstrap home ä` (logs `scratch/bootstrap.log`, `scratch/verify.log`); `test_b13::*`; existing umlaut fixtures | Setup, tests and audit work in such paths. | Bootstrap picked Python 3.13 and finished; `VERIFY = PASS` (208 tests). Scripts are pure ASCII with CRLF in the workspace, and the `.cmd` quoting is correct. **The distributed copy `fresh install ü` has an LF-only `.cmd`.** Longest venv path is ~123 chars on Windows. | PASS (pwsh/Linux), UNVERIFIED (cmd.exe, PS 5.1) | L13, I9, I10 |
| 16 | Config missing, malformed or partially upgraded | `test_b07::*` | Fail closed with a CONFIG_* code; the safe default stays in place. | Missing, directory, empty, UTF-16, cp1252, wrong or missing `config_version` all fail closed. A UTF-8 BOM (Notepad) and CRLF are accepted. **Duplicate YAML keys override silently:** an appended `capabilities:` block turns labels and drafts on. | PARTIAL | L11 |
| 17 | Migration interrupted halfway | `test_b05::test_real_kill_in_the_middle_of_migration` + existing simulated test | Nothing half-applied; the next open completes the migration. | A real `os._exit` after 4 DDL statements; the next open recovers and the chain verifies. | PASS | I8 |
| 18 | CI passes while a forbidden method exists in generated code | `test_b09::test_forbidden_scan_misses[8 variants]`, `poc_ci_green_with_send.sh` | The static gate catches any send/delete/trash path. | 8 bypasses pass `forbidden_scan.py`. With a lint-clean, typed `src/reminders.py` that POSTs to `.../messages/send`, **every CI gate is green** (ruff, format, mypy, secret scan, forbidden scan, config check, 208 tests). | **FAIL → M7** | |
| 19 | Dependency update changes Gmail client behavior | `test_b10::*` (real googleapiclient); lock dry-run (26/26 resolved, 0 unpinned extras, `pip check` OK); `test_b13::test_ci_matrix_and_pinning_gaps` | Runtime behaviour pinned and contract-tested against the real library. | Runtime lock is complete, and the real-library contract (request building, params, HttpError, Retry-After) passes with the pinned versions. The project suite has **no** real-library test. Dev tools are unpinned (drift already visible: `ast_serialize 0.12.0` in `.venv` vs `0.12.1` in a fresh bootstrap). No hashes. CI is Python 3.12 only, while the bootstrap prefers 3.13. | PARTIAL | L12 |
| 20 | Run with zero messages | existing `test_zero_messages_run` | Status OK, 0 mutations. | As expected. | PASS | none |
| 21 | Run with 50k candidates and pagination | existing `test_large_mailbox_pagination_is_bounded`; `test_b08::test_50k_candidates_bounded_but_tail_is_never_processed` | Bounded work; every candidate eventually processed. | Bounded at 1,000 messages / 10 pages. **Tail starvation:** 500 of 1,500 matching messages are never classified, however many runs. Each run re-fetches everything (2,011 API calls per run). | PARTIAL | L3 |
| 22 | Thread with 100+ replies | `test_b08::test_thread_with_300_replies_cost_is_constant` | Constant cost. | 1 `threads.get` + 1 `messages.get` for 300 replies. | PASS | I12: `truncated` is unused. |
| 23 | HTML-only and empty-body messages | `test_b12::test_html_only_empty_and_payloadless_messages` | No crash; safe classification. | OK with 4 threads, including payload `{}` and a missing payload. | PASS | none |
| 24 | Single message belongs to multiple user labels | `test_b12::test_message_with_many_user_labels_and_two_app_labels_undo_exact` | Only app labels touched; undo restores the exact labelIds. | 40 foreign labels + STARRED/IMPORTANT + 2 app labels → exact restore. | PASS | none |
| 25 | Undo requested for non-latest run | existing `test_undo_non_latest_run`; `test_b04::test_undo_older_run_silently_reverts_*`, `::test_last_run_selector_stuck_*` | Undo of run N never alters a later run's effects. | The basic case passes. **Coincident state:** undoing the older run wipes the later run's effect and the human state in between; the later run becomes un-undoable (CONFLICT). | PARTIAL | L7, I5 |
| 26 | Audit DB copied/restored from stale backup | existing `test_stale_backup_restore_is_detected`; `test_b05::test_stale_db_restore_undetected_when_head_file_missing`, `::test_whole_folder_restore_undetected_and_reapplies_human_overrides` | A stale ledger is detected and refused. | A DB-only restore is detected. **A missing head file, or restoring the folder (DB + head together), is accepted silently.** The next run re-applies a label the human removed, re-creates a discarded reply draft, and earlier runs can no longer be undone. | **FAIL → M3** | |
| 27 | Watch/PubSub event duplicated or out of order (future stage) | n/a; `test_b10::test_guard_blocks_forbidden_methods_on_real_discovery_resource` | n/a | No watch code exists. `users.watch`/`users.stop` are forbidden endpoints and blocked on the real discovery resource. | N/A | Re-test at S7 (dedup by historyId, out-of-order handling) |
| 28 | Watch expires silently (future stage) | n/a | n/a | As in 27. | N/A | At S7: renewal job, expiry alerting, fallback full sync |

### Additional attacks beyond the matrix

| Attack | PoC | Verdict |
|---|---|---|
| Hard kill at 6 points during **undo** (before/after modify, UNDONE before commit, UNDO_PREPARE before commit, after 2nd modify, UNDO_END before commit), then undo again and a later APPLY run | `test_b01::test_undo_crash_then_recover[U1..U6]` | PASS: undo completes, nothing pending, the later run does not re-apply. |
| App label deleted in Gmail after creation | `test_b03::test_app_label_deleted_in_gmail_blocks_every_future_apply_run` | FAIL → M4 |
| Message whose modify always fails (poison) | `test_b03::test_poison_message_blocks_all_later_actions_forever` | FAIL → M5 |
| Human relabels REFERENCE→DONE | `test_b03::test_manual_relabel_is_overridden_by_next_run` | FAIL → M6 |
| Undo when a restore label was deleted / mid-loop 403 | `test_b04::test_undo_is_not_all_or_nothing_*` | FAIL → M2 |
| Undo after switching capabilities off | `test_b04::test_undo_refused_when_labels_capability_switched_off` | FAIL → L6 |
| Concurrent head-file writers | `poc_head_tmp_race.py` (FileNotFoundError in ~47 % of 2×20,000 writes); `test_b05::test_windows_style_replace_permission_error_after_commit` | FAIL → L8 |
| 0-byte head file after power loss | `test_b05::test_zero_length_head_file_blocks_every_command_without_repair_path` | FAIL → L9 |
| First-time setup interrupted | `poc_interrupted_bootstrap.sh` | FAIL → L1 |
| Ledger growth | `test_b08::test_ledger_growth_costs` | L14 |
| `verify.ps1` behaviour on a failing gate | planted lint error in the copy (`scratch/verify_fail.log`) | PASS: records `G1 LINT = FAIL`, continues, `VERIFY = FAIL`, exit 1 |
| `bootstrap.ps1` candidate probing / array handling | `scratch/probe_candidates.ps1` | PASS |
| `.cmd` choice/errorlevel ordering, APPLY never offered, ASCII, PS parse | `test_b13::*` | PASS |
| Ctrl+C during apply | inline check (see I4) | RUN_END outcome `RUNNING` (I4) |
| Own reply draft becomes the "newest" thread message | `test_b08::test_own_draft_becomes_newest_message_of_thread` | I3 |

## 4. Findings

Order: Medium, then Low, then Info. Each finding gives repro, impact and fix. The PoC paths are relative to `/tmp/claude-0/redteam-b/`.

### M1 (Medium): Mutations that reached Gmail are recorded as terminal `FAILED` / `RECONCILED_DRIFT` and cannot be undone

**Repro**
- `test_b04_undo.py::test_applied_change_recorded_as_failed_is_not_undoable_retry_exhausted`: `AfterApply(503)` followed by three 503s on `messages.modify`.
- `::test_applied_change_recorded_as_failed_is_not_undoable_verify_read_error`: the verify `messages.get` fails 4×.
- `::test_transient_error_during_reconcile_finalises_pending_as_drift`: crash after modify, then a short 503 burst during the next run's reconcile.

**Observed**
- Gmail has `JARVIS/REFERENCE` on m1.
- The ledger has `FAILED` (RETRY_EXHAUSTED_SERVER / VERIFY_RETRY_EXHAUSTED_SERVER) or `RECONCILED_DRIFT/MESSAGE_UNAVAILABLE`, all terminal and not pending.
- `undo` returns `NOTHING` and the label stays.
- `VERIFY_MISMATCH` (an existing project test) is the same class: the write was applied, yet it is recorded FAILED.

**Impact**
- During exactly the conditions that occur when processing many messages (429/5xx storms), some applied labels become invisible to undo.
- `UNDO = DONE` is reported while mislabels remain.
- The idempotency key is not marked applied either.

**Fix**
1. In `_change_labels`, if the request may have been executed (any exception after the request was sent, retries exhausted, or verify read failed), do not write `FAILED`. Either write a non-terminal `OUTCOME_UNKNOWN`, or immediately re-read the state and record `RECONCILED_APPLIED` / `RECONCILED_NOT_APPLIED`.
2. Record `VERIFY_MISMATCH` as applied-with-drift (include it in `applied_actions`; undo's drift check protects it).
3. In `reconcile_pending`:
   - Only `API_NOT_FOUND` may finalise as `MESSAGE_UNAVAILABLE`.
   - On `TransientExhaustedError`, auth errors and the like, leave the row pending and abort the run (fail closed).
4. Add the three PoCs, inverted, as regression tests.

### M2 (Medium): Undo is not all-or-nothing

**Repro**
- `test_b04_undo.py::test_undo_is_not_all_or_nothing_when_a_restore_label_was_deleted`: m2's original state contains `JARVIS/PROJECT`; the user deletes that now-unused label; undo is run.
- `::test_undo_not_all_or_nothing_on_mid_loop_api_error`: a 403 on the 2nd modify.

**Observed**
- `FailClosed(LABEL_MISSING)` is raised after m1 was already reverted; m2 is still `JARVIS/ACTION`.
- Same outcome with the mid-loop 403.

**Impact**
- The mailbox is left half undone, contradicting the module docstring ("Any drift -> CONFLICT and the mailbox stays untouched (all-or-nothing)").
- The operator gets a single error code and no list of which messages were reverted.

**Fix**
1. In preflight, resolve every add/remove label for every message (`resolver.require`) and dry-run `authorize(..., origin="undo")` before the first mutation.
2. On a mid-loop failure, attempt compensation: re-apply `current` to the already-reverted messages. Otherwise report status `PARTIAL` with the exact list.
3. Make `undo` exit with a distinct code for PARTIAL.

### M3 (Medium): Stale-backup / rollback detection is bypassed by a missing head file or a whole-folder restore

**Repro**
- `test_b05_audit_storage.py::test_stale_db_restore_undetected_when_head_file_missing`
- `::test_whole_folder_restore_undetected_and_reapplies_human_overrides`

**Observed**
- `_check_head()` silently adopts the current DB head when `audit.head.json` is absent ("first open after upgrade").
- The head file lives in the same folder as the DB, so any folder backup restores both consistently.
- After a restore, the run:
  - re-applies `JARVIS/REFERENCE` that the human had removed,
  - re-creates a reply draft the human had discarded,
  - `last_undoable_run()` returns `None` (earlier runs can no longer be undone).

**Impact**
- The matrix item's invariant (detect and refuse a stale ledger) only holds for a DB-only restore.
- Loss of idempotency and undo history, and a re-mutation against human decisions.

**Fix**
1. Keep the rollback anchor outside the backed-up data folder: HKCU registry value or DPAPI-protected blob on Windows, or a second location.
2. Refuse to start when the DB has rows and the anchor is missing, unless an explicit `audit-rebaseline --confirm` command is run. That command verifies the chain and writes an audited `HEAD_REBASELINE` event.
3. Store a monotonic epoch / last run_id in the anchor.
4. Optionally cross-check on startup that messages carrying app labels have APPLIED records.

### M4 (Medium): A user-deleted app label blocks every future APPLY run

**Repro**
- `test_b03_idempotency.py::test_app_label_deleted_in_gmail_blocks_every_future_apply_run`

**Observed**
- The `LABEL_CREATE` idempotency key is `fingerprint(LABEL_CREATE, label_name)` and stays "applied" forever.
- After the label is deleted in Gmail, the re-create is `SKIPPED_IDEMPOTENT`, the first `LABEL_CHANGE` fails `LABEL_MISSING`, and the result is `FAILED_CLOSED`, on every run (3/3).

**Impact**
- Permanent outage of the apply path.
- Recovery requires the user to guess that they must recreate the label manually.

**Fix**
- For `LABEL_CREATE`, the mailbox is the source of truth: if `resolver.missing()` reports it, create it again (409 is already reconciled).
- Alternatively, include the last seen label id in the key.

### M5 (Medium): A single poison message stops the whole pipeline on every run

**Repro**
- `test_b03_idempotency.py::test_poison_message_blocks_all_later_actions_forever`: the newest message's modify always returns 400.

**Observed**
- 3/3 runs end `FAILED_CLOSED` at the same action.
- Older messages are never labelled; nothing is quarantined.

**Impact**
- The automation is stuck until the message ages out of the query window (default 30 days).
- Persistent `VERIFY_MISMATCH` behaves the same way, e.g. a Gmail filter or second client re-adding a label.

**Fix**
1. Split failures by scope.
   - Message-scoped: 400/404/409, VERIFY_MISMATCH, LABEL_MISSING for one message. Record FAILED, count consecutive failures per message key, quarantine after N (e.g. 3), and continue with the next action.
   - Global: auth/403 scope, audit, policy, retries exhausted for list/labels. Fail closed as today.
2. Have `status` list quarantined items; add `--retry-quarantined`.

### M6 (Medium): A manual relabel by the human is reverted once by the next run ("human decision wins" only for removals)

**Repro**
- `test_b03_idempotency.py::test_manual_relabel_is_overridden_by_next_run`

**Observed**
- Run 1 adds `JARVIS/REFERENCE`.
- The human moves the message to `JARVIS/DONE`.
- Run 2 plans `+REFERENCE -DONE`, which is a new idempotency key, and applies it: the message is back in REFERENCE.
- Only a second manual move sticks.
- This holds for every new manual app-label combination.

**Impact**
- Done or triaged mail reappears in its old state; the automation fights manual triage.
- Undo of the older run then mis-restores (see L7).

**Fix**
- Before planning, look up the last APPLIED after-state for the message in the ledger.
- If the current app labels differ from it and the content fingerprint is unchanged, treat it as a human override: write `SKIPPED_HUMAN_OVERRIDE` and do not mutate.
- Re-plan only when a new newest message arrives.

### M7 (Medium): The forbidden-method gate (G4-G6) is trivially bypassable; full CI stays green with a send path in `src/`

**Repro**
- `test_b09_static_gate.py::test_forbidden_scan_misses`. All 8 variants pass the gate:
  - `getattr(m, 'se'+'nd')`
  - a variable name passed to `getattr`
  - `''.join(['tr','ash'])`
  - `eval(...)`
  - `m.__getattr__('send')`
  - an own `build()` service
  - raw REST `AuthorizedSession(creds).post('.../messages/'+'send')`
  - a concatenated full-mail scope string
- `poc_ci_green_with_send.sh`: plants a typed, lint-clean `src/reminders.py` that POSTs to `users/me/messages/send`. ruff, ruff format, mypy, secret scan, forbidden scan, config check and pytest (208) are all green.
- CI and verify.ps1 scan `src/` only.

**Impact**
- The APPLY scope `gmail.modify` permits `messages.send` and `trash` at Google's side. The runtime guard and the policy only protect code paths that go through `GmailClient`.
- The static gate is the only control against a new path, and it gives weak assurance for "generated code".

**Fix**
1. AST allow-list:
   - Imports of `googleapiclient.discovery`, `google.auth.transport.*`, `requests`, `httplib2`, `urllib.request`, `http.client` only in `auth.py` / `gmail_client.py`.
   - Forbid `eval`/`exec`/`compile` and non-constant `getattr`/`__getattr__`/`attrgetter` outside the adapter.
   - Flag string constants containing `googleapis.com/gmail`.
2. Scan `src tools scripts` (whole repo) in CI.
3. Defence in depth: never hand the `Credentials` object outside the auth→client path, and build the service on an `AuthorizedHttp` subclass that checks method + path of every outgoing request against the endpoint allow-list. That also covers raw REST through the shared transport.
4. Add the 8 bypasses as planted fixtures to `test_misc_safety.py`.

### M8 (Medium): Audit storage error handling misdiagnoses locks as corruption and lets disk-full / read-only / lock errors escape as raw tracebacks

**Repro (all in `test_b05_audit_storage.py`)**
- `::test_locked_db_is_reported_as_corrupt`: another process holds `BEGIN EXCLUSIVE` (DB browser, backup tool, AV). `status` → `ABBRUCH (AUDIT_CORRUPT): Audit DB unreadable or corrupt (OperationalError)` after 5.1 s.
- `::test_external_lock_mid_run_escapes_as_raw_sqlite_exception`: a lock taken mid-run → raw `sqlite3.OperationalError: database is locked` out of `Engine.run()`. Reads such as `is_key_applied`, `pending` and `verify` are unwrapped.
- `::test_disk_full_on_insert_escapes_as_raw_exception`: SQLITE_FULL on INSERT. `_tx` re-raises the raw error, and its own `ROLLBACK` fails, so the user sees `cannot rollback - no transaction is active` and the real cause (`database or disk is full`) is hidden.
- `::test_unwritable_db_file_as_non_root`: a real read-only DB file → `sqlite3.OperationalError: attempt to write a readonly database` traceback, exit 1.
- `::test_unwritable_data_dir_crashes_cli_with_traceback`: data dir not writable → `PermissionError` from the lock file open escapes `main()` (exit 1).
- `::test_readonly_db_is_wrapped_but_mislabelled_locked`: when BEGIN fails, the code is `AUDIT_LOCKED` (wrong label).

**Impact**
- Mutations stay blocked (fail closed holds).
- But the operator is told the healthy ledger is **corrupt**, which invites deleting the audit DB and with it the idempotency and undo history.
- Other cases crash with tracebacks, no RUN_END and the generic exit code 1.

**Fix**
1. Wrap every SQLite call through one helper that maps `exc.sqlite_errorname` (Py ≥ 3.11):
   - BUSY/LOCKED → `AUDIT_LOCKED`
   - FULL → `AUDIT_FULL`
   - READONLY/CANTOPEN/PERM → `AUDIT_READONLY`
   - CORRUPT/NOTADB → `AUDIT_CORRUPT`
2. In `__init__`, only CORRUPT/NOTADB may become AUDIT_CORRUPT.
3. In `_tx`, guard `ROLLBACK` with `if self._db.in_transaction` and chain the original error.
4. Catch `OSError` in lock acquisition and data-dir creation → `LockError` / `AuditUnavailableError` with a clear message.

---

### L1 (Low): An interrupted first-time setup is never repaired by `START_GMAIL_AUTOMATION.cmd`

**Repro:** `poc_interrupted_bootstrap.sh`

**Observed**
- The `.cmd` treats "setup done" as `exist .venv\Scripts\python.exe`.
- With a venv created but no dependencies, menu [1] Doctor crashes with `ModuleNotFoundError: No module named 'yaml'` (as would every entry), and the bootstrap is never re-run.
- Re-running `bootstrap.ps1` reuses the pip-less venv:
  - `pip install --upgrade pip` is unchecked,
  - then it throws "Abhaengigkeiten konnten nicht installiert werden".
- The user must know to delete `.venv`.

**Fix**
- At the end of the bootstrap, write `.venv\.bootstrap-ok` containing the hash of `requirements-lock.txt`.
- The `.cmd` re-runs the bootstrap when the marker is missing or the hash differs.
- The bootstrap recreates the venv (`--clear`) when `python -m pip --version` fails.
- Check `$LASTEXITCODE` after the pip self-upgrade and the editable install.

### L2 (Low): No run-level deadline or page cap

**Repro**
- `test_b06_retry.py::test_429_huge_retry_after_has_no_run_level_budget`: 200 threads × 3 × 429 with `Retry-After: 86400` → 600 sleeps of 60 s = 10.0 h for one run.
- `::test_empty_pages_with_next_token_loop_forever`: >5,000 page requests.

**Impact**
- The run, and with it the instance lock, can block for hours or indefinitely.
- Scheduled runs are refused (LOCKED) meanwhile, and quota is burned.

**Fix**
- Run deadline (e.g. 15 min) plus a cumulative backoff budget → `RUN_BUDGET_EXCEEDED`.
- Cap pages at `ceil(limit/page_size)+2`.
- Stop on a repeated token or on empty pages that still carry a token.

### L3 (Low): Tail starvation and full re-fetch above `max_messages_per_run`

**Repro:** `test_b08_scale.py::test_50k_candidates_bounded_but_tail_is_never_processed`

**Observed**
- 1,500 matching messages, cap 1,000: 500 messages are never classified across 3 runs.
- Each run makes 2,011 API calls, re-fetching already processed threads.

**Impact**
- With default `in:inbox newer_than:30d`, a busy inbox (more than 1,000 messages in 30 days) never gets its older mail classified.
- Quota waste (threads.get + full messages.get every run).

**Fix**
- Skip threads whose `historyId` is unchanged since the last CLASSIFIED row (ledger).
- Or use an incremental cursor (history-based sync).
- Or exclude already-processed mail in the query, or page through the window oldest-first with a stored checkpoint.

### L4 (Low): A 429 on `drafts.create` / `labels.create` aborts the whole run

**Repro:** `test_b06_retry.py::test_429_on_draft_create_aborts_whole_run` → `FAILED_CLOSED AMBIGUOUS_RATE_LIMIT`; later work is skipped.

**Fix**
- Treat 429 and 403 `rateLimitExceeded` as definitely not applied: back off and retry even for non-idempotent creates.
- Keep the ambiguous treatment for 5xx and network errors.

### L5 (Low): Common transient network errors are not retried

**Repro**
- `test_b06_retry.py::test_network_error_classification`: `ssl.SSLEOFError`, `socket.gaierror`, `OSError(ENETUNREACH)` and `http.client.IncompleteRead` classify as UNKNOWN.
- `::test_ssl_eof_mid_pagination_aborts_run_without_retry`

**Fix**
- Classify `ssl.SSLError`, `socket.gaierror`, `OSError` with errno ∈ {ENETUNREACH, EHOSTUNREACH, ECONNABORTED, ETIMEDOUT}, and `http.client.HTTPException` subclasses as NETWORK.
- Non-idempotent writes remain ambiguous and go through reconcile.

### L6 (Low): Undo needs the `labels` capability, so the kill switch blocks recovery

**Repro:** `test_b04_undo.py::test_undo_refused_when_labels_capability_switched_off` → `CAPABILITY_GATE`.

**Impact:** the natural incident response, "switch capabilities off, then undo the bad run", fails.

**Fix**
- Allow `origin="undo"` restores of audited changes with `--apply` + APPLY profile regardless of the capability flag.
- Or at least print an explicit hint.

### L7 (Low): Undoing an older run silently wipes a later run's change when the states coincide

**Repro:** `test_b04_undo.py::test_undo_older_run_silently_reverts_later_runs_change_on_coincident_state`

**Observed**
1. Run 1 moves m1 from {} to {REF}.
2. The human moves it to {DONE}.
3. Run 2 moves it from {DONE} to {REF}.
4. Undo of run 1 succeeds (DONE) and leaves {}.
5. Undo of run 2 is CONFLICT: the human's {DONE} cannot be restored.

**Fix:** in undo preflight, if the ledger shows a later, not-undone APPLIED action on the same message from another run, refuse with `CONFLICT/LATER_RUN` (or require undoing newest-first).

### L8 (Low): Head-file write is unguarded and uses a shared temp name

**Repro**
- `poc_head_tmp_race.py`: two writers, `FileNotFoundError` in ~47 % of writes.
- `test_b05_audit_storage.py::test_windows_style_replace_permission_error_after_commit`: simulated Windows `PermissionError` from `os.replace` while the file is open (AV scanner, or `status`, which takes no lock).

**Observed**
- An `OSError` escapes `append()` **after** the row committed; the run crashes with a traceback and leaves a pending action.
- Real-world trigger: `status`/`doctor` adopting a missing head concurrently with a run, or Windows Defender / an indexer holding `audit.head.json`.

**Fix**
- Unique temp name in the same dir (`tempfile.mkstemp`).
- Retry `os.replace` on `PermissionError` with backoff (Windows).
- Map remaining errors to `AuditUnavailableError(AUDIT_HEAD_WRITE)`.

### L9 (Low): A 0-byte or corrupt head file blocks every command, with no repair path

**Repro:** `test_b05_audit_storage.py::test_zero_length_head_file_blocks_every_command_without_repair_path` → `AUDIT_HEAD_CORRUPT` from status/scan/run/undo/doctor.

**Observed**
- The head is written without `fsync`, so a power loss can produce exactly this.
- The only "fix" is manually deleting the file, which also silently disables rollback detection (M3).

**Fix**
- `fsync` the temp file and the directory.
- Add an audited `audit-rebaseline --confirm` command.

### L10 (Low): With more than 500 drafts, reconcile misses the auto-draft and creates a duplicate

**Repro:** `test_b08_scale.py::test_more_than_500_drafts_reconcile_misses_draft_and_duplicates_it` → `RECONCILED_NOT_APPLIED`, 2 drafts in the thread.

**Observed:** `drafts_in_thread` / `find_draft_with_key` read only the first `drafts.list` page (maxResults=500, no pageToken loop).

**Caveat:** depends on Gmail's draft ordering; the fake lists oldest first.

**Fix:** paginate.

### L11 (Low): Duplicate YAML keys override silently

**Repro:** `test_b07_config.py::test_partially_merged_config_with_duplicate_keys_last_one_wins_silently`: an appended `capabilities:` block flips labels and drafts on. Also applies within rules.

**Impact**
- A partially merged config behaves differently from what the operator reads at the top of the file.
- APPLY still needs `--apply`.

**Fix:** a SafeLoader subclass that raises on duplicate mapping keys (→ `CONFIG_MALFORMED`).

### L12 (Low): CI and dependency gaps

**Repro:** `test_b13_windows_ci_static.py::test_ci_matrix_and_pinning_gaps`, the lock dry-run, `test_b10_real_client.py`.

**Gaps**
- CI is Python 3.12 only, although `bootstrap.ps1` prefers 3.13 (and picked 3.13 here). 3.13 works today, but untested.
- Dev tools are unpinned (`ruff>=0.6`, `mypy>=1.10`, `pytest>=8`). Drift is already observable (`ast_serialize` 0.12.0 → 0.12.1); a new ruff/mypy release can flip gates without a code change.
- No `--require-hashes`.
- Actions are pinned by tag, not SHA.
- `bootstrap.ps1`, `verify.ps1` and the `.cmd` are never executed in CI; there is no Windows PowerShell 5.1 job.
- No `pip check`.
- No contract test against the real googleapiclient.

**Fix**
- Matrix `["3.12", "3.13"]`.
- `requirements-dev-lock.txt` with hashes, `--require-hashes`.
- SHA-pinned actions.
- A Windows job running `powershell -NoProfile -File scripts/verify.ps1` (5.1) and pwsh.
- `pip check`.
- Adopt `test_b10_real_client.py`.

### L13 (Low): The distributed copy ships an LF-only `.cmd`

**Repro:** `test_b13_windows_ci_static.py::test_line_endings_workspace_vs_distributed_copy`. The workspace is CRLF, but `/tmp/claude-0/fresh install ü/GMAIL-AUTOMATION/START_GMAIL_AUTOMATION.cmd` (and the .ps1 files) are LF; git stores them LF and converts only on checkout.

**Impact**
- cmd.exe label lookup (`goto :menu`) is known to be unreliable with LF-only batch files.
- Untestable here, so marked residual.

**Fix**
- Build release ZIPs with `git archive` (applies `eol=crlf`).
- Add a test that the shipped `.cmd` contains CRLF.

### L14 (Low): The ledger grows without bound, and every run pays O(n)

**Repro:** `test_b08_scale.py::test_ledger_growth_costs`: 200,000 rows (81 MB) → `verify()` 3.0 s plus `pending()` 2.2 s per run (one query per PREPARE ever written).

**Projection**
- Hourly 1,000-message scans write ~1,000 rows per run, about 8.8 M rows/year: ~3.5 GB and ~2 min of verify per run.
- `append()` is ~1.1 ms here (fsync per row); expect several ms on NTFS.

**Fix**
- Incremental verify from a checkpoint stored with the anchor; full verify only in `audit-verify`.
- Pending via a `NOT EXISTS` query or a terminal index.
- Yearly ledger rotation with a chained anchor.
- Optionally do not write CLASSIFIED rows for unchanged threads.

### L15 (Low): Drafts edited or discarded in the crash window are mistracked

**Repro**
- `test_b12_races_drafts.py::test_draft_edited_by_user_before_reconcile_no_duplicate_but_untracked`: the web-UI edit drops `X-Gmail-Automation-Key` → `RECONCILED_NOT_APPLIED`; `undo` does not list the draft for manual review.
- `::test_draft_discarded_by_user_in_crash_window_is_recreated`

**Fix**
- Record candidate draft ids (thread + creation window) at reconcile time as `RECONCILED_UNCERTAIN` and list them in undo.
- Do not auto-recreate within N hours of an unresolved PREPARE for the same (thread, template).

---

### Info

- **I1:** On POSIX, `flock` is bound to the inode. Deleting the lock file while it is held lets a second instance acquire a new one (`test_b02::test_deleted_lock_file_allows_second_instance_posix`). Windows (`msvcrt`, file in use) is not affected.
- **I2:** The freshness check has a TOCTOU window. A reply arriving between the freshness check and `messages.modify` is not detected (verify checks only the target's labels). `ThreadSnapshot.history_id` is captured but never compared (`test_b12::test_reply_arriving_*`, `::test_label_change_on_other_message_*`). Fix: re-check the thread after the write, and compare historyId.
- **I3 (assumption):** Gmail's `threads.get` includes draft messages. The scanner then picks the operator's own reply draft as the "newest" message and classifies the template text (`test_b08::test_own_draft_becomes_newest_message_of_thread`). Fix: ignore messages with the `DRAFT` label when choosing the newest.
- **I4:** Ctrl+C during apply writes `RUN_END` with outcome `RUNNING` (inline check: pending=1, outcome RUNNING); `status` shows RUNNING instead of "aborted". Fix: catch `KeyboardInterrupt` in `run()` and set the status to `ABORTED` before `_finish`.
- **I5:** `undo --last-run` always selects the newest run with an un-undone change. Once that run is in CONFLICT (normal after manual triage), older runs are reachable only via `--run-id` (`test_b04::test_last_run_selector_stuck_on_conflicting_newest_run`).
- **I6:** 403 `dailyLimitExceeded` is reported as "Gmail denied ... - fail closed" with code AUTH_403, which reads as a scope problem. A `Retry-After` given as an HTTP date is ignored (`test_b06`).
- **I7:** run_id is the UTC second plus 24 random bits. Two runs started in the same second collide with probability 2⁻²⁴, which would merge them for undo (synthetic burst: 16 collisions in 20,000 same-second ids, `test_b11`). Use 64+ random bits.
- **I8:** A `schema_version` table without a `ledger` table (manual surgery) raises a raw `sqlite3.OperationalError` instead of `AuditIntegrityError` (`test_b05::test_schema_version_without_ledger_table_raises_raw`).
- **I9:** Windows MAX_PATH budget. The longest venv file is ~123 chars relative to the project root (`.venv\Lib\site-packages\oauthlib\...\resource_owner_password_credentials.cpython-313.pyc`). Without `LongPathsEnabled`, the project root must stay under ~136 chars. A typical OneDrive-for-Business Documents path is ~100 chars.
- **I10:** `cd /d "%~dp0"` does not work for UNC paths (`\\server\share`). Use `pushd "%~dp0"` / `popd`.
- **I11:** In production, `google-auth-httplib2` (`AuthorizedHttp`) also refreshes on 401 by itself (bounded). "Exactly one refresh" holds only for the explicit refresh in `_execute` (analysis, not PoC'd).
- **I12:** `limits.max_thread_messages` / `ThreadSnapshot.truncated` has no effect; the flag is computed and never consumed.

## 5. Notes for the fix/regression cycle

- Every PoC is a self-contained pytest that uses only the project's own fakes. To turn one into a regression test, copy it into `tests/` and invert the assertion marked as the finding.
- The crash harness (`crashlib.py`, `crash_run.py`) is worth adopting as-is. It is the only test that proves durability against a real process kill, not just `KeyboardInterrupt` (which still runs `finally` and writes RUN_END).
- `test_b10_real_client.py` (offline `RoutingHttp` over the real discovery service) is the recommended contract test for dependency bumps.


---

## Fix-Status nach dem Release-Zyklus (Stand 2026-10-03)

Alle Medium-Findings sind behoben. Die Lows sind behoben oder als Restrisiko dokumentiert. Kein Finding war Critical oder High.

| Finding | Schwere | Status | Umsetzung | Regressionstest |
|---|---|---|---|---|
| M1 | Medium | **behoben** | Ein Write mit unbekanntem Ausgang wird sofort neu gelesen und festgehalten (`RECONCILED_*`), oder er bleibt offen für den Abgleich, nie als finales FAILED. `VERIFY_MISMATCH` wird `APPLIED_DRIFT` (undo-fähig). Der Abgleich schließt nur bei 404 ab. Jeder Fehler nach einem 5xx-Versuch gilt als mehrdeutig (C-L1). | `test_B_M1_*`, `test_C_L1_*`, `test_verify_mismatch_is_applied_with_drift_and_undoable` |
| M2 | Medium | **behoben** | Preflight prüft vor der ersten Änderung alle Labels und autorisiert jede Wiederherstellung. Fehler mitten im Lauf werden kompensiert (`ROLLED_BACK`, Exit 8) oder als `PARTIAL` mit Nachrichtenliste gemeldet (Exit 9). | `test_B_M2_*` |
| M3 | Medium | **behoben** / Rest | Rollback-Anker außerhalb des Datenordners. Ledger mit Einträgen ohne Anker wird verweigert. Neu-Verankerung nur explizit und protokolliert (`audit-rebaseline`, mit Befund und eigenen Flags). Rest: Die Wiederherstellung des gesamten Benutzerprofils bleibt unerkannt (R-2). | `test_B_M3_*`, `test_C_L6_*` |
| M4 | Medium | **behoben** | Labels: Maßstab ist das Postfach, ein gelöschtes App-Label wird neu angelegt | `test_B_M4_*` |
| M5 | Medium | **behoben** | 400/404/409 betreffen nur die Nachricht: FAILED und weiter, nach 3 Fehlern Quarantäne. Auch dauerhafte 5xx zählen (C-L2). Quarantäne meldet `PARTIAL`, Exit 9 (C-L3). | `test_poison_message_*`, `test_message_scoped_failure_*`, `test_C_L2_*` |
| M6 | Medium | **behoben** | `SKIPPED_HUMAN_OVERRIDE`, wenn die App-Labels nicht mehr dem letzten Stand des Programms entsprechen; auch bei App-Labels beim Erstkontakt (C-L4) | `test_manual_*`, `test_app_label_set_by_a_person_before_first_run_is_kept` |
| M7 | Medium | **behoben** | Statischer Gate-Scan über src/ und tools/; Reflection, Transport-Importe, Re-Importe und Aliasing werden erkannt; Ausnahmen an exakte Pfade gebunden. Dazu Transport-Allow-List (`GuardedHttp`) mit Body-Prüfung und Refresh-Transport nur zum Token-Endpunkt. | `test_forbidden_scan_catches_planted_code[*]`, `test_C_M1_*` |
| M8 | Medium | **behoben** | SQLite-Fehler → `AUDIT_LOCKED`/`FULL`/`READONLY`/`CORRUPT`/`IO`; ROLLBACK abgesichert; Schema-Prüfung; OSError bei Lock/Datenordner gekapselt | `test_B_M8_*`, `test_B_I8_*` |
| L1 | Low | **behoben** | Bootstrap-Marker mit Lock-Hashes; defektes venv wird neu gebaut; jeder pip-Exit-Code geprüft | CI-Job `windows-scripts` |
| L2 | Low | **behoben** / Rest | Backoff-Budget pro Lauf, Laufzeit-Deadline, begrenzte Paginierung. Rest: Die Deadline greift zwischen API-Aufrufen; eine hängende Regex wird durch den ReDoS-Lint verhindert. | `test_B_L2_*` |
| L3 | Low | Restrisiko | Mehr als `max_messages_per_run` Treffer: Der älteste Rest wird nicht verarbeitet (R-4) | – |
| L4 | Low | **behoben** | 429 bei Creates wird wiederholt (abgelehnt = nicht ausgeführt) | `test_B_L4_*` |
| L5 | Low | **behoben** | TLS/DNS/OSError/HTTPException gelten als vorübergehend | `test_B_L5_*` |
| L6 | Low | **behoben** | Undo braucht APPLY und `--apply`, aber kein Capability-Flag | `test_B_L6_*` |
| L7 | Low | **behoben** | `LATER_RUN`-Konflikt; Undo der Reihe nach vom neuesten Lauf; No-op-Einträge werden als UNDONE markiert (C-L5) | `test_B_L7_*`, `test_C_L5_*` |
| L8 | Low | **behoben** | Eindeutige Temp-Datei, fsync, Wiederholung bei Windows-Sharing-Violation, Fehler → `AUDIT_HEAD_WRITE` | `test_B_L8_*` |
| L9 | Low | **behoben** | fsync, Reparatur über `audit-rebaseline` | `test_B_L9_*` |
| L10 | Low | **behoben** | Entwürfe paginiert (begrenzt) | `test_B_L10_*` |
| L11 | Low | **behoben** | Doppelte YAML-Schlüssel → `CONFIG_MALFORMED` | `test_B_L11_*` |
| L12 | Low | teilweise / Rest | CI-Matrix 3.12+3.13, exakt gepinnte Prüfwerkzeuge, `pip check`, Windows-Job mit PS 5.1 und 7. Rest: Actions per Tag statt SHA gepinnt, keine Hash-Locks (R-8). | `test_ci_workflow_covers_required_gates` |
| L13 | Low | **behoben** | Release-ZIP per `git archive` (CRLF), CRLF-Test, CI-Prüfung | `test_B_L13_*` |
| L14 | Low | teilweise / Rest | Offene Aktionen per `NOT EXISTS` und Index. Rest: Die vollständige Kettenprüfung kostet pro Lauf O(n) (R-5). | – |
| L15 | Low | Restrisiko | Entwürfe, die im Absturzfenster bearbeitet oder verworfen werden (R-9) | – |
| I1 | Info | Restrisiko | POSIX: Wird die Lock-Datei gelöscht, ist eine zweite Instanz möglich; Windows ist nicht betroffen | – |
| I2 | Info | Restrisiko | Kurzes Zeitfenster zwischen Frische-Prüfung und Write; die Folge ist undo-fähig (R-3) | – |
| I3 | Info | **behoben** | Entwurfs-Nachrichten sind nie die neueste Nachricht | `test_B_I3_*` |
| I4 | Info | **behoben** | Strg+C → RUN_END `ABORTED` | `test_B_M1_I4_*` |
| I5 | Info | teilweise | `LATER_RUN` sagt, welcher Lauf zuerst dran ist; `--run-id` ist verfügbar | – |
| I6 | Info | **behoben** | Tageskontingent → `API_QUOTA_DAILY`; Retry-After als HTTP-Datum | `test_B_I6_*` |
| I7 | Info | **behoben** | run_id mit 64 Zufallsbits | `test_B_I7_*` |
| I8 | Info | **behoben** | `AUDIT_SCHEMA_INVALID` | `test_B_I8_*` |
| I9 | Info | dokumentiert | Kurzen Projektpfad wählen (README) | – |
| I10 | Info | **behoben** | `pushd`/`popd` für UNC-Pfade | `test_B_I10_*` |
| I11 | Info | **behoben** | Transport-401-Auto-Refresh deaktiviert; genau ein expliziter Refresh | `test_401_refreshes_exactly_once_no_loop` |
| I12 | Info | unverändert | `max_thread_messages` markiert nur `truncated` (informativ) | – |
