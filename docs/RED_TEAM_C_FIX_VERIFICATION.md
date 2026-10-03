# Red Team C: Fix Verification, GMAIL-AUTOMATION 1.0.0rc1

> **Hinweis (Release-Zyklus 1.0.0rc1):** Dies ist der unveränderte Originalbericht des Red-Team-Durchgangs. Die genannten `/tmp/claude-0/...`-Pfade beziehen sich auf den damaligen Prüf-Arbeitsbereich. Alle Proofs of Concept wurden umgekehrt als Regressionstests übernommen: `tests/test_red_team_regressions.py`. Der Fix-Status steht am Ende des Berichts.

**Date:** 2026-10-03 · **Target:** `/home/claude/GMAIL-AUTOMATION` at `1cdce5d` (read-only, offline, no Gmail account) · **Scope:** the 9 Medium findings from Red Team A/B (A-F1, B-M1..M8), plus new defects introduced by the fix commits `9fb9cee..1cdce5d`

## 1. Result

| Severity | Count |
|---|---:|
| Critical | 0 |
| High | 0 |
| Medium | 1 |
| Low | 9 |
| Info | 4 |

**Release rule (any Critical or High blocks): no blocker.** No path was found through the shipped code that:
- sends, deletes, trashes or changes system labels,
- reaches APPLY without `--apply` plus the APPLY profile,
- lets undo or compensation touch non-app labels.

Undo and quarantine also never continue after a global error.

**Original Medium findings not fully fixed:** B-M1 (partly), B-M5 (partly), B-M6 (partly), B-M7 (partly).

**Fully fixed:** A-F1, B-M2, B-M3, B-M4, B-M8.

## 2. Method and how to rerun

- **PoC suite:** `/tmp/claude-0/redteam-c/test_c0{1..5}_*.py`. It has 78 tests: 77 pass, and 1 is skipped (root can read a mode-000 file).
  - `*_FIXED` tests assert the secure behaviour. They are regressions and variants of the original PoCs.
  - `*_RESIDUAL` tests assert the **observed** weak behaviour, so they pass while the weakness exists. Invert the marked assertion once it is fixed.
- **Rerun:**
  ```
  cd /home/claude/GMAIL-AUTOMATION && PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. .venv/bin/python -m pytest \
     /tmp/claude-0/redteam-c/ -c /tmp/claude-0/redteam-c/pytest.ini --rootdir=/tmp/claude-0/redteam-c -q
  ```
- **Isolation:** the project's fakes and fixtures are used throughout (`tests/fakes.py`, `tests/conftest.py`). `GMAIL_AUTOMATION_HOME` and `GMAIL_AUTOMATION_ANCHOR_DIR` always point to pytest temp dirs. There was no network access.
- **Project not modified:** `git status` is clean before and after.
- **Project gates, re-run (all green):**

| Gate | Result |
|---|---|
| pytest | 321 passed |
| `forbidden_scan.py` | PASS (22 files) |
| `secret_scan.py` | PASS |
| `ruff check src tests tools` | clean |
| `mypy` | no issues (20 files) |

- **Static gate scope of this pass:** the static-gate and transport assessment uses code review and import-only fixtures fed to the project's own `Scanner` class. No end-to-end bypass code (sending, raw REST) was written.

## 3. Original findings → verified fixed?

| Finding | Verified fixed? | Evidence (PoC test) |
|---|---|---|
| **A-F1** Unicode line separator crashes APPLY | **yes** | `test_c04::test_F1_every_line_boundary_in_subject_and_msgid_is_safe_FIXED`: 10 separators (U+2028/2029, NEL, VT, FF, FS/GS/RS, CRLF, CR) in Subject **and** Message-ID, each with an injected `Bcc:`. Result: no crash, no Bcc/Cc header. The project's own catch-all `DRAFT_HEADER_INVALID` and `InternalError` paths were also confirmed. |
| **B-M1** Applied write recorded as terminal FAILED | **partly** | Fixed: lost response then 429/5xx retries exhausted gives RECONCILED_APPLIED and is undoable (`test_c01::test_M1_original_variants_FIXED`). Reconcile on 403/400 keeps the row pending (`test_M1_reconcile_auth_error_keeps_row_pending_FIXED`). Draft reconcile lookup failure stays pending (`test_M1_draft_reconcile_lookup_failure_stays_pending_FIXED`). **Residual:** a non-transient error on a *retry* attempt after a possibly-applied 5xx still writes terminal FAILED. See C-L1. |
| **B-M2** Undo not all-or-nothing | **yes** | `test_c02::test_M2_compensation_never_touches_system_or_foreign_labels_FIXED`: ROLLED_BACK leaves STARRED/IMPORTANT/user labels byte-identical. `test_M2_mid_loop_lost_response_counts_as_reverted_FIXED`. `test_M2_preflight_conflict_on_one_message_leaves_all_untouched_FIXED`. `test_M2_forged_first_action_with_system_label_is_conflict_FIXED`: a forged ledger row with `before_state = TRASH` gives CONFLICT/LABEL_NOT_APPROVED and 0 mutations. |
| **B-M3** Stale backup / missing head undetected | **yes** (Low residual in rebaseline UX, C-L6) | `test_c03::test_M3_anchor_dir_switched_by_env_is_refused_FIXED`, `test_M3_stale_db_copied_to_new_data_dir_is_refused_FIXED`, `test_M3_deleted_db_with_anchor_present_is_rollback_FIXED`, `test_M3_rebaseline_refuses_broken_chain_FIXED`, `test_M3_anchor_is_private_and_outside_data_dir_FIXED` (0700, outside the data dir). |
| **B-M4** User-deleted app label blocks APPLY forever | **yes** | `test_c01::test_M4_label_deleted_twice_and_renamed_FIXED`: the label is renamed out of the namespace twice and re-created each time. |
| **B-M5** Poison message blocks pipeline | **partly** | Fixed for 4xx: isolated, then quarantined after 3 (`test_c01::test_M5_poison_400_is_isolated_and_quarantined_FIXED`). A global error after a message-scoped error still stops the run (`test_M5_global_error_after_message_failure_still_stops_FIXED`). **Residual:** a persistent per-message 5xx (C-L2), and quarantine reporting exit 0 (C-L3). |
| **B-M6** Human relabel reverted | **partly** | Relabel and removal are respected; there is no re-mutation after undo (`test_c01::test_M6_relabel_and_removal_are_respected_FIXED`, `test_M6_override_after_undo_and_after_rolled_back_undo_FIXED`). **Residual:** first contact (C-L4). |
| **B-M7** Static gate bypassable, CI green with a send path | **partly** | The new GuardedHttp blocks send/trash/delete via the real googleapiclient service (project test plus code review). The direct-import and reflection cases are now flagged (`test_c05::test_M7_direct_transport_imports_are_flagged_FIXED`). **Residual:** indirect transport access is not flagged (C-M1). |
| **B-M8** SQLite errors misdiagnosed / raw tracebacks | **yes** | `test_c03::test_M8_lock_between_prepare_and_applied_is_mapped_and_reconciled_FIXED`: an external lock taken right before modify gives AUDIT_LOCKED, the row stays pending, and the next run reconciles it. `test_M8_rebaseline_cli_on_locked_db_maps_error_FIXED` gives exit 5 and AUDIT_LOCKED. |

Selected Low/Info originals also checked:

| Finding | Verdict | Evidence |
|---|---|---|
| A-I8 | fixed | `test_c05::test_I8_*`: 6 argv variants all exit 2 |
| A-F3 | fixed | `test_c01::test_F3_non_domain_error_after_mutation_leaves_row_pending_FIXED`, `test_c05::test_F3_partial_exit_code_FIXED` |
| A-F7 | fixed | — |
| B-L6 | fixed | Capability bypass is limited to `origin="undo"`, label add/remove, app labels, APPLY plus flag (`test_c02::test_L6_*`) |
| B-L11 | fixed | Also with anchors/aliases |
| A-F4 | partly | C-L9 |
| A-F6 | partly | C-L8 |
| B-L7 | partly | New deadlock, C-L5 |
| A-I1 | fixed | But the fix introduced C-L7 |

## 4. Findings (new or residual)

### C-M1 (Medium): Static gate still misses indirect transport access; transport guard is endpoint-level only (B-M7 residual)

**Repro**
- `test_c05::test_M7_indirect_transport_access_is_not_flagged_RESIDUAL`, 6 import-only fixtures. All give 0 findings:
  - `from .gmail_client import httplib2`
  - `from .retry import http, socket, ssl`
  - `from src.gmail_client import httplib2`
  - `from .auth import _default_request`
  - `sys.modules`
  - `importlib.util.find_spec`
- Code review, `tools/forbidden_scan.py`:
  - `visit_ImportFrom` checks only `node.level == 0`.
  - It checks the import **path**, never the imported **name**. A transport module re-exported by `gmail_client.py`/`retry.py`, or the unguarded `requests`-based factory `auth._default_request()` (used for token refresh), reaches any `src/` module without a finding.
- Code review, `src/gmail_client.py::check_transport`:
  - It allows `POST …/messages/{id}/modify` with **any body**.
  - The system-label refusal (TRASH/SPAM/INBOX) exists only in `GmailClient._check_label_ref`.
  - Code that reaches the guarded resource or the raw service (e.g. via `client._root`, or `build_gmail_service`) is limited only to the endpoint, not to the label ids.

**Observed:** The original B-M7 statement ("a lint-clean src/ module with a forbidden path keeps every CI gate green") is still achievable through these gaps. The runtime GuardedHttp only covers traffic that uses the googleapiclient service; the explicit refresh transport is unguarded.

**Impact:** No reachable path in the current code. The risk is generated or new code in `src/` (the threat B-M7 described), which the static gate is meant to stop.

**Fix**
1. In the scanner:
   - Check `ImportFrom` with `level > 0` and `src.*` imports by the imported **names**. Deny module objects and the names `httplib2`, `socket`, `ssl`, `http`, `_default_request`, `build_gmail_service`, `load_credentials`, `GuardedHttp`, `_root` outside an explicit allow-list (`cli.py`, `auth.py`, `gmail_client.py`).
   - Flag `sys.modules`, `importlib.util`, `runpy`, `pkgutil`, `inspect.getattr_static`/`getmembers`, and `getattr` used as a value (not in call position).
2. Wrap the refresh transport so it can only reach `oauth2.googleapis.com/token`. Example: a `requests.Session` with a guarded adapter, or route refresh through `GuardedHttp` via `google_auth_httplib2.Request`.
3. In `GuardedHttp`, parse the JSON body of `messages.modify` and `drafts.create` and refuse non-`Label_\d+` ids and system labels. That gives a body-level second barrier.

### C-L1 (Low): An error on a retry attempt after a possibly-applied 5xx is recorded as terminal FAILED (B-M1 residual)

**Repro**
- `test_c01::test_M1_deadline_crossed_during_retry_after_applied_5xx_RESIDUAL`: `AfterApply(503)`, then the backoff sleep crosses the 30-min run deadline. Result: `FAILED/RUN_DEADLINE`.
- `test_c01::test_M1_auth_failure_on_retry_after_applied_5xx_RESIDUAL`: `AfterApply(503)`, then 401, then the refresh fails. Result: `FAILED/AUTH_REFRESH_FAILED`.

**Observed**
- Gmail has `JARVIS/REFERENCE`.
- The ledger has a terminal FAILED, nothing pending and no RECONCILED_*.
- `undo` returns NOTHING and the label stays.

**Cause:** `_change_labels` treats every `GmailAutomationError` except `TransientExhaustedError`/`AmbiguousWriteError` as "definitely not applied". Neither `RunBudgetExceeded` (a `FailClosed`), nor `AuthError`, nor `API_*` raised on attempt ≥ 2 is in `_UNKNOWN_OUTCOME`.

**Impact:** As in B-M1, an applied label is invisible to undo. The trigger is narrower: a 5xx storm plus a deadline crossing or a refresh failure.

**Fix**
- `messages.modify` is a set operation, so on **any** exception from it, re-read the message and settle it (`_settle_observed`). Alternatively, have `GmailClient._execute` raise `AmbiguousWriteError` for any failure that follows an earlier transient attempt on a mutating call.

### C-L2 (Low): A message that always gets 5xx still blocks every run and is never quarantined (B-M5 residual)

**Repro:** `test_c01::test_M5_persistent_5xx_on_one_message_blocks_every_run_RESIDUAL` (500 backendError on m1 each time, 4 runs).

**Observed:** Every run ends FAILED_CLOSED at m1. m2 is never labelled. There are no SKIPPED_QUARANTINED rows.

**Fix:** Count settled `RECONCILED_NOT_APPLIED` outcomes with 5xx codes per message toward `failure_streak`. Quarantine after N such outcomes. Keep the run-stop for the current run.

### C-L3 (Low): Quarantine turns persistent failures into STATUS=OK / exit 0

**Repro:** `test_c01::test_M5_quarantine_turns_a_persistent_failure_into_exit_OK_RESIDUAL`. Both messages failed 3×; run 4 reports `quarantined=2`, `status=OK`, `error=None`.

**Impact:** A scheduler or monitor that watches exit codes turns green while the whole window is excluded. That includes a global 4xx cause such as a deleted label id or an account precondition, which is classed as message-scoped.

**Fix**
- Status `PARTIAL` (exit 9), or a dedicated exit code, while `quarantined > 0`.
- If every planned message ends quarantined or failed in one run, treat that as a global failure.

### C-L4 (Low): A human's app label on a not-yet-processed message is overwritten (B-M6 residual)

**Repro:** `test_c01::test_M6_human_label_on_not_yet_processed_message_is_overwritten_RESIDUAL`. The user puts `JARVIS/DONE` on a new message before the first run.

**Observed:** `human_override=0`. The run removes DONE and adds REFERENCE.

**Cause:** `_human_override` returns False when `last_set_labels` is None.

**Fix:** On first contact (`last is None`), treat non-empty current app labels as a human decision: skip, or add-only and never remove.

### C-L5 (Low): A no-op undo item is never marked UNDONE, so undo of older runs deadlocks with LATER_RUN (new, introduced by the B-L7 fix)

**Repro:** `test_c02::test_L7_noop_drift_action_deadlocks_undo_of_older_run_RESIDUAL`
1. Run A: {} → REFERENCE.
2. Run B plans REFERENCE → PROJECT. A second client puts REFERENCE back before the verify read, so B is audited `APPLIED_DRIFT` with `after_state == before_state`.

**Observed**
- `undo B` returns `DONE`, `reverted=0`. The item has no add/remove and is skipped without UNDONE rows.
- `last_undoable_run()` still returns B.
- `undo A` returns `CONFLICT/LATER_RUN`, permanently. Run A's label can never be undone, and `undo --last-run` stays stuck on B.

**Fix:** In `undo_run`, when an item needs no change, still write `UNDONE` rows (`_mark_undone(audit, i, i.original)`).

### C-L6 (Low): `audit-rebaseline` blesses a rollback or rewritten ledger with the same `--confirm`, and the preview shows no diagnosis

**Repro:** `test_c03::test_M3_rebaseline_preview_hides_rollback_and_rewrite_diagnosis_RESIDUAL`.
1. Rows are dropped and the chain is re-hashed (no secret is needed), which gives `AUDIT_HEAD_MISMATCH`.
2. The preview prints only `HASH-KETTE = PASS` and the generic warning.
3. `--confirm` succeeds and `status` turns green.
4. The applied change is now invisible to undo (`last_undoable_run() is None`).

**Impact:** The rollback anchor is the only integrity barrier (the chain has no key). The repair path does not tell the operator that the anchor saw a **rollback of N rows** or a **history rewrite**, as opposed to a merely missing or corrupt anchor.

**Fix**
- Show the anchor verdict in the preview: missing, corrupt, rollback with anchor seq vs. DB seq, or mismatch at seq X.
- Require a distinct flag (e.g. `--accept-rollback` / `--accept-rewrite`) for those cases.
- Record the verdict in `HEAD_REBASELINE.detail`.

### C-L7 (Low): The hidden-HTML heuristic (A-I1 fix) drops visible text, which bypasses the money guard and force_review rules (new)

**Repro:** `test_c04::test_I1_hidden_text_heuristic_drops_visible_text_RESIDUAL[implicit-p-close|visibility-override|font-size-override]`. Three markup patterns:
- `<p style=display:none><div>…`: a browser closes `<p>` implicitly, so the div is visible.
- A `visibility:hidden` parent with a `visibility:visible` child.
- A `font-size:0` parent with a `font-size:14px` child.

**Observed:** The visible payment wording is dropped from the text, and the message becomes ACTION/AUTO with an ack draft.

**Impact:** The same class as A-F6: a label plus a static draft to the From address. No send.

**Fix**
- Model only the safe direction. Text in hidden subtrees can still be fed to the **guards** (money guard, force_review), while it is excluded from the rules that *trigger* ACTION.
- Alternatively, re-enable text when a descendant sets `visibility:visible` or a non-zero font-size, and close `<p>` on block-level start tags.

### C-L8 (Low): The money guard sees only `newest_text` of the preferred part (A-F6 residual)

**Repro**
- `test_c04::test_F6_guard_ignores_text_after_a_fake_reply_marker_RESIDUAL`: the payment request sits below a forged `Am … schrieb …:`.
- `::test_F6_guard_ignores_html_alternative_when_plain_exists_RESIDUAL`: a harmless text/plain part, with the payment request only in text/html (which Gmail displays).
- `::test_F6_guard_lexicon_gaps_RESIDUAL`: "Geld … Euro … Lastschrift", "begleichen … Betrag … SEPA", "Guthabenkarten". Note: the original A-F6 PoC phrase "Geld … senden" is still not covered.

**Observed:** ACTION/AUTO with the ack draft in every case.

**Fix**
- Run the guard (a safety check, where a false positive only costs REVIEW) over the subject, the **full** `body_text`, **and every** text/html alternative, including quoted and hidden text.
- Extend the lexicon: `geld`, `euro`, `€`, `betrag`, `begleich`, `lastschrift`, `sepa`, `kreditkarte`, `credit card`, `guthaben`, `transfer`, `usdt`, `eth`.

### C-L9 (Low): The ReDoS lint misses non-nested catastrophic shapes (A-F4 residual)

**Repro:** `test_c04::test_F4_lint_misses_other_catastrophic_shapes_RESIDUAL`. Each pattern is accepted by config load. Measured search time on n vs. n+2 characters (n=22 → n=24):

| Pattern | n=22 | n=24 |
|---|---:|---:|
| `(a\|a)+$` | 0.72 s | 2.85 s |
| `(a{1,10})+$` | 0.35 s | 1.40 s |
| `(a+){1,40}$` | 0.35 s | 1.39 s |

That is ×4 per 2 characters, so about 40 hostile characters hang the run. The 20k haystack cap does not help. The run deadline is only checked between API calls, so a hung regex holds the lock indefinitely.

**Precondition:** the operator writes such a regex. Shipped regexes are not affected.

**Fix**
- Treat bounded repeats with max > 1 like unbounded ones in `_has_unbounded_repeat`/`_nested_unbounded`.
- Reject repeated alternations whose branches can match the same prefix.
- Or use the `regex` module with `timeout=`, or a watchdog subprocess.

### Info

- **C-I1:** An unusable anchor **location** (path is a file, or unreadable) is reported as `AUDIT_HEAD_CORRUPT` "anchor file is corrupt" (`test_c03::test_M8_anchor_dir_unwritable_on_first_run_INFO`). There is also no migration from the old in-folder `audit.head.json`: an upgrading v1 user gets `AUDIT_ANCHOR_MISSING` and must rebaseline without the old anchor being consulted.
- **C-I2:** A full user-profile restore that brings back both `%LOCALAPPDATA%` and `%APPDATA%` (or `~/.local/share` and `~/.local/state`) restores DB and anchor consistently and stays undetected. This is inherent to a local anchor; document it.
- **C-I3:** Undo restores `before_state` of the run and compensation restores the pre-undo state. Both can silently override an app label that a second client or a human set in the same window. For example, an `APPLIED_DRIFT` after-state containing a foreign app label is fully reverted. Only app labels are affected.
- **C-I4 (not verified against Google):** `check_transport` ignores `X-HTTP-Method-Override`. No allowed POST path maps to a dangerous endpoint under another verb, and googleapiclient's long-URI GET→POST override would be blocked (fail closed). Consider refusing the header explicitly.

## 5. What held up well

- Every global error still stops the run after message-scoped failures. Quarantine never applies to global codes or to LABEL_CREATE.
- Undo, compensation and preflight only ever compute deltas over application labels. A forged ledger row naming TRASH/SPAM is refused before any call.
- The capability bypass for undo is confined to `origin="undo"` plus label add/remove plus app-label names plus APPLY profile plus `--apply`. Planned actions always carry `origin="plan"`.
- The anchor lives outside the data folder (0700, keyed by DB path). DB-only restore, whole-folder restore, deleted DB, switched anchor dir and a copied stale DB are all refused. A broken chain is never re-anchored.
- SQLite lock, full, read-only and corrupt conditions are mapped precisely, also mid-run and in the CLI.
- DRY-RUN stays mutation-free with all the new checks. APPLY needs the explicit flag; no abbreviation, environment variable or misplaced flag works.


---

## Fix-Status nach dem Release-Zyklus (Stand 2026-10-03)

| Finding | Schwere | Status | Umsetzung | Regressionstest |
|---|---|---|---|---|
| C-M1 | Medium | **behoben** | Gate: Re-Importe von Transport-Objekten und privaten Namen, `sys.modules`, `importlib.util`/`runpy`/`pkgutil`/`inspect`/`ctypes`/`builtins`/`subprocess`, Aliasing reflektiver Builtins, Zugriff auf `_root`. Transport: Body-Prüfung (nur `Label_<n>`, Entwürfe threadgebunden), `X-HTTP-Method-Override` abgewiesen, Refresh-Transport nur `POST` an den Token-Endpunkt. | `test_C_M1_*`, `test_forbidden_scan_catches_planted_code[rc_*]` |
| C-L1 | Low | **behoben** | Jeder Fehler nach einem 5xx-/Netzwerk-Versuch eines Writes → `AmbiguousWriteError` → neu lesen oder offen lassen | `test_C_L1_*` |
| C-L2 | Low | **behoben** | Nach 5xx als nicht angewendet festgehaltene Writes zählen zur Quarantäne; der aktuelle Lauf stoppt trotzdem | `test_C_L2_*` |
| C-L3 | Low | **behoben** | Quarantäne → `PARTIAL` (Exit 9) | `test_poison_message_is_quarantined_after_three_failures` |
| C-L4 | Low | **behoben** | App-Labels beim Erstkontakt gelten als Entscheidung des Menschen | `test_app_label_set_by_a_person_before_first_run_is_kept` |
| C-L5 | Low | **behoben** | No-op-Undo-Einträge werden als UNDONE markiert | `test_C_L5_*` |
| C-L6 | Low | **behoben** | Befund in Vorschau und Ereignis; `--accept-rollback` / `--accept-rewrite` nötig | `test_C_L6_*` |
| C-L7 | Low | **behoben** | Sichtbarkeit pro Element wie im Browser (hart: display:none/hidden/opacity:0; überschreibbar: visibility/font-size; implizites `</p>`); die Guards sehen auch versteckten Text | `test_C_L7_*` |
| C-L8 | Low | **behoben** | Guard und force_review-Regeln prüfen `guard_text` (alle Teile, zitiert und versteckt); Wortliste erweitert | `test_C_L8_*` |
| C-L9 | Low | **behoben** | Wiederholte Alternativen und begrenzte Wiederholungen in großen Wiederholungen werden abgelehnt | `test_C_L9_*` |
| C-I1 | Info | **behoben** | Nicht lesbarer Anker-Ort → `AUDIT_ANCHOR_UNREADABLE`; keine Migration nötig, da erstes Release | `test_C_I1_*` |
| C-I2 | Info | Restrisiko | Die Wiederherstellung des gesamten Benutzerprofils bringt DB und Anker konsistent zurück (R-2) | – |
| C-I3 | Info | Restrisiko | Undo bzw. Kompensation setzen den auditierten Stand; ein fremdes App-Label aus demselben Zeitfenster kann überschrieben werden, nur App-Labels (R-3) | – |
| C-I4 | Info | **behoben** | `X-HTTP-Method-Override` wird abgewiesen | `test_C_M1_transport_refuses_system_labels_in_modify_body_and_method_override` |

Nach den Fixes: Die Suite von Red Team C läuft mit 51 von 51 FIXED-Prüfungen grün. Alle 26 RESIDUAL-/INFO-Proofs of Concept schlagen jetzt fehl, weil das Verhalten behoben ist.
