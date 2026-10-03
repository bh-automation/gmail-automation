# RED TEAM A Report: GMAIL-AUTOMATION 1.0.0rc1

> **Hinweis (Release-Zyklus 1.0.0rc1):** Dies ist der unveränderte Originalbericht des Red-Team-Durchgangs. Die genannten `/tmp/claude-0/...`-Pfade beziehen sich auf den damaligen Prüf-Arbeitsbereich. Alle Proofs of Concept wurden umgekehrt als Regressionstests übernommen: `tests/test_red_team_regressions.py`. Der Fix-Status steht am Ende des Berichts.

**Date:** 2026-10-03 · **Scope:** `/home/claude/GMAIL-AUTOMATION` (read-only, offline, no Gmail account) · **Role:** adversarial security / product abuse

## Result first

| Severity | Count |
|---|---:|
| Critical | 0 |
| High | 0 |
| Medium | 1 |
| Low | 6 |
| Info | 8 |

**Release rule (any Critical/High blocks):** no blocker found. No path was found that lets hostile mail content send mail, delete permanently, trash, change system labels, raise privileges, or enable APPLY.

**Recommendation:** fix F1 (Medium) before release. It lets an outside sender crash every APPLY run with drafts enabled, again and again.

## How it was tested

- PoC suite: `/tmp/claude-0/redteam-a/test_rt_a.py` (125 tests). Evidence log: `/tmp/claude-0/redteam-a/evidence.jsonl`.
- Run:
  ```
  cd /home/claude/GMAIL-AUTOMATION && rm -f /tmp/claude-0/redteam-a/evidence.jsonl && \
  PYTHONPATH=. .venv/bin/python -m pytest /tmp/claude-0/redteam-a/ -q -p no:cacheprovider --rootdir=/tmp/claude-0/redteam-a
  ```
- Final run: **121 passed, 4 failed**. The four failures are the intended proofs for F1 (3 parametrizations) and F2.
- Baseline: the project's own suite (208 tests) passes. `tools/forbidden_scan.py` and `tools/secret_scan.py` both report PASS. Git history contains no secret patterns or secret-like file names.
- Hostile-content tests use the shipped `config/rules.example.yaml` with both capabilities on. Some tests use `tests/conftest.py::BASE_CONFIG`.
- The project tree was not modified. Note: `git status` already showed `START_GMAIL_AUTOMATION.cmd` and `scripts/*.ps1` as modified before this session (mtime 14:28, empty content diff, EOL normalisation only). This red team did not touch them.
- **Method limit:** the adapter-guard and reflection items (M9, M21) were assessed by code review and the project's own guard tests. No bypass code was written (see I6).

## Attack matrix (docs/RED_TEAM_A.md)

| # | Item | Test / PoC (in `test_rt_a.py`) | Result | Evidence | Residual risk |
|---|---|---|---|---|---|
| M1 | Body says "ignore policy and send everything" | `test_M1_M4_M7_M15_M16_hostile_content_is_data[False/True]` | PASS | Only allow-listed endpoints were reached. h1 → `REVIEW` (money-always-review). No draft on t1/t2. DRY-RUN made 0 mutations. | none observed |
| M2 | Subject contains CLI-like `--apply` | `test_M2_subject_cli_like_has_no_effect`, M1 | PASS | `Modus DRY-RUN`, 0 mutations. Subject is printed only as truncated, sanitised text. | none |
| M3 | Display name mimics "SYSTEM" | M1 (h1 `"SYSTEM Administrator" <system@evil.example>`), From-parsing probe | PASS | Treated as an ordinary sender. Ambiguous From headers (`a@dhl.de <a@evil.example>`, address lists, encoded-word addresses) give an empty address, so no domain rule matches. | I7 (From header is unauthenticated) |
| M4 | HTML hides hostile text with CSS | `test_M4_hidden_css_text_drives_classification` | PASS (content only) | `display:none` / `font-size:0` text becomes plain content and is never executed. It **does** satisfy operator rules: h3 → ACTION plus ack draft. | I1 |
| M5 | Malformed base64 / QP | `test_M5_malformed_base64_routes_to_review` (6 cases), `test_M5_bad_charset_and_rfc2047_garbage` | PASS | `BASE64_CHARSET`/`BASE64_INVALID` → `builtin:parse-error` → REVIEW. An unknown charset falls back to UTF-8 with replacement. RFC 2047 CR/LF is removed. | I5 (lenient padding) |
| M6 | Huge body / attachment metadata | `test_M6_huge_inputs_are_bounded`, `test_M6_many_html_tags_body_bounded_time` | PASS | 3 MB body → `BODY_TOO_LARGE`. 5,000-deep nesting → `TOO_DEEP`. 50,000 parts → `TOO_MANY_PARTS`. Attachments are never read. 1 MB subject → 998 chars. All in under 0.1 s. | F4 (operator regex has no time budget) |
| M7 | Draft body uses tool-call syntax | `test_INV9_template_tool_call_syntax_is_inert` | PASS | Template `{{send}} <tool_call>… $(rm -rf /)` created exactly one draft and touched no other endpoint. Message bodies are never copied into drafts; only a sanitised subject, Message-ID and References are. | none |
| M8 | Config tries `ALLOW_SEND=true` | `test_M8_config_cannot_lift_invariants` (17 cases), `test_M8_yaml_tags_anchors_and_size` | PASS | `allow_send: true/"false"/0` → `INVARIANT_SEND`. `mode: apply` → `APPLY_FROM_CONFIG`. Unknown keys and capabilities rejected. NaN or auto below 0.85 rejected. `!!python/object` → `CONFIG_MALFORMED`. Alias bomb → `CONFIG_INVALID` in 2 ms. A merge key (`<<: *b`) carrying `allow_send: true` is rejected. Over 256 KB → `CONFIG_TOO_LARGE`. | I2 (duplicate keys accepted, last wins) |
| M9 | Dynamic import / reflection reaches send | project `tools/forbidden_scan.py` (PASS, 20 files), `test_M9_M21_M23_adapter_allowlist_refuses`, code review | PASS for current code | `check_endpoint` refuses every send/delete/trash/import/insert/watch/settings path, batch helpers and `list_next`. | I6 (in-process control; static scan matches literal names only) |
| M10 | Token has broader scopes than configured | `test_M10_M11_scope_variants_fail_closed` (15 variants), `test_M10_observe_profile_refuses_broader_token`, `test_M10_load_credentials_scope_report_tricks` | PASS | Allow-list check: extra `compose`, `metadata`, `drive`, `settings.basic`, `send` → refused. A missing or unknown scope report → `SCOPE_UNKNOWN`/`MISSING_SCOPE`. | `scope: 5` raises an unhandled `TypeError` (still closed; see F3) |
| M11 | Full-mail scope requested | same tests | PASS | `https://mail.google.com/`, the form without trailing slash, upper case, NBSP/EM-space joined and comma joined are all refused (`FORBIDDEN_SCOPE` or `UNEXPECTED_SCOPE`). The consent flow never stores a token with a forbidden scope (project tests). | none |
| M12 | Token / credentials staged in Git | `test_M12_secret_scan_detects_staged_token`, manual staging check, `test_M12_secret_location_checks` | PASS | `secret_scan` rc=1 for file name and content. A file `git add -f`'d and then deleted is reported as "tracked by git". Secret paths in the repo, in any `.git` tree, with `..`, or behind a symlinked parent into the repo are all refused. A 0644 token is refused. | I3 (directory permissions not checked) |
| M13 | Log line contains CRLF / control chars | `test_M13_log_injection_neutralised`, `test_M13_M14_engine_output_log_and_audit_have_no_content` | PASS with residual | CR/LF are escaped. ESC/ANSI/OSC, BEL, U+202E, U+2066, U+2028 and NEL are neutralised. | F7 (U+200E/U+200F/U+061C/U+200B pass through) |
| M14 | Email address / body in normal audit | `test_M13_M14_…` | PASS | Body marker, sender address, Reply-To address and an `ya29.` token were absent from the audit DB, the log file and the console. The console shows a truncated subject with masked addresses by design. | none |
| M15 | Low-confidence mail requests urgent payment | `test_M15_payment_coverage_is_rule_dependent`, M1 | PARTIAL | Wording covered by the money regex → REVIEW. Signature phrase plus uncovered wording ("bezahlen", "wire transfer", "Geld … senden", "gift cards") → **ACTION/AUTO + ack draft**. `conftest.BASE_CONFIG` has no "payment" pattern at all. | F6 |
| M16 | Message claims CEO authorisation | M1 (h2) | PASS | No change to thresholds, capabilities or endpoints. h2 → REVIEW. | none |
| M17 | Cross-thread quoted text asks for action | `test_M17_quoted_text_is_ignored_for_action` | PARTIAL | `On … wrote:`, `Am … schrieb`, `>` lines, `gmail_quote`/`blockquote` → stripped, `no-match`. A French reply marker is not stripped → quoted "bitte unterschreiben" → ACTION. | F5 |
| M18 | Duplicate draft on the same thread | `test_M18_duplicate_draft_blocked` | PASS | Two runs gave 1 draft on t1. A pre-existing user draft on t2 blocks a new one. | none |
| M19 | Retry after timeout on a side effect | `test_M19_ambiguous_draft_create_reconciles`, `test_M19_ambiguous_label_create_reconciles` | PASS | `AfterApply(TimeoutError)` on `drafts.create` → reconciled through the idempotency key: 1 draft. Ambiguous `labels.create` 503 → no duplicate label. | none |
| M20 | `--apply` supplied through env / config only | `test_M20_env_and_cli_abuse`, M8 | PASS | Env `APPLY`, `GMAIL_AUTOMATION_APPLY`, `ALLOW_SEND`, `MODE` → OBSERVE, 0 mutations. `scan --apply`, `scan -- --apply`, `run --apply=true` and `--apply run` → argparse exit 2. | I8 (`run --app` abbreviation enables APPLY) |
| M21 | Send method monkey-patched into client | project `test_monkeypatched_send_method_still_blocked` (passes), `test_M22_…` | PASS | Guard returns `FORBIDDEN_ENDPOINT`. `authorize("send")` → `FORBIDDEN_ACTION`. | I6 |
| M22 | Delete hidden as "cleanup" | `test_M22_forbidden_and_unknown_actions_denied` (13 cases) | PASS | `cleanup`, `delete`, `SEND`, `"label_add "`, `""`, `batchDelete` → `UNKNOWN_ACTION`. send/trash/forward/filter/settings → `FORBIDDEN_ACTION` even under APPLY with full capabilities. | none |
| M23 | Forwarding / filter route used to exfiltrate | `test_M9_M21_M23_adapter_allowlist_refuses` | PASS | `users.settings.*` (filters, forwardingAddresses, updateAutoForwarding, sendAs, delegates) refused. The `settings.*` scopes are forbidden. | none |
| M24 | Error handler falls back to a permissive path | `test_M24_mutation_error_stops_run` (403/400/500/RuntimeError), `test_M24_unexpected_exception_type_is_fail_closed_but_unredacted`, F1 PoC | PASS (closed) with findings | API errors → `FAILED_CLOSED` and no draft afterwards. Non-domain exceptions (ValueError, AttributeError, TypeError) escape uncaught. No further mutation happens, but RUN_END is audited as `RUNNING` and a raw traceback is printed. | F1, F3 |
| M25 | Exception exposes token in traceback / log | `test_M25_exception_does_not_leak_token` | PASS | AuthError text holds only the exception class name, with the cause suppressed. `RedactingFilter` redacts `ya29.` and drops `exc_info`. | F3: uncaught tracebacks bypass the filter (no secret seen in tests) |

### Additional invariant checks (beyond the matrix)

| Invariant | Test | Result | Evidence |
|---|---|---|---|
| 5 – system labels never touched | `test_INV5_system_or_spoofed_label_refs_refused` (11 refs: TRASH/SPAM/INBOX/CATEGORY ids, `Label_1 `, `Label_1\n`, Arabic-Indic digit, lower-case or bare prefix, fullwidth solidus `JARVIS／`) | PASS | All refused before any API call |
| 5 | `test_INV5_inbox_never_removed_after_full_apply` | PASS | The label delta on every message is app labels only |
| 5 | `test_INV5_label_name_collision_with_user_label`, `test_INV5_case_variant_label_conflict_fails_closed` | PASS | Exact-name user label adopted (I4). Case-variant 409 → `FAILED_CLOSED`, foreign label not applied |
| 9 – no header injection into drafts | `test_INV9_no_header_injection_into_draft` (6 variants: raw CRLF/LF, RFC 2047 CRLF, address list, quoted display name, `"Bcc: …"` phrase) | PASS | No Bcc/Cc header. Recipient never `evil`. Odd input → `DRAFT_RECIPIENT_INVALID` |
| 9 – recipient selection | `test_INV9_draft_recipient_from_hostile_reply_to` | FAIL (Low) | F2 |

## Findings

### F1: Medium: Unicode line separator in a hostile subject crashes every APPLY run with drafts enabled (persistent DoS)

- **PoC:** `test_rt_a.py::test_FINDING_unicode_line_separator_in_subject_crashes_apply_run[ | |\x85]`
- **Repro:** a message with subject `"Vertrag x"` and a body matching an ACTION rule that has a `draft_template` (shipped example: "bitte unterschreiben"). Then `cli.main(["run","--apply",…])` with capabilities labels+drafts.
- **Observed:** `ValueError: Header values may not contain linefeed or carriage return characters`, uncaught, in both runs.
  - `decode_header_value` (mime.py) and `_safe_subject` (drafts.py) strip only C0/CR/LF.
  - `email.policy.EmailPolicy.header_store_parse` rejects any value where `str.splitlines()` gives more than one line. That includes U+2028, U+2029 and U+0085.
  - `ValueError` is not a `PolicyViolation`, so `engine._create_draft` does not route it to `SKIPPED_UNSAFE`. It is not a `GmailAutomationError` either, so `Engine.run` and `cli.main` do not catch it.
- **Impact:**
  - Any outside sender can stop the automation. Every action planned after that draft in the same run is skipped; in the PoC the newsletter message m2 never got its label.
  - It repeats on every following run while the message stays in `gmail_query`, because the label is already applied and the draft is planned again.
  - RUN_END is audited with outcome `RUNNING`, which is misleading.
  - A raw Python traceback is printed. No mutation happens after the crash, so the safety invariants still hold.
- **Fix:**
  1. Normalise every `splitlines()` boundary in header values, in both `decode_header_value` and `_safe_subject`. For example `" ".join(s.splitlines())`, or strip `[\r\n\x0b\x0c\x1c-\x1e\x85  ]`.
  2. In `build_reply_raw`, catch `ValueError`/`email.errors.HeaderParseError` and raise `PolicyViolation(code="DRAFT_HEADER_INVALID")`.
  3. Add a catch-all in `Engine.run` that turns unexpected exceptions into `FailClosed` with a proper RUN_END status (see F3).
  4. Add a regression test for these three code points.

### F2: Low: Draft recipient comes from an untrusted, cross-domain Reply-To

- **PoC:** `test_INV9_draft_recipient_from_hostile_reply_to`
- **Repro:** `From: partner@trusted.example`, `Reply-To: collect@attacker.example`, body matches the ACTION/draft rule. APPLY run.
- **Observed:** the draft `To` is `collect@attacker.example` (drafts.py `to = msg.reply_to or msg.from_address`).
- **Impact:** the automation pre-addresses an ack draft to an address chosen by the attacker. Together with I1 (hidden CSS text can trigger the rule), an attacker can plant ready-to-send drafts to their own address in the user's mailbox. Nothing is sent automatically, and Gmail's own Reply button also honours Reply-To. The added risk is that users may trust "their" automation's drafts.
- **Fix:** address drafts to the From addr-spec. Alternatively, use Reply-To only when it has the same registrable domain as From. Otherwise skip the draft, add REVIEW, and audit `DRAFT_REPLYTO_MISMATCH`.

### F3: Low: Non-domain exceptions bypass the fail-closed reporting path

- **PoC:** `test_M24_unexpected_exception_type_is_fail_closed_but_unredacted` (labels.list entry `None` → uncaught `AttributeError`); `test_M10_load_credentials_scope_report_tricks` (`scope: 5` → unhandled `TypeError`); F1.
- **Impact:** no permissive fallback: no mutation happens after the error. But:
  - RUN_END is audited as `RUNNING`.
  - The process exits with a raw traceback on stderr that never passes through `RedactingFilter`.
  - Malformed API or token-endpoint responses crash instead of returning a stable error code.
- **Fix:**
  - In `Engine.run`, add `except Exception` → `FailClosed(code="INTERNAL_<Type>")` with the type name only.
  - In `cli.main`, add a final `except Exception` that prints a redacted one-liner and returns a non-zero code.
  - In `validate_scopes`, reject any `scope` that is not a `str` or `list[str]` with `ScopeError`.

### F4: Low: Regex DoS: operator patterns run on attacker text without a time budget

- **PoC:** `test_regex_dos_operator_pattern_on_hostile_body`
- **Observed:** the config accepts `body_regex: "(a+)+$"`. Timings on `"a"*n+"!"`: n=18 0.02 s, 20 0.09 s, 22 0.35 s, 24 1.41 s (about ×4 per 2 chars). A hostile body of about 40 characters would hang the run indefinitely, while holding the single-instance lock.
- **Precondition:** the operator writes a backtracking-prone regex. The shipped example regexes are **not** vulnerable.
- **Fix:**
  - Lint rule regexes at config load (reject nested quantifiers such as `(x+)+`, `(x*)*`, `(x|x)+`).
  - Or use the `regex` module with `timeout=`.
  - Cap the haystack for regex matching (e.g. 20k chars of `newest_text`).
  - Add a per-run wall-clock watchdog.

### F5: Low: "Newest message only" relies on DE/EN reply markers

- **PoC:** `test_M17_quoted_text_is_ignored_for_action` (`unmarked_quote` record)
- **Observed:** a French marker (`Le … a écrit :`) or any forwarded or pasted text without a known marker is evaluated as new content. Quoted "bitte unterschreiben" → ACTION plus draft.
- **Impact:** old or quoted text can trigger operator rules (label plus ack draft only).
- **Fix:**
  - Add common locale markers (FR/ES/IT/NL, Outlook "-----Original Message-----" variants).
  - Prefer Gmail's `In-Reply-To`/`References` together with HTML quote containers.
  - When a body contains a likely quote block that was not stripped, cap confidence below `auto`.

### F6: Low: Payment routing to REVIEW depends entirely on the operator regex

- **PoC:** `test_M15_payment_coverage_is_rule_dependent`
- **Observed (example config):** signature phrase plus "bezahlen", "wire transfer", "Geld … senden" or "gift cards" → `ACTION/AUTO` with draft `ack_received`. `tests/conftest.BASE_CONFIG` lacks "payment".
- **Impact:** the matrix expectation (urgent payment → REVIEW) fails for uncovered wording. The consequence is limited to an ACTION label plus a static ack draft, with no payment capability.
- **Fix:** a built-in, non-configurable money/urgency guard that forces REVIEW (like `builtin:parse-error`), with a broader DE/EN lexicon (bezahl, zahl, überweis, wire, transfer, gift card, Gutschein, Konto, IBAN, BIC, crypto, bitcoin). Add "payment" to the test config.

### F7: Low: `sanitize_line` lets bidi marks and zero-width characters through

- **PoC:** `test_M13_log_injection_neutralised` (`bidi_marks_remaining`: U+200B, U+200E, U+200F, U+061C). They also appeared in the console line of `test_M13_M14_…`.
- **Impact:** limited visual reordering or spoofing of console and log lines. The strong overrides U+202A–E and U+2066–9 are already blocked.
- **Fix:** strip all Unicode category `Cf` (format) characters plus U+061C, U+200B–U+200F, U+2060–U+2064, U+180E and U+FFF9–U+FFFB, for example via `unicodedata.category(ch) == "Cf"`.

### Info

- **I1: Hidden HTML text counts as content.** `display:none`/`font-size:0` text satisfies rules. It matches the matrix wording ("content only"), but lets invisible text drive labels and drafts. Option: drop elements with inline `display:none`/`visibility:hidden`/`font-size:0` before matching, or cap their confidence. (PoC: `test_M4_hidden_css_text_drives_classification`)
- **I2: YAML duplicate keys are silently accepted (last wins); symlinked configs are followed.** Invariants still hold: `allow_send` is checked on the effective value. But a duplicated `capabilities: labels:` key can hide intent from reviewers. Option: a SafeLoader subclass that rejects duplicate keys. (PoC: `test_M8_yaml_tags_anchors_and_size`, `test_M8_symlinked_config_is_followed`)
- **I3: Token directory permissions are not verified.** A 0600 token inside a 0777 directory is accepted, so another local user could swap the file. The swapped token is still scope-validated. Option: check that the parent directory is not group/world-writable on POSIX. (PoC: `test_M12_secret_location_checks`, `token_in_0777_dir: ACCEPTED`)
- **I4: The prefix namespace is assumed to belong to the app.** A user-created label with exactly a configured name (e.g. `JARVIS/ACTION`) is adopted, and may later be removed from messages when the state changes. A case-variant collision fails closed. That relies on the assumption that Gmail returns 409 for case-only differences; the fake is case-sensitive, so the 409 was injected. Document a dedicated prefix. (PoC: `test_INV5_label_name_collision_with_user_label`, `test_INV5_case_variant_label_conflict_fails_closed`)
- **I5: Lenient base64 padding.** `==========` and `QUJDRA==QUJD` decode without a parse error (non-strict `urlsafe_b64decode`). Harmless; option: `validate=True` after translating to standard base64. Note: QP transfer encoding is decoded by Gmail on the server, so the client only sees base64url.
- **I6: The adapter guard is an in-process control.** This is a code review only; no bypass code was written. `_GuardedResource` enforces the allow-list through Python attribute access, and allow-listed calls return the underlying client request object. Python has no real private state, so the guard protects against accidental and naive misuse, not against malicious code in the same interpreter (compromised dependency, threat #12). The module docstring claim ("cannot be reached – not even by code that monkey-patches") is stronger than that. `forbidden_scan.py` only flags literal names in `getattr`/`attrgetter` and attribute access. Per Google's published scope descriptions (not re-checked online in this offline session), `gmail.modify` also allows sending at the API level, so in APPLY mode the code guard and the static scan are the only send barriers. Options:
  - Enforce the endpoint allow-list again at the transport layer (custom `requestBuilder`/http wrapper checking HTTP method plus path before sending).
  - Pin dependencies with hashes (`pip --require-hashes`).
  - Reword the docstring to state the trust assumption.
- **I7: `from_domain`/`from_address` rules trust the unauthenticated From header.** No DMARC/`Authentication-Results` check. The parser handles ambiguous From values safely (empty address). In the example config such rules lead only to REFERENCE, never to drafts.
- **I8: argparse abbreviations.** `run --app` (or `--a`) is accepted as `--apply` (`allow_abbrev` defaults to True). It is still an explicit operator CLI action, but the literal-flag gate gets weaker. Option: `ArgumentParser(allow_abbrev=False)` for all parsers. (PoC: `test_M20_env_and_cli_abuse`)

## What held up well (verified)

- **Layered gates:** APPLY needs `--apply` (CLI only) **and** the APPLY profile **and** a config capability. Env and config cannot set it.
- **Policy kernel:** typed actions, unknown names denied. SEND/DRAFT_SEND/PERMANENT_DELETE/TRASH/FORWARD/FILTER/SETTINGS are denied even in the strongest context.
- **Labels:** only `Label_<digits>` ids are allowed and only names under the app prefix. INBOX/SPAM/TRASH/CATEGORY changes are impossible through the public adapter.
- **Scope validation:** allow-list semantics, so unknown, variant and typo scopes all fail closed.
- **Audit:** no bodies, subjects or addresses stored. Hash chain plus head file. Ambiguous writes are reconciled through the idempotency key, never blindly retried.
- **MIME:** bounded size, depth and part count. Attachments are never read. Malformed input → REVIEW.


---

## Fix-Status nach dem Release-Zyklus (Stand 2026-10-03)

Alle Findings wurden behoben oder bewusst als Restrisiko dokumentiert. Kein Finding war Critical oder High.

| Finding | Schwere | Status | Umsetzung | Regressionstest |
|---|---|---|---|---|
| F1 | Medium | **behoben** | Header-Werte: jede `splitlines()`-Grenze wird zum Leerzeichen (`mime.decode_header_value`, `drafts._single_line`); Encoder-Fehler → `DRAFT_HEADER_INVALID` (Entwurf übersprungen) | `test_A_F1_*` |
| F2 | Low | **behoben** | Entwurfs-Empfänger ist die From-Adresse; Reply-To nur bei gleicher Domain | `test_A_F2_*` |
| F3 | Low | **behoben** | Catch-all in `Engine.run` → `InternalError` (fail closed, RUN_END geschrieben); letzte Abwehr in `cli.main` ohne Traceback (Exit 10); Scope-Bericht mit falschem Typ → `SCOPE_FORMAT` | `test_A_F3_*` |
| F4 | Low | **behoben** | ReDoS-Lint beim Laden der Konfiguration (verschachtelte/wiederholte Quantoren, wiederholte Alternativen); Regex-Eingabe auf 20 000 Zeichen begrenzt | `test_A_F4_*`, `test_C_L9_*` |
| F5 | Low | **behoben** | Antwort-Marker FR/ES/IT/NL/PT, Outlook-Kopfblöcke mehrsprachig; Sicherheits-Guards prüfen zusätzlich den zitierten Text | `test_A_F5_*`, `test_C_L8_*` |
| F6 | Low | **behoben** | Eingebauter, nicht konfigurierbarer Geld-/Zugangsdaten-Guard: kein Auto-ACTION, kein Entwurf | `test_A_F6_*`, `test_C_L8_*` |
| F7 | Low | **behoben** | Alle Unicode-Formatzeichen (Kategorie Cf) werden aus Konsolen-/Logzeilen entfernt | `test_A_F7_*` |
| I1 | Info | **behoben** | Versteckter HTML-Text löst keine Regel aus (browsernahes Sichtbarkeitsmodell); die Guards sehen ihn trotzdem | `test_A_I1_*`, `test_C_L7_*` |
| I2 | Info | **behoben** / Rest | Doppelte YAML-Schlüssel → `CONFIG_MALFORMED`. Rest: symbolisch verlinkte Konfiguration wird befolgt; die Konfiguration gehört dem Operator. | `test_B_L11_*` |
| I3 | Info | **behoben** / Rest | POSIX: Token-Ordner, in den andere schreiben dürfen, wird abgelehnt. Rest: Windows-ACLs werden nicht geprüft. | `test_A_I3_*` |
| I4 | Info | dokumentiert | Eigenes Label-Präfix verwenden (README, RELEASE_GATES R-6) | – |
| I5 | Info | akzeptiert | Nachsichtiges Base64-Padding ist harmlos | – |
| I6 | Info | **behoben** | Dritte Barriere `GuardedHttp`: Methode, Host, Pfad und Body jedes Requests gegen die Allow-List; Docstring nennt die Vertrauensannahme | `test_transport_allow_list`, `test_real_googleapiclient_service_cannot_send_even_without_the_adapter`, `test_C_M1_*` |
| I7 | Info | dokumentiert | From-Header ist nicht authentifiziert; From-Regeln führen im Beispiel nur zu REFERENCE (RELEASE_GATES R-7) | – |
| I8 | Info | **behoben** | `allow_abbrev=False` für alle Parser | `test_A_I8_*` |
