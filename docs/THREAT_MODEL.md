# Threat Model

## Assets
OAuth tokens, mailbox contents, drafts, labels, audit DB, rules config, Git history and operator trust.

## Main threats
1. Hostile email prompt injection.
2. OAuth scope overreach.
3. Accidental auto-send.
4. Permanent deletion.
5. Duplicate processing.
6. Race between scan and apply.
7. Secret leakage into Git/logs.
8. Cross-thread misclassification.
9. Undo against changed state.
10. LLM hallucinating facts in drafts.
11. API retries duplicating side effects.
12. Compromised dependency or CI artifact.

## Controls
Capability allow-list, dry-run default, separate profiles, idempotency keys, before/after checks, redaction, CI static scans, mocked integration tests and release gates.

## Umsetzung in V1 (1.0.0rc1)

| # | Bedrohung | Kontrollen im Code | Nachweis |
|---|---|---|---|
| 1 | Prompt-Injection über Mails | Regel-Klassifikator ohne Gmail-Handle; Inhalt ist nur Daten; versteckter HTML-Text löst keine Regel aus; eingebauter Geld-/Zugangsdaten-Guard und force_review-Regeln sehen alle Teile (zitiert, versteckt, jede MIME-Alternative); Header werden auf eine Zeile normalisiert | `test_prompt_injection_is_inert_data`, `test_hostile_mailbox_cannot_escalate`, `test_A_F1_*`, `test_C_L7_*`, `test_C_L8_*` |
| 2 | Zu weite OAuth-Scopes | Zwei Profile (OBSERVE: readonly; APPLY: modify + labels); Prüfung gegen Googles Token-Antwort; verbotene, unerwartete oder falsch typisierte Scopes werden abgelehnt | `tests/test_auth.py` |
| 3 | Unbeabsichtigtes Senden | Vier unabhängige Schichten: Policy-Invariante, Adapter-Allow-List, `GuardedHttp`-Transport-Allow-List mit Body-Prüfung, statischer Gate-Scan | G5 in `RELEASE_GATES.md` |
| 4 | Endgültiges Löschen | wie 3; System-Labels (TRASH/SPAM/INBOX …) sind auch im Request-Body gesperrt | G6 |
| 5 | Doppelte Verarbeitung | Idempotenz-Schlüssel, NOOP-Prüfung, Write-ahead-Audit mit Abgleich; Vorrang des Menschen verhindert Ping-Pong | G8 |
| 6 | Wettlauf zwischen Scan und Apply | Frische-Prüfung (Thread und Labels) direkt vor jedem Write; Prüfung nach dem Write (`APPLIED_DRIFT`) | `test_stale_*`, `test_verify_mismatch_*` |
| 7 | Secrets in Git oder Logs | Secrets nur außerhalb des Repos und außerhalb jedes Git-Baums; Secret-Scan; Redaction; keine Tracebacks in Logs | G3, `test_tokens_are_redacted` |
| 8 | Fehlklassifikation über Threads hinweg | Nur die neueste echte Nachricht (keine Entwürfe) wird bewertet; zitierter Text wird entfernt (DE/EN/FR/ES/IT/NL/PT) | `test_B_I3_*`, `test_A_F5_*` |
| 9 | Undo gegen geänderten Zustand | Preflight (Drift, späterer Lauf, fehlende Labels, Policy) vor jeder Änderung; Kompensation bei Fehlern mitten im Lauf | G11, G12 |
| 10 | Erfundene Fakten in Entwürfen | Nur statische Operator-Vorlagen, kein Mail-Inhalt im Entwurf, Empfänger ist die From-Adresse | `test_draft_header_injection_is_refused`, `test_A_F2_*` |
| 11 | Wiederholungen mit doppelten Seiteneffekten | Mehrdeutige Writes werden nie blind wiederholt, sondern neu gelesen und festgehalten; Backoff-Budget, Deadline, begrenzte Paginierung | `test_B_M1_*`, `test_C_L1_*`, `test_B_L2_*` |
| 12 | Kompromittierte Abhängigkeit oder CI-Artefakt | Exakt gepinnte Laufzeit- und Prüfwerkzeuge, `pip check`, CI ohne Secrets; Restrisiko R-1/R-8 | `RELEASE_GATES.md` |

### Zusätzliche Bedrohungen aus den Red-Team-Durchgängen

| Bedrohung | Kontrolle |
|---|---|
| Wiederherstellung eines alten Audit-Backups (Rücksetzen der Historie) | Rollback-Anker außerhalb des Datenordners (`%APPDATA%`), `AUDIT_ROLLBACK`; Neu-Verankerung nur explizit und protokolliert |
| Eine einzelne Nachricht blockiert die Automatisierung („Poison message“) | Fehler, die nur eine Nachricht betreffen, werden auditiert; nach 3 Fehlern Quarantäne; der Lauf meldet `PARTIAL` |
| Gesperrte, volle oder schreibgeschützte Audit-DB | Präzise Fehlercodes (`AUDIT_LOCKED`/`FULL`/`READONLY`/`CORRUPT`), nie „corrupt“ bei einer Sperre |
| ReDoS durch Operator-Regex gegen Angreifer-Text | Lint beim Laden der Konfiguration, begrenzte Eingabelänge |
| Abgekürzte Flags (`--app` als `--apply`) | `allow_abbrev=False` |

Restrisiken: siehe `RELEASE_GATES.md`, Abschnitt „Restrisiken“.
