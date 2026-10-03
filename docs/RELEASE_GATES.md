# Release-Gates 1.0.0

Stand: 2026-10-03 · alle Gates offline geprüft (kein Gmail-Konto, keine Secrets) · Python 3.12 und 3.13

Release-Regel: Alle Gates müssen PASS sein. Ein Critical- oder High-Finding aus den Red-Team-Durchgängen blockiert das Release. Ergebnis: **alle 16 Gates PASS, 0 Critical / 0 High offen.**

## Gates

| Gate | Prüfung | Nachweis | Status |
|---|---|---|---|
| G1 Lint | ruff check, ruff format --check, mypy | `scripts/verify.ps1`, CI-Schritte „G1“ | PASS |
| G2 Tests | komplette Suite, offline | `python -m pytest` – 356/356 (3.12 und 3.13) | PASS |
| G3 Secret-Scan | Dateinamen, Inhalte, von Git verfolgte Dateien, Git-Historie | `tools/secret_scan.py`, `test_secret_scan_*`, `test_gitignore_covers_secrets_and_state` | PASS |
| G4 OBSERVE kann nichts ändern | Policy (Profil), Adapter-Allow-List, Transport-Allow-List (OBSERVE erlaubt nur GET) | `test_observe_*`, `test_observe_client_cannot_mutate_and_never_reaches_fake`, `test_transport_allow_list` | PASS |
| G5 Senden gesperrt (in der Anwendung) | Policy-Invariante, Adapter-Guard, Transport-Guard, statischer Gate-Scan, Laufzeit-Selbsttest in jeder Zusammenfassung | `test_send_hard_block`, `test_monkeypatched_send_method_still_blocked`, `test_real_googleapiclient_service_cannot_send_even_without_the_adapter`, `test_draft_is_never_sent`, `SEND_BLOCK = PASS` | PASS |
| G6 Endgültiges Löschen gesperrt | wie G5, zusätzlich trash/batchDelete und System-Labels im Request-Body | `test_delete_hard_block`, `test_system_and_foreign_labels_refused`, `test_C_M1_transport_refuses_system_labels_in_modify_body_and_method_override`, `DELETE_BLOCK = PASS` | PASS |
| G7 DRY-RUN ohne Änderungen | Standardmodus, auch wenn Fähigkeiten eingeschaltet sind | `test_dry_run_has_zero_mutations_even_with_capabilities`, `test_run_without_apply_is_dry_run_even_with_env_and_config`, `test_dry_run_stays_mutation_free_with_all_new_checks` | PASS |
| G8 Idempotenz | Idempotenz-Schlüssel, NOOP-Prüfung, Abgleich nach Absturz, Vorrang des Menschen | `test_reprocessing_unchanged_data_is_a_no_op`, `test_crash_*`, `test_manual_*`, `test_B_M1_*`, `test_C_L1_*` | PASS |
| G9 Keine doppelten Entwürfe | Ledger und Gmail-Entwürfe (paginiert), Schlüssel-Header, Abgleich mehrdeutiger Creates | `test_duplicate_draft_protection`, `test_existing_user_draft_in_thread_blocks_auto_draft`, `test_ambiguous_draft_create_is_reconciled_not_duplicated`, `test_B_L10_drafts_are_paginated` | PASS |
| G10 Audit-Integrität | Hash-Kette, nur anhängen, Manipulation, Rollback-Anker außerhalb des Datenordners, präzise Speicherfehler | `tests/test_audit.py`, `test_B_M3_*`, `test_B_M8_*`, `test_B_L8_*`, `test_B_L9_*`, `test_C_L6_*` | PASS |
| G11 Undo | Vorschau, dann Ausführung; alles oder nichts mit Kompensation; Kill-Switch blockiert Undo nicht | `test_undo_preview_then_apply_restores_exact_state`, `test_B_M2_*`, `test_B_L6_*`, `test_C_L5_*` | PASS |
| G12 Undo verweigert bei Konflikt | STATE_DRIFT, API_NOT_FOUND, LATER_RUN, LABEL_MISSING – das Postfach bleibt unverändert | `test_undo_conflict_*`, `test_B_L7_*`, `test_B_M2_undo_with_deleted_restore_label_is_conflict_and_untouched` | PASS |
| G13 Grenze gegen Prompt-Injection | Mail-Inhalt ist nur Daten; versteckter Text steuert keine Regel; Geld-Guard sieht alle Teile; Header-Injection; Unicode | `test_prompt_injection_is_inert_data`, `test_injection_cannot_trigger_rules_via_quoted_text`, `test_hostile_mailbox_cannot_escalate`, `test_A_F1_*`, `test_A_F6_*`, `test_C_L7_*`, `test_C_L8_*` | PASS |
| G14 OAuth-Scope-Prüfung | Scopes laut Googles Token-Antwort; Vollzugriff, send, insert und settings verboten; falscher Typ wird abgelehnt | `tests/test_auth.py`, `test_A_F3_scope_report_with_wrong_type_fails_closed` | PASS |
| G15 CI ohne echtes Gmail | Workflow ohne Secrets; Fakes und Doubles | `.github/workflows/ci.yml`, `test_ci_workflow_covers_required_gates` | PASS |
| G16 Saubere Git-Arbeitskopie | `git status --porcelain` leer beim Tag; keine Secret-Dateien verfolgt | geprüft vor `git tag v1.0.0` | PASS |

## Red-Team-Ergebnis

| Durchgang | Critical | High | Medium | Status |
|---|---:|---:|---:|---|
| A – Angriffe auf das Produkt | 0 | 0 | 1 → 0 offen | PASS |
| B – Betrieb und Zuverlässigkeit | 0 | 0 | 8 → 0 offen | PASS |
| C – Prüfung der Fixes | 0 | 0 | 1 → 0 offen | PASS |

Berichte mit Fix-Status: [A](RED_TEAM_A_REPORT.md) · [B](RED_TEAM_B_REPORT.md) · [C](RED_TEAM_C_FIX_VERIFICATION.md)

## Restrisiken (bewusst akzeptiert und dokumentiert)

| ID | Restrisiko | Begrenzung / Empfehlung |
|---|---|---|
| R-1 | Alle Sperren sind Kontrollen im selben Prozess. Bösartiger Code im selben Interpreter, etwa eine kompromittierte Abhängigkeit, kann sie umgehen. | Exakt gepinnte Laufzeit-Abhängigkeiten, statischer Gate-Scan, Transport-Allow-List; Abhängigkeiten nur bewusst aktualisieren |
| R-2 | Die Wiederherstellung des **gesamten** Benutzerprofils (`%LOCALAPPDATA%` und `%APPDATA%`) bringt DB und Anker konsistent zurück. Das wird nicht erkannt. | Nach einer Profil-Wiederherstellung `status` prüfen; der Vorrang des Menschen verhindert Ping-Pong |
| R-3 | Kurzes Zeitfenster zwischen Frische-Prüfung und Write. Undo und Kompensation setzen den auditierten Stand und können ein fremdes App-Label aus genau diesem Fenster überschreiben. | Betrifft nur App-Labels; jede Änderung ist auditiert und undo-fähig |
| R-4 | Mehr Treffer als `max_messages_per_run` (höchstens 1000): Der älteste Rest wird nicht verarbeitet. | Abfrage eingrenzen (kürzerer Zeitraum); inkrementelle Synchronisation steht auf der Roadmap |
| R-5 | Das Ledger wächst unbegrenzt; die vollständige Kettenprüfung kostet pro Lauf O(n), etwa 3 s bei 200 000 Zeilen. | Für V1 ausreichend; Rotation und inkrementelle Prüfung stehen auf der Roadmap |
| R-6 | Ein vom Nutzer angelegtes Label mit genau dem konfigurierten Namen wird übernommen. | Eigenes Präfix verwenden (Standard `JARVIS/`) |
| R-7 | Der From-Header ist nicht authentifiziert (keine DMARC-Prüfung). | From-Regeln nur für risikoarme Zustände (Beispiel: REFERENCE); Entwürfe gehen nur an die From-Adresse |
| R-8 | CI-Actions sind per Tag gepinnt, nicht per SHA; es gibt keine Hash-Locks (`--require-hashes`). | Vor einer Veröffentlichung die Actions auf Commit-SHAs pinnen und Dependabot aktivieren |
| R-9 | Ein Entwurf, der genau im Absturzfenster bearbeitet oder verworfen wird, kann falsch zugeordnet oder einmal neu angelegt werden. | Selten; ein Entwurf wird nie gesendet |
| R-10 | Das Verhalten gegen das echte Gmail ist nur mit Fakes und dem echten googleapiclient (ohne Netzwerk) getestet. | Gestufter Livetest vor `v1.0.0`: [LIVE_ROLLOUT.md](LIVE_ROLLOUT.md) |
| R-11 | OAuth-Apps im Status *Testing*: Der Refresh-Token läuft laut Google nach 7 Tagen ab. | `auth` erneut ausführen; das Programm meldet `REFRESH_FAILED` sauber |
| R-12 | Windows: ACLs des Token-Ordners werden nicht geprüft (nur POSIX-Rechte). | Der Datenordner liegt im Benutzerprofil (`%LOCALAPPDATA%`) |
| R-13 | Eine Laufzeit-Deadline unterbricht keine hängende Berechnung (z. B. eine Regex). | Der ReDoS-Lint lehnt katastrophale Muster schon beim Laden der Konfiguration ab |
| R-14 | Der APPLY-Token (`gmail.modify`) hat auf Google-Seite Lese-, Verfassen-, Sende- und Papierkorbrechte. Die Sperren gelten nur für diese Anwendung: Wer die Token-Datei erlangt, kann außerhalb der Anwendung senden. | Token nur außerhalb des Projekts (geprüft); APPLY-Token erst anlegen, wenn er gebraucht wird; für Scans OBSERVE nutzen; Zugriff im Google-Konto widerrufbar; der Vollzugriff-Scope bleibt verboten |
