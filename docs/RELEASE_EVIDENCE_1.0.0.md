# Release-Evidence GMAIL-AUTOMATION 1.0.0

Datum: 2026-10-03 · Geprüfter Code: `main` c340a95 (Kern) und `feature/mission-control` 3bcee11, auf Windows 11 (Build 26200, Python 3.13.14) und Linux (Python 3.12).
Diese Datei enthält keine Secrets, Tokens, Client-IDs und keine Inhalte echter Mails. Die ausführlichen Protokolle (geschwärzt) liegen beim Betreiber unter `%LOCALAPPDATA%\GmailAutomation\live-evidence\`.

## Offline-Gates
| Gate | Linux | Windows |
|---|---|---|
| G1 Lint / Format / Typen | PASS | PASS (ruff lief; in rc3 war ruff.exe durch die Anwendungssteuerung zeitweise blockiert) |
| G2 Tests | 356 (Kern) · 390 + 7 Browser (Mission Control) | 388 bestanden, 2 übersprungen (Symlink-Recht, POSIX-Rechte) |
| G3 Secret-Scan · G4–6 Forbidden-Scan · Abhängigkeiten · Config | PASS | PASS |
| Mission-Control-Browser-Gate (Chromium) | PASS | PASS |

## Live-Gates am echten Gmail-Konto
| Stufe | Ergebnis |
|---|---|
| OBSERVE (`gmail.readonly`) | PASS. GATEST: Vertrag ACTION 0.86 · Zahlung REVIEW 0.70 · Hallo REVIEW 0.00. 0 Änderungen; historyId aller Testmails unverändert |
| Stichprobe echter Mails (7 Tage, 30 Mails, nur lesend) | 0 Änderungen, 0 Parserfehler. Nur anonymisierte Statistik |
| APPLY-Profil | Scopes `gmail.modify` + `gmail.labels`; kein `mail.google.com`, kein separates `send`/`compose` |
| Label-Canary (GATEST-APPLY-001 und -002) | genau 1 Labeländerung an der Canary-Mail (beim ersten Lauf zusätzlich: Label JARVIS/ACTION angelegt) · Idempotenz: 0 · Undo: DONE, Labelzustand exakt wie vorher |
| Undo wird respektiert | Ein erneuter APPLY-Lauf auf die zurückgesetzte Canary ändert nichts (0) |
| Entwurf-Canary (GATEST2 Draft) | genau 1 Entwurf im richtigen Thread, Empfänger = Absender, kein CC/BCC/Anhang, nicht versendet · Duplikat-Lauf: 0 |
| Gesendet / Papierkorb / gelöscht | 0 / 0 / 0 über alle Läufe |

## Abschließendes Live-Red-Team (Code-Stand 1.0.0): 17/17 PASS
Kritisch = 0, Hoch = 0.

- Policy-Kernel lehnt ab: senden, Entwurf senden, endgültig löschen, Papierkorb, weiterleiten, Filter, Einstellungen – selbst mit APPLY + `--apply` + allen Capabilities + Confidence 1.0. Positiv-Kontrollen bestanden.
- Gefälschter Modus (OBSERVE + Flag, APPLY ohne `--apply`), gefälschte Capability, Confidence 0.84, Nicht-App-Label (INBOX): abgelehnt.
- Transport-Allow-List: send, drafts.send, delete, trash, modify(TRASH): abgelehnt.
- OAuth-Trennung: Das OBSERVE-Token gilt nicht als APPLY, das APPLY-Token nicht als OBSERVE, Vollzugriff wird abgelehnt.
- Prompt Injection, Geld-, Anweisungs- und HTML-Mails: als Daten behandelt, alle REVIEW, 0 Änderungen.
- Mission Control: gefälschter Modus/Profil/Confidence/Capability per POST ignoriert (DRY-RUN/observe, 0 Änderungen); ungültiger Host, fehlender Origin, Cross-Site-POST, gefälschtes Action-Token → 403; keine Mutations-Endpunkte; 0 Treffer bei der Suche nach Secrets oder Tokens in API-Antworten und Logs; XSS: 0 Dialoge, 0 Konsolenfehler, 0 eingeschleuste Elemente; nur 127.0.0.1; ein veraltetes Backend wird als DEGRADED gemeldet.
- Gleichzeitiges Lesen des Audit-Ankers: 1 schreibender Scan und 8 parallele Leser, alle mit Exit-Code 0, 0 Anker-Fehler.
- Audit: PASS (Hash-Kette); 0 offene Aktionen, 0 in Quarantäne.
- Keine Änderung außerhalb der exakten Canary-Abfrage (`historyId` aller anderen Mails unverändert).

## Bewusst offen (nach 1.0.0)
- Feinabstimmung der Geld-Regel und der Fälle ohne Regeltreffer (Stichprobe: 8 von 30 über die Geld-Regel, 10 ohne Treffer).
- Mission Control bleibt ein eigener Branch und rein lesend; keine Mailbox-Mutation über die Konsole.
- Die Zustellung phishing-ähnlicher Testmails über outlook.de war unzuverlässig (Umgebung, kein Produktfehler).

## Sichere Voreinstellung
`mode: dry-run`, `labels: false`, `drafts: false`. Es ist keine allgemeine Inbox-Automatisierung aktiviert.
