# Changelog

## 1.0.0rc2 – 2026-10-03

Keine funktionalen Code-Änderungen gegenüber rc1.

- Dokumentation: Die OAuth-Aussage ist präzisiert. `gmail.modify` würde auf Google-Seite Senden erlauben; GMAIL-AUTOMATION sperrt Senden und endgültiges Löschen **in der Anwendung** (Policy, Adapter, Transport-Allow-List). Neues Restrisiko R-14 (APPLY-Token als Geheimnis).
- Neu: `docs/LIVE_ROLLOUT.md` – gestufter Livetest (OBSERVE → ein Label-Lauf → Idempotenz → Undo → ein Entwurf) mit Bestanden- und Abbruchkriterien.
- Veröffentlichungsreife: In der Git-Historie stehen eine neutrale Autor-Adresse und keine Session-Links in den Commit-Nachrichten; Testdaten enthalten keine Klarnamen.

## 1.0.0rc1 – 2026-10-03

Erstes Release (Kandidat). Lokale, abgesicherte Gmail-Automatisierung für Windows: Observe → Klassifizieren → Labels → Entwürfe, mit Audit und Undo. Standard ist DRY-RUN.

### Funktionen
- OAuth-Profile OBSERVE (`gmail.readonly`) und APPLY (`gmail.modify` + `gmail.labels`); Scopes werden gegen Googles eigene Token-Antwort geprüft.
- Regelbasierter, deterministischer Klassifikator mit Konfidenzbändern (≥ 0,85 automatisch, 0,60–0,84 REVIEW-Label, < 0,60 keine Änderung).
- App-Labels (`JARVIS/…`) und Antwort-Entwürfe aus statischen Vorlagen. Senden und endgültiges Löschen sind in der Anwendung gesperrt (Policy-Kernel, Adapter- und Transport-Allow-List); sie bietet dafür weder Funktion noch freigegebenen HTTP-Endpunkt.
- Write-ahead-Audit (SQLite, Hash-Kette, nur anhängen) mit Rollback-Anker außerhalb des Datenordners.
- Konfliktbewusstes Undo: Vorschau, dann alles oder nichts mit Kompensation.
- Windows-Einstiegspunkte: `START_GMAIL_AUTOMATION.cmd`, `scripts/bootstrap.ps1` (repariert sich selbst), `scripts/verify.ps1` (alle Gates offline).
- CLI: `doctor`, `auth`, `scan`, `run`, `status`, `undo`, `config-check`, `audit-verify`, `audit-rebaseline`.

### Sicherheit (aus den Red-Team-Durchgängen A, B und C)
- Header-Werte werden auf eine Zeile normalisiert (auch U+2028/U+2029/NEL); Encoder-Fehler überspringen den Entwurf, statt den Lauf abzubrechen.
- Der Entwurfs-Empfänger ist immer die From-Adresse (Reply-To nur bei gleicher Domain).
- Eingebauter Geld-/Zugangsdaten-Guard; die Guards sehen alle MIME-Teile sowie zitierten und versteckten Text.
- Versteckter HTML-Text steuert keine Regel (browsernahes Sichtbarkeitsmodell).
- ReDoS-Lint für Operator-Regexes; doppelte YAML-Schlüssel werden abgelehnt.
- Transport-Allow-List `GuardedHttp` mit Body-Prüfung; der Refresh-Transport erreicht nur den Token-Endpunkt.
- Gehärteter statischer Gate-Scan (Reflection, Transport-Importe, Re-Importe, Aliasing; Ausnahmen an exakte Pfade gebunden).
- Mehrdeutige Writes werden neu gelesen und festgehalten, nie als finales FAILED verbucht.
- Fehler, die nur eine Nachricht betreffen: FAILED und weiter, Quarantäne nach 3 Fehlern; globale Fehler stoppen den Lauf.
- Vorrang des Menschen: manuell geänderte App-Labels werden nie zurückgesetzt.
- Präzise Audit-Speicherfehler; nebenläufigkeitssichere Migration und Anker-Prüfung.
- `--apply` lässt sich nicht abkürzen; unerwartete Fehler stoppen ohne Traceback (Exit 10).

### Exit-Codes
0 OK · 2 Policy/Konfiguration · 3 Anmeldung/Scope · 4 Undo-Konflikt · 5 Audit · 6 Lock · 7 Gmail-API · 8 fail closed / Undo zurückgerollt · 9 teilweise · 10 intern · 130 Abbruch.
