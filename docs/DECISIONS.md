# Architecture Decision Log

## ADR-001 — Local-first Windows deployment
Chosen to minimize operational surface and fit personal mailbox use.

## ADR-002 — Rules before LLM
Deterministic rules create a measurable baseline. LLM support is optional and constrained.

## ADR-003 — Capability policy between classifier and Gmail
The classifier cannot mutate Gmail directly.

## ADR-004 — Read-only Observe stage before Apply
Privilege and behavior are introduced incrementally.

## ADR-005 — SQLite audit ledger
Simple, local, transactional and easy to inspect/backup.

## ADR-006 — No full-mail OAuth scope
Permanent-delete-capable scope is outside the product boundary.

## ADR-007 — Fluent-inspired UI, not branded clone
Use Fluent principles/components where appropriate without bundling proprietary assets or fonts.

## ADR-008 — Rollback-Anker außerhalb des Datenordners
Ein Backup des Datenordners stellt DB und Anker sonst gemeinsam wieder her. Der Anker liegt deshalb in `%APPDATA%` (Daten in `%LOCALAPPDATA%`). Neu verankert wird nur explizit und protokolliert (`audit-rebaseline`, Befund + eigene Flags).

## ADR-009 — Fehler nach Geltungsbereich trennen
400/404/409 betreffen nur eine Nachricht: auditieren, weitermachen, nach 3 Fehlern Quarantäne. Alles andere (Auth, Scope, Policy, Audit, Kontingent, unbekannt) stoppt den Lauf (fail closed). Ein Write mit unbekanntem Ausgang wird neu gelesen, nie als finales FAILED verbucht.

## ADR-010 — Der Mensch hat das letzte Wort
Weichen die App-Labels vom letzten Stand des Programms ab oder sind sie beim Erstkontakt schon vorhanden, wird die Nachricht nicht mehr angefasst (`SKIPPED_HUMAN_OVERRIDE`).

## ADR-011 — Transport-Allow-List als dritte Barriere
Policy und Adapter schützen nur Code, der durch `GmailClient` geht. `GuardedHttp` prüft deshalb jeden HTTP-Request (Methode, Host, Pfad, Body). Der statische Scan verhindert neue Transporte außerhalb von Adapter und Auth.

## ADR-012 — Undo als Alles-oder-nichts
Preflight vor der ersten Änderung. Scheitert ein Schritt mitten im Lauf, werden die bereits zurückgesetzten Nachrichten kompensiert. Nur wenn auch das scheitert: `PARTIAL` mit genauer Liste.

## ADR-013 — Eingebauter Geld-/Zugangsdaten-Guard
Zahlungs-, Konto- und Passwort-Wörter verhindern ein automatisches ACTION samt Entwurf. Der Guard ist nicht konfigurierbar und prüft den gesamten Inhalt (alle MIME-Teile, zitiert, versteckt). Ein Fehlalarm kostet nur ein REVIEW.
