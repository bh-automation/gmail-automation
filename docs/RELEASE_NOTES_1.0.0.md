# GMAIL-AUTOMATION 1.0.0

Lokale, abgesicherte Gmail-Automatisierung für Windows: lesen → klassifizieren → App-Labels → Antwort-Entwürfe, mit Audit und Undo. Standard ist DRY-RUN.

## Was 1.0.0 garantiert
- Senden, Entwurf-Senden, endgültiges Löschen und Papierkorb sind in der Anwendung gesperrt (Policy-Kernel, Adapter- und Transport-Allow-List). Hinweis: `gmail.modify` würde bei Google Senden erlauben; die Sperre liegt in der Anwendung.
- Zwei getrennte OAuth-Profile: OBSERVE (`gmail.readonly`) und APPLY (`gmail.modify` + `gmail.labels`). Vollzugriff wird abgelehnt.
- Änderungen nur mit `--apply` **und** eingeschalteter Capability, nur `JARVIS/`-Labels, nur ab Confidence 0.85.
- Write-ahead-Audit mit Hash-Kette und Rollback-Anker; Undo mit Konflikterkennung; ein Undo wird respektiert (kein erneutes Anwenden).
- Entwürfe nur aus festen Vorlagen; Duplikatschutz pro Thread.

## Neu gegenüber rc3
- Vorlage `ack_received` ohne Zusage: „Vielen Dank, ich habe Ihre Nachricht erhalten.“

## Upgrade
`config/rules.yaml` ist eine lokale Kopie. Wer die alte Vorlage übernommen hat, ersetzt die Zeile „…melde mich zeitnah.“ durch den neuen Satz.

## Nachweise
`docs/RELEASE_EVIDENCE_1.0.0.md` · `docs/LIVE_ROLLOUT.md` · `CHANGELOG.md`
