# GMAIL-AUTOMATION

Lokale, abgesicherte Gmail-Automatisierung für Windows: **lesen → klassifizieren → Labels setzen → Antwort-Entwürfe anlegen** – mit Audit und Undo.

> **English summary:** Local, hardened Gmail automation for Windows (Python). It reads and classifies mail, can set labels and create reply *drafts* – never sends, never deletes. Default is DRY-RUN; every change is audited (write-ahead log, hash chain) and can be undone with a conflict check. Separate OAuth profiles (`gmail.readonly` for scans; `gmail.modify` only for APPLY – sending and deleting are blocked by the application, not by Google), mail content is treated as untrusted data, failures stop the run (fail closed). Tested on Ubuntu and Windows (PowerShell 5.1 and 7). See [SECURITY.md](SECURITY.md) and the docs below.

Standard ist immer **DRY-RUN**: Das Programm zeigt nur an, was es tun würde. Änderungen am Postfach brauchen drei Dinge gleichzeitig: das CLI-Flag `--apply`, das OAuth-Profil **APPLY** und eine eingeschaltete Fähigkeit in `config/rules.yaml`.

## Sicherheitszusagen (V1, in der Anwendung erzwungen)

| Zusage | Wie sie erzwungen wird |
|---|---|
| Kein automatisches Senden | Policy-Kernel, Adapter-Allow-List, HTTP-Transport-Allow-List, statischer Gate-Scan |
| Kein endgültiges Löschen, kein Papierkorb | wie oben; System-Labels (TRASH, SPAM, INBOX …) werden auch im Request-Body abgewiesen |
| Kein Vollzugriffs-Scope `https://mail.google.com/` | Scope-Prüfung gegen Googles eigene Token-Antwort; alles Unerwartete wird abgelehnt |
| Mail-Inhalt ist nur Daten | Regeln kommen nur aus der Konfiguration; versteckter HTML-Text steuert keine Regel; Geld-/Passwort-Wörter erzwingen REVIEW |
| Jede Änderung protokolliert | Write-ahead-Audit (PREPARE → Änderung → Prüfung → APPLIED), Hash-Kette, Rollback-Anker außerhalb des Datenordners |
| Undo mit Konfliktprüfung | ändert nichts, wenn sich das Postfach seitdem geändert hat; scheitert ein Schritt, wird alles zurückgerollt |
| Unsicher → REVIEW | Konfidenz unter 0,85 führt nie zu einer riskanten Aktion; unter 0,60 gibt es gar keine Änderung |
| Fehler → Stopp | globale Fehler beenden den Lauf („fail closed“); nur eine einzelne abgelehnte Nachricht wird übersprungen und nach 3 Fehlern in Quarantäne gestellt |
| Der Mensch hat das letzte Wort | ändert jemand die App-Labels von Hand, fasst das Programm diese Nachricht nicht mehr an |

**Wichtig zur OAuth-Berechtigung:** Für Labels und Entwürfe verlangt Google den Scope `gmail.modify`. Dieser Scope würde auf Google-Seite auch Lesen, Verfassen und **Senden** erlauben; nur das sofortige endgültige Löschen erlaubt er nicht. Die Zusagen oben sind deshalb Sperren **der Anwendung**: GMAIL-AUTOMATION v1 bietet keinen Weg zum Senden oder Löschen und lässt keinen solchen HTTP-Endpunkt durch (Policy, Adapter, Transport-Allow-List). Der APPLY-Token selbst ist ein schützenswertes Geheimnis: Er liegt nur in `%LOCALAPPDATA%\GmailAutomation\` und lässt sich im Google-Konto jederzeit widerrufen (Sicherheit → *Drittanbieter-Apps mit Kontozugriff*). Für reine Scans reicht das Profil OBSERVE.

## Schnellstart (Windows)

**Voraussetzung:** Python 3.12 oder 3.13 von python.org. Das Projekt in einen kurzen Pfad entpacken, z. B. `C:\Tools\GMAIL-AUTOMATION` (Windows-Pfadlimit).

1. **Starten:** `START_GMAIL_AUTOMATION.cmd` doppelklicken. Beim ersten Start wird die Umgebung `.venv` angelegt. Ein abgebrochenes oder veraltetes Setup wird automatisch repariert.
2. **Google Cloud einrichten (einmalig, manuell):**
   1. In der [Google Cloud Console](https://console.cloud.google.com/) ein Projekt anlegen.
   2. **Gmail API** aktivieren.
   3. **OAuth-Zustimmungsbildschirm** einrichten: Nutzertyp *Extern*, Status *Testing*, die eigene Gmail-Adresse als Testnutzer eintragen.
   4. **Anmeldedaten → OAuth-Client-ID → Desktop-App** anlegen und die JSON-Datei herunterladen.
   5. Die Datei als `client_secret.json` speichern unter `%LOCALAPPDATA%\GmailAutomation\`. Menüpunkt **[1] Doctor** zeigt den genauen Ordner. Die Datei darf **nie** in den Projektordner.
3. **Anmelden (nur lesen):** Menü **[4] Anmelden**. Im Browser bei Google zustimmen; angefragt wird nur `gmail.readonly`.
4. **Prüfen:** Menü **[1] Doctor**. Alle Zeilen sollten `PASS` zeigen.
5. **Probelauf:** Menü **[2] Scan**. Er liest und klassifiziert die Mails und zeigt den Plan, ändert aber nichts. Danach die Regeln in `config/rules.yaml` anpassen und mit `python -m src.cli config-check` prüfen.

### Änderungen bewusst einschalten (APPLY)

Erst wenn der Scan so aussieht, wie Sie es wollen:

```powershell
# 1. In config/rules.yaml: capabilities: labels: true   (Entwürfe zusätzlich: drafts: true)
.venv\Scripts\python.exe -m src.cli auth --profile apply        # zweite Zustimmung: gmail.modify + gmail.labels
.venv\Scripts\python.exe -m src.cli run --apply --max 20         # klein anfangen
.venv\Scripts\python.exe -m src.cli status                       # Läufe, offene Aktionen, Quarantäne
.venv\Scripts\python.exe -m src.cli undo --last-run              # Vorschau
.venv\Scripts\python.exe -m src.cli undo --last-run --apply      # zurücksetzen
```

Das Programm sendet Entwürfe nie und löscht sie nie automatisch; Undo listet sie nur zum manuellen Prüfen auf. Vor dem ersten APPLY auf das ganze Postfach den [gestuften Livetest](docs/LIVE_ROLLOUT.md) durchlaufen.

**Hinweis zum Testing-Modus:** Laut Google-Dokumentation laufen Refresh-Tokens von OAuth-Apps im Status *Testing* (Nutzertyp *Extern*) nach **7 Tagen** ab. Danach meldet das Programm `REFRESH_FAILED`. Dann einfach `auth --profile observe` bzw. `auth --profile apply` erneut ausführen.

## Befehle

| Befehl | Zweck | Ändert das Postfach? |
|---|---|---|
| `doctor [--online]` | Umgebung, Konfiguration, Sperren, Audit, Tokens prüfen | nein |
| `auth --profile observe\|apply` | Google-Anmeldung je Profil (Browser) | nein |
| `scan [--max N]` | lesen + klassifizieren (immer DRY-RUN) | nein |
| `run [--apply] [--max N] [--retry-quarantined]` | Lauf; ohne `--apply` DRY-RUN | nur mit `--apply` |
| `status [--runs N]` | letzte Läufe, Audit-Integrität, offene Aktionen, Quarantäne | nein |
| `undo --last-run\|--run-id ID [--apply]` | Lauf zurücksetzen; ohne `--apply` nur Vorschau | nur mit `--apply` |
| `config-check [--config DATEI]` | Konfiguration validieren | nein |
| `audit-verify` | Hash-Kette und Rollback-Anker prüfen | nein |
| `audit-rebaseline [--confirm …]` | Anker nach Prüfung neu setzen (protokolliert) | nein |

Alle Befehle: `.venv\Scripts\python.exe -m src.cli <befehl>`. `--apply` lässt sich nicht abkürzen.

### Exit-Codes (für Aufgabenplanung / Monitoring)

| Code | Bedeutung |
|---|---|
| 0 | OK |
| 2 | Policy- oder Konfigurationsfehler (auch: Vorschau von `audit-rebaseline`) |
| 3 | Anmeldung / Scope-Problem |
| 4 | Undo-Konflikt – das Postfach bleibt unverändert |
| 5 | Audit nicht verfügbar oder Integritätsfehler |
| 6 | Zweite Instanz läuft oder Lock nicht schreibbar |
| 7 | Gmail-API-Fehler |
| 8 | Lauf gestoppt (fail closed) / Undo vollständig zurückgerollt |
| 9 | Teilweise: einzelne Nachrichten fehlgeschlagen, in Quarantäne oder mit Abweichung |
| 10 | Unerwarteter interner Fehler (gestoppt, ohne Traceback) |
| 130 | Abbruch mit Strg+C (offene Aktionen gleicht der nächste APPLY-Lauf ab) |

## Wo liegt was?

| Inhalt | Ort |
|---|---|
| Programm, Regeln (`config/rules.yaml`) | Projektordner |
| `client_secret.json`, Tokens, `audit.sqlite3`, Logs | `%LOCALAPPDATA%\GmailAutomation\` |
| Rollback-Anker | `%APPDATA%\GmailAutomation\anchors\` (bewusst getrennt vom Datenordner) |

Wird ein **altes Backup** des Datenordners zurückgespielt, verweigert das Programm den Start (`AUDIT_ROLLBACK`). So werden Ihre seitherigen manuellen Entscheidungen nicht überschrieben. Nach bewusster Prüfung: `audit-rebaseline --confirm --accept-rollback`.

## Wenn etwas nicht klappt

| Meldung | Bedeutung → was tun |
|---|---|
| `client_secret fehlt` | Schritt 2 oben |
| `REFRESH_FAILED` | Token abgelaufen oder widerrufen → `auth --profile …` erneut ausführen |
| `MISSING_SCOPE` / `UNEXPECTED_SCOPE` / `FORBIDDEN_SCOPE` | Bei der Zustimmung wurden falsche Rechte erteilt → App-Zugriff im Google-Konto entfernen, `auth` erneut |
| `LOCKED` | Ein anderer Lauf ist aktiv → warten |
| `AUDIT_LOCKED` | Ein anderes Programm (DB-Viewer, Backup, Virenscanner) hält die Audit-DB → schließen, erneut versuchen |
| `AUDIT_ANCHOR_MISSING` / `AUDIT_HEAD_CORRUPT` | Anker fehlt oder ist beschädigt → `audit-rebaseline` (Vorschau), dann `--confirm` |
| `AUDIT_ROLLBACK` | Ein älteres Audit wurde eingespielt → prüfen; nur bewusst `--accept-rollback` |
| `STATUS = PARTIAL` | Einzelne Nachrichten sind fehlgeschlagen oder in Quarantäne → `status`, ggf. `run --apply --retry-quarantined` |
| `UNDO = CONFLICT … LATER_RUN` | Ein späterer Lauf hat dieselbe Nachricht geändert → zuerst den neueren Lauf zurücksetzen |
| `UNDO = CONFLICT … STATE_DRIFT` | Die Nachricht wurde seitdem geändert → das Postfach bleibt, wie es ist (gewollt) |

## Prüfen und Entwickeln

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify.ps1   # alle Release-Gates offline
```

Die Tests brauchen kein Gmail-Konto und keine Secrets. CI läuft auf Ubuntu und Windows mit Python 3.12 und 3.13. Ein eigener Windows-Job führt `bootstrap.ps1` und `verify.ps1` in Windows PowerShell 5.1 und in PowerShell 7 aus.

## Dokumentation

- [Gestufter Livetest mit dem echten Gmail-Konto](docs/LIVE_ROLLOUT.md)
- [Release-Gates G1–G16 und Restrisiken](docs/RELEASE_GATES.md)
- [Bedrohungsmodell](docs/THREAT_MODEL.md) · [Sicherheitsmodell](docs/SECURITY_MODEL.md) · [Architektur](docs/ARCHITECTURE.md) · [OAuth-Scope-Matrix](docs/OAUTH_SCOPE_MATRIX.md)
- Red-Team-Berichte: [A – Angriffe auf das Produkt](docs/RED_TEAM_A_REPORT.md) · [B – Betrieb und Zuverlässigkeit](docs/RED_TEAM_B_REPORT.md) · [C – Prüfung der Fixes](docs/RED_TEAM_C_FIX_VERIFICATION.md)
- [Änderungen](CHANGELOG.md) · [Sicherheitsrichtlinie / Security Policy](SECURITY.md)
