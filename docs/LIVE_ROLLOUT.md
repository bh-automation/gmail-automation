# Gestufter Livetest mit dem echten Gmail-Konto

Ziel: Den Release Candidate ohne Risiko gegen das echte Postfach prüfen. Danach steht die Freigabe für `v1.0.0` an.
Grundregel: **pro Stufe genau eine neue Fähigkeit**, nur auf drei eigene Testmails. Erst wenn alle Kriterien einer Stufe erfüllt sind, geht es zur nächsten Stufe.

Dauer: etwa 60–90 Minuten. Alle Befehle laufen in PowerShell im Projektordner.

```powershell
function ga { & .\.venv\Scripts\python.exe -m src.cli @args }   # Abkürzung nur für diese Sitzung
```

## Abbruchkriterien (gelten für jede Stufe)

| Beobachtung | Sofort tun |
|---|---|
| Im Ordner **Gesendet** taucht etwas auf, das Sie nicht selbst gesendet haben | Stopp. Google-Konto → Sicherheit → *Drittanbieter-Apps mit Kontozugriff* → Zugriff der App entfernen. Den Ordner `%LOCALAPPDATA%\GmailAutomation\logs` sichern. |
| Eine Mail außerhalb der Testmails bekommt ein `JARVIS/`-Label | Stopp, dann `ga undo --last-run` (Vorschau) und `ga undo --last-run --apply` |
| `STATUS` ist nicht `OK`, oder `AUDIT` ist nicht `PASS` | Stopp, Ausgabe aufheben, nicht weitermachen |

## Stufe 0 – Vorbereitung

1. Google Cloud einrichten und `client_secret.json` ablegen (README, Schnellstart Schritt 2).
2. Von einer **zweiten eigenen Adresse** (z. B. GMX) drei Testmails an das Gmail-Konto senden:

   | Betreff | Text | Erwartung |
   |---|---|---|
   | `GATEST Vertrag` | `Hallo, bitte unterschreiben Sie den Vertrag.` | ACTION 0.86 |
   | `GATEST Zahlung` | `Bitte die Zahlung bestätigen.` | REVIEW 0.70 (Geld-Regel) |
   | `GATEST Hallo` | `Nur ein kurzer Test.` | REVIEW 0.00, keine Änderung |

3. In `config/rules.yaml` den Bereich auf die Testmails begrenzen und alle Fähigkeiten ausgeschaltet lassen:

   ```yaml
   gmail_query: "in:inbox subject:GATEST newer_than:2d"
   capabilities:
     labels: false
     drafts: false
   ```

4. `ga config-check` → `CONFIG = PASS`

## Stufe 1 – OBSERVE (nur lesen)

```powershell
ga auth --profile observe      # Browser: Google fragt nur "E-Mails ansehen" an
ga doctor --online
ga scan
```

**Bestanden, wenn:**
- `doctor`: alle Zeilen `PASS`, `OAUTH TOKENS = PASS  observe: scopes ok`
- `scan` zeigt genau die drei Testmails: `[ACTION 0.86] … (signature-request)`, `[REVIEW 0.70] … (money-always-review)`, `[REVIEW 0.00] … (builtin:no-match)`
- `MODE = DRY-RUN`, `MUTATIONS = 0`, `SEND_BLOCK = PASS`, `DELETE_BLOCK = PASS`, `AUDIT = PASS`
- Zeigt `GATEST Vertrag` stattdessen `[REVIEW 0.75] … (builtin:money-guard)`, enthält die Mail Zahlungs- oder Passwort-Wörter, oft in einer Signatur oder einem Werbe-Footer. Dann die Testmail ohne Signatur und als reinen Text erneut senden.

**Echte Mails prüfen, weiterhin nur lesend:** In `rules.yaml` vorübergehend `gmail_query: "in:inbox newer_than:7d"` eintragen und `ga scan --max 50` ausführen. Die Einordnung querlesen und die Regeln bei Bedarf anpassen. Danach die Abfrage wieder auf `GATEST` setzen.

## Stufe 2 – APPLY-Berechtigung

```powershell
ga auth --profile apply        # zweite Zustimmung: gmail.modify + gmail.labels
ga doctor --online
```

**Bestanden, wenn:** `OAUTH TOKENS = PASS  observe: scopes ok; apply: scopes ok`.

Hinweis: `gmail.modify` würde auf Google-Seite auch Senden erlauben. GMAIL-AUTOMATION sperrt das in der Anwendung (siehe `SECURITY_MODEL.md`). Prüfen Sie deshalb in jeder Stufe den Ordner **Gesendet**.

## Stufe 3 – genau ein kontrollierter Label-Lauf

In `rules.yaml`: `labels: true`, `drafts: false`.

```powershell
ga run                          # erst die Vorschau (DRY-RUN): Plan prüfen
ga run --apply --max 5
ga status
```

**Bestanden, wenn:**
- `GATEST Vertrag` trägt `JARVIS/ACTION`, `GATEST Zahlung` trägt `JARVIS/REVIEW`, `GATEST Hallo` ist unverändert
- keine andere Mail hat ein `JARVIS/`-Label; **Gesendet** ist unverändert; es gibt keinen neuen Entwurf
- `STATUS = OK`, `AUDIT = PASS`, `OFFENE AKTIONEN = 0`

## Stufe 4 – Idempotenz

```powershell
ga run --apply --max 5
```

**Bestanden, wenn:** `MUTATIONS = 0` – es wird nichts doppelt gesetzt.

## Stufe 5 – Undo

```powershell
ga undo --last-run              # Vorschau: welche Labels zurückgesetzt würden
ga undo --last-run --apply
ga status
```

**Bestanden, wenn:** `UNDO = DONE`, beide `JARVIS/`-Labels sind von den Mails wieder weg, die Mails liegen unverändert im Posteingang, `AUDIT = PASS`. Die in Stufe 3 angelegten Labels selbst bleiben in der Label-Liste bestehen (Undo löscht keine Labels).

## Stufe 6 – genau ein kontrollierter Entwurf

1. Eine **neue** Testmail senden: Betreff `GATEST2 Vertrag`, Text `Hallo, bitte unterschreiben Sie den Vertrag.`
2. In `rules.yaml`: `gmail_query: "in:inbox subject:GATEST2 newer_than:2d"` und `drafts: true`.
   Der eigene Suchbegriff ist wichtig: Die Mails aus Stufe 0 sollen nicht im Bereich liegen. Sonst würde für die zurückgesetzte `GATEST Vertrag` jetzt ebenfalls ein Entwurf entstehen, denn „Entwurf anlegen“ ist eine eigene, dort noch nie ausgeführte Aktion.

```powershell
ga run --apply --max 5
ga run --apply --max 5          # zweiter Lauf: darf keinen zweiten Entwurf anlegen
ga status
```

**Bestanden, wenn:**
- In Gmail unter **Entwürfe** liegt genau **ein** Entwurf: Antwort im Thread `GATEST2 Vertrag`, Empfänger ist die Absenderadresse der Testmail, Text = Vorlage `ack_received`
- **Gesendet** ist unverändert, und an der zweiten Adresse ist **nichts** angekommen
- der zweite Lauf meldet keine neue Änderung (doppelter Entwurf verhindert)

## Stufe 7 – Abschluss

```powershell
ga audit-verify                 # AUDIT = PASS
```

1. Den Testentwurf und die Testmails in Gmail **von Hand** löschen (das Programm löscht nie).
2. In `rules.yaml` die gewünschte Produktionsabfrage eintragen, z. B. `"in:inbox newer_than:30d"`. Die Fähigkeiten bewusst wählen; empfohlen ist zunächst nur `labels: true`.
3. Wenn alle Stufen bestanden sind: Freigabe `v1.0.0` (siehe unten).

## BONUS – Vorrang des Menschen

An einer `JARVIS/`-markierten Testmail das Label von Hand ändern. Danach `ga run --apply` ausführen. Erwartung: `MANUELL_GEAENDERT = 1`, und das Programm setzt nichts zurück.

## Freigabe v1.0.0 (nach bestandenem Livetest)

```powershell
# Version in pyproject.toml und src/__init__.py auf 1.0.0 setzen, CHANGELOG-Eintrag ergänzen, committen, dann:
.\.venv\Scripts\python.exe -m pytest -q
git status --porcelain          # muss leer sein (G16)
git tag -a v1.0.0 -m "GMAIL-AUTOMATION 1.0.0 - Livetest bestanden"
```
