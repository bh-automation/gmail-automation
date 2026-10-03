# OAuth / Capability Matrix

| Capability | Observe | Controlled Apply | Notes |
|---|---:|---:|---|
| Read metadata/content | yes | yes | minimize scope where feasible |
| Search/list messages | yes | yes | Gmail query syntax |
| Create/manage app labels | no | yes | explicit apply profile |
| Apply/remove labels | no | yes | audited + undoable |
| Create drafts | no | optional | send remains hard-blocked |
| Send messages/drafts | **NO** | **NO** | code-level hard block |
| Permanent delete | **NO** | **NO** | full-mail scope forbidden |
| Forwarding/settings mutation | **NO** | **NO** | outside V1 surface |

Runtime must validate the granted scopes and reject unexpected broad privilege.

## Umsetzung (1.0.0rc1)

| Profil | Angefragte Scopes | Erlaubt bei der Prüfung | Verboten (sofortiger Abbruch) |
|---|---|---|---|
| OBSERVE | `gmail.readonly` | `gmail.readonly` | `https://mail.google.com/`, `gmail.send`, `gmail.insert`, `gmail.settings.basic`, `gmail.settings.sharing`, jeder unerwartete Scope |
| APPLY | `gmail.modify`, `gmail.labels` | `gmail.modify`, `gmail.labels`, `gmail.readonly` | wie oben |

Laut Google erlaubt `gmail.modify` alle Lese- und Schreibvorgänge, also auch Verfassen, **Senden** und Papierkorb, ausgenommen nur das sofortige endgültige Löschen. Google verlangt diesen Scope für das Ändern von Labels an Nachrichten; für Entwürfe genügt alternativ `gmail.compose`, das ebenfalls senden darf. Deshalb sperrt V1 Senden und Löschen in vier unabhängigen Schichten **in der Anwendung** (siehe `SECURITY_MODEL.md`). Der Token selbst bleibt sendefähig, siehe Restrisiko R-14 in `RELEASE_GATES.md`. Die geprüften Scopes stammen aus Googles Token-Antwort (Refresh-Grant ohne Scope-Parameter), nicht aus der lokalen Token-Datei.
