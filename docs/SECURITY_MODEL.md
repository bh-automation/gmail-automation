# Security Model

## Safety kernel
All state-changing actions pass through a central policy function. The kernel accepts only typed actions and denies unknown actions.

## OAuth strategy
- Never request `https://mail.google.com/`.
- Start with a read-only Observe profile.
- Require explicit re-authorization when moving to an Apply profile.
- Validate granted scopes at runtime and refuse unexpected privilege.
- Store OAuth material outside the repository.

## Code-level controls
- `ALLOW_SEND = False` compiled/configured as an invariant.
- `ALLOW_PERMANENT_DELETE = False`.
- Gmail client wrapper contains no public send/delete functions.
- Static test scans source for forbidden client method names.
- Runtime policy rejects SEND/DELETE action types.

## Data minimization
Audit message IDs, thread IDs, hashes and action metadata rather than full bodies. Console output should truncate subjects and mask addresses in non-debug mode.

## LLM isolation
The LLM, if enabled, receives minimized content and outputs structured classification only. It receives no Gmail credentials and no executor handle.

## Umsetzung in V1 (1.0.0rc1)

Vier unabhängige Barrieren zwischen Code und einer gefährlichen Gmail-Operation:

1. **Policy-Kernel** (`src/policy.py`): typisierte Aktionen, unbekannte werden abgelehnt; SEND/DRAFT_SEND/PERMANENT_DELETE/TRASH/FORWARD/FILTER/SETTINGS sind immer verboten. Änderungen brauchen das APPLY-Profil, das explizite `--apply` und die Fähigkeit aus der Konfiguration (Undo: nur APPLY und `--apply`).
2. **Adapter-Allow-List** (`_GuardedResource` in `src/gmail_client.py`): Jeder Attributzugriff auf den googleapiclient-Service wird gegen die Endpunktliste des Profils geprüft, bevor ein Request entsteht.
3. **Transport-Allow-List** (`GuardedHttp`): Methode, Host, Pfad und Body jedes ausgehenden HTTP-Requests. Erlaubt sind nur `Label_<n>`-IDs in modify-Bodies und threadgebundene Entwürfe. Kein Redirect, kein Method-Override. Der Refresh-Transport erreicht nur den OAuth-Token-Endpunkt.
4. **Statischer Gate-Scan** (`tools/forbidden_scan.py`, CI und `verify.ps1`): verbietet verbotene Methodennamen, Reflection, Transport- und Credential-Importe außerhalb von Adapter und Auth sowie Re-Importe und Aliasing.

Vertrauensannahme: Das sind Kontrollen im selben Prozess. Bösartiger Code im selben Interpreter ist ein dokumentiertes Restrisiko (R-1 in `RELEASE_GATES.md`).
