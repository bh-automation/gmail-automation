# Architecture

## Design goal
A capability-oriented Gmail automation with strict separation between observation, decision and execution.

## Planes

### 1. Identity plane
OAuth profiles, scope validation, token storage outside Git, explicit re-auth when privilege changes.

### 2. Ingestion plane
Gmail query -> message metadata -> MIME normalization -> content fingerprint.

### 3. Decision plane
Rules classifier -> confidence -> policy engine -> proposed action plan.

### 4. Execution plane
A narrow Gmail adapter exposes only approved V1 mutations. Forbidden operations do not exist in the public adapter surface.

### 5. Evidence plane
SQLite audit ledger, run IDs, before/after state, outcome, error codes and integrity checks.

### 6. Recovery plane
Idempotency and conflict-aware undo.

## Trust boundaries
- Google OAuth/token boundary
- Gmail API boundary
- untrusted message-content boundary
- optional LLM boundary
- local operator boundary
- Git/CI boundary

## Key design decision
Do not give the classifier direct Gmail mutation capabilities. It returns a typed `ActionPlan`; the policy engine validates that plan; only then can the executor invoke an allow-listed adapter method.
