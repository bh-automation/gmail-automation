# Threat Model

## Assets
OAuth tokens, mailbox contents, drafts, labels, audit DB, rules config, Git history and operator trust.

## Main threats
1. Hostile email prompt injection.
2. OAuth scope overreach.
3. Accidental auto-send.
4. Permanent deletion.
5. Duplicate processing.
6. Race between scan and apply.
7. Secret leakage into Git/logs.
8. Cross-thread misclassification.
9. Undo against changed state.
10. LLM hallucinating facts in drafts.
11. API retries duplicating side effects.
12. Compromised dependency or CI artifact.

## Controls
Capability allow-list, dry-run default, separate profiles, idempotency keys, before/after checks, redaction, CI static scans, mocked integration tests and release gates.
