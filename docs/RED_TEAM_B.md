# Red Team B — Reliability, Recovery & Operations

Release rule: any unresolved Critical/High issue blocks release.

## Attack matrix
- [ ] Process crashes after Gmail mutation but before audit completion.
- [ ] Process crashes after audit prepare but before Gmail mutation.
- [ ] Two instances start simultaneously.
- [ ] Same Gmail event appears twice.
- [ ] Thread receives new message between scan and apply.
- [ ] Labels changed manually before undo.
- [ ] Draft manually edited before automated reconciliation.
- [ ] SQLite locked/corrupt/unwritable.
- [ ] Network fails mid-page.
- [ ] 401 refresh path loops.
- [ ] 403 scope mismatch.
- [ ] 429 burst with Retry-After.
- [ ] 5xx transient failure.
- [ ] Clock/timezone variation.
- [ ] Windows path contains spaces/non-ASCII.
- [ ] Config missing, malformed or partially upgraded.
- [ ] Migration interrupted halfway.
- [ ] CI passes while forbidden method exists in generated code.
- [ ] Dependency update changes Gmail client behavior.
- [ ] Run with zero messages.
- [ ] Run with 50k candidate messages and pagination.
- [ ] Thread with 100+ replies.
- [ ] HTML-only and empty-body messages.
- [ ] Single message belongs to multiple user labels.
- [ ] Undo requested for non-latest run.
- [ ] Audit DB copied/restored from stale backup.
- [ ] Watch/PubSub event duplicated or arrives out of order (future stage).
- [ ] Watch expires silently (future stage).

## Required evidence
For every item: reproduction, expected invariant, observed result, fix/mitigation and regression test.
