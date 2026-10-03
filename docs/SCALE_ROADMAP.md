# Scale Roadmap

| Stage | Capability | Gate to enter | Primary risk |
|---|---|---|---|
| S0 | Offline fixtures only | unit tests green | false confidence |
| S1 | Observe/read-only | OAuth read-only validated | privacy/logging |
| S2 | Dry-run production mailbox | zero mutations verified | classification quality |
| S3 | Controlled label apply | explicit `--apply`, undo green | unintended mutation |
| S4 | Draft creation | duplicate protection + send hard-block | accidental send |
| S5 | Optional LLM assist | prompt-injection suite green | instruction hijack |
| S6 | Scheduled local runs | crash recovery + single-instance lock | repeated actions |
| S7 | Gmail push/Pub/Sub | operational runbook + watch renewal | event loss/duplication |
| S8 | Multi-account | strict tenant/token isolation | cross-account leakage |
| S9 | Signed releases | CI provenance + changelog | supply-chain drift |

## Scale principles
- Prefer replayable event/audit records over hidden state.
- Every privilege increase requires a new gate.
- Performance optimizations never weaken idempotency.
- Human review remains first-class; REVIEW is a valid successful outcome.
