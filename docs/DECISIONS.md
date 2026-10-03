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
