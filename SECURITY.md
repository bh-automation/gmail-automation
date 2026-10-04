# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | yes |
| < 1.0 (release candidates) | no |

## Reporting a vulnerability

Please **do not open a public issue** for security problems.
Use GitHub's private vulnerability reporting for this repository (*Security → Report a vulnerability*).
If that is not available, open a minimal public issue that only asks for a private contact channel – without technical details.

Please include: affected version/commit, steps to reproduce, expected vs. actual behaviour, and the impact you see.
Never include real mail content, OAuth tokens, `client_secret.json` or other credentials in a report.

## Scope

In scope: anything that could make GMAIL-AUTOMATION
- send, forward or permanently delete mail,
- request a broader OAuth scope than documented in `docs/OAUTH_SCOPE_MATRIX.md`,
- let mail content (including hidden HTML) change rules or trigger actions,
- bypass the audit log, the undo conflict check or the fail-closed behaviour,
- leak tokens or secrets into the project folder, logs or reports.

Out of scope: weaknesses of Google's OAuth platform itself and attacks that require an already compromised Windows user account.

## Design notes

The security model and threat model are documented in `docs/SECURITY_MODEL.md` and `docs/THREAT_MODEL.md`.
Default mode is DRY-RUN; mailbox changes require `--apply`, the APPLY OAuth profile and an explicitly enabled capability in `config/rules.yaml`.
