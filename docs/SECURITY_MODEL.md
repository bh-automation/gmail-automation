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
