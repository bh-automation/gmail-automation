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
