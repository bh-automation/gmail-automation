"""Draft creation only. Sending is impossible in V1 (policy + adapter hard block).

Drafts use static operator templates. No message content is copied into a draft body,
and header values from untrusted mail are validated against header injection.
"""

from __future__ import annotations

import base64
import re
from email.message import EmailMessage

from .errors import PolicyViolation
from .gmail_client import GmailClient
from .models import NormalizedMessage

KEY_HEADER = "X-Gmail-Automation-Key"
_MSGID_RE = re.compile(r"<[^<>\s\r\n]{3,250}>")
_ADDR_RE = re.compile(r"[^@\s<>\"\r\n,;]{1,64}@[A-Za-z0-9.\-]{1,253}")


def _safe_subject(subject: str) -> str:
    s = re.sub(r"[\r\n\x00-\x1f\x7f]", " ", subject).strip()[:200]
    return s if re.match(r"(?i)^(re|aw):", s) else f"Re: {s}" if s else "Re:"


def build_reply_raw(msg: NormalizedMessage, template_text: str, idempotency_key: str) -> str:
    to = msg.reply_to or msg.from_address
    if not to or not _ADDR_RE.fullmatch(to):
        raise PolicyViolation("Draft recipient is missing or unsafe", code="DRAFT_RECIPIENT_INVALID")
    em = EmailMessage()
    em["To"] = to
    em["Subject"] = _safe_subject(msg.subject)
    if _MSGID_RE.fullmatch(msg.message_id_header or ""):
        em["In-Reply-To"] = msg.message_id_header
        refs = " ".join(r for r in (msg.references or "").split() if _MSGID_RE.fullmatch(r))[:900]
        em["References"] = (refs + " " + msg.message_id_header).strip()
    em[KEY_HEADER] = idempotency_key
    em.set_content(template_text)
    return base64.urlsafe_b64encode(em.as_bytes()).decode("ascii")


def drafts_in_thread(client: GmailClient, thread_id: str) -> list[str]:
    out = []
    for d in client.list_drafts(max_results=500):
        message = d.get("message") or {}
        if str(message.get("threadId", "")) == thread_id and d.get("id"):
            out.append(str(d["id"]))
    return out


def find_draft_with_key(client: GmailClient, thread_id: str, key: str) -> str | None:
    for draft_id in drafts_in_thread(client, thread_id):
        value = client.get_draft_headers(draft_id).get(KEY_HEADER.lower(), "")
        if "".join(value.split()) == key:  # header may be folded in transit
            return draft_id
    return None
