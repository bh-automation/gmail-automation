"""Draft creation only. Sending is impossible in V1 (policy + adapter + transport hard block).

Drafts use static operator templates. No message content is copied into a draft body,
and header values from untrusted mail are validated against header injection.
The recipient is always the From address; a Reply-To pointing to another domain is
ignored (an attacker must not be able to pre-address drafts to an address they control).
"""

from __future__ import annotations

import base64
import re
from email.errors import HeaderParseError
from email.message import EmailMessage

from .errors import PolicyViolation
from .gmail_client import GmailClient
from .models import NormalizedMessage

KEY_HEADER = "X-Gmail-Automation-Key"
_MSGID_RE = re.compile(r"<[^<>\s\r\n]{3,250}>")
_ADDR_RE = re.compile(r"[^@\s<>\"\r\n,;]{1,64}@[A-Za-z0-9.\-]{1,253}")
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def _single_line(value: str) -> str:
    """Collapse every str.splitlines() boundary (incl. U+2028/U+2029/NEL) and strip controls."""
    return _CTRL_RE.sub(" ", " ".join(value.splitlines())).strip()


def _safe_subject(subject: str) -> str:
    s = _single_line(subject)[:200]
    return s if re.match(r"(?i)^(re|aw):", s) else f"Re: {s}" if s else "Re:"


def _domain(addr: str) -> str:
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


def draft_recipient(msg: NormalizedMessage) -> str:
    """From address; Reply-To only when it stays inside the sender's own domain."""
    if msg.reply_to and msg.from_address and _domain(msg.reply_to) == _domain(msg.from_address):
        return msg.reply_to
    return msg.from_address


def build_reply_raw(msg: NormalizedMessage, template_text: str, idempotency_key: str) -> str:
    to = draft_recipient(msg)
    if not to or not _ADDR_RE.fullmatch(to):
        raise PolicyViolation("Draft recipient is missing or unsafe", code="DRAFT_RECIPIENT_INVALID")
    try:
        em = EmailMessage()
        em["To"] = to
        em["Subject"] = _safe_subject(msg.subject)
        if _MSGID_RE.fullmatch(msg.message_id_header or ""):
            em["In-Reply-To"] = msg.message_id_header
            refs = " ".join(r for r in (msg.references or "").split() if _MSGID_RE.fullmatch(r))[:900]
            em["References"] = (refs + " " + msg.message_id_header).strip()
        em[KEY_HEADER] = idempotency_key
        em.set_content(template_text)
        raw = em.as_bytes()
    except (ValueError, TypeError, HeaderParseError, UnicodeError):
        # The email package rejected a header built from untrusted input: skip the draft, never crash.
        raise PolicyViolation("Draft headers rejected by the email encoder", code="DRAFT_HEADER_INVALID") from None
    return base64.urlsafe_b64encode(raw).decode("ascii")


def drafts_in_thread(client: GmailClient, thread_id: str) -> list[str]:
    return [
        str(d["id"])
        for d in client.list_all_drafts()
        if str((d.get("message") or {}).get("threadId", "")) == thread_id and d.get("id")
    ]


def find_draft_with_key(client: GmailClient, thread_id: str, key: str) -> str | None:
    for draft_id in drafts_in_thread(client, thread_id):
        value = client.get_draft_headers(draft_id).get(KEY_HEADER.lower(), "")
        if "".join(value.split()) == key:  # header may be folded in transit
            return draft_id
    return None
