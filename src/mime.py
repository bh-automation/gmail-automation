"""Safe, bounded parsing of Gmail API message payloads (text/plain, text/html, multipart).

Malformed input never raises out of `normalize_message`; it yields parse_errors so the
classifier can route the message to REVIEW.
"""

from __future__ import annotations

import base64
import binascii
import html
import re
from email.header import decode_header, make_header
from email.utils import parseaddr
from html.parser import HTMLParser
from typing import Any

from .models import NormalizedMessage
from .redaction import fingerprint

MAX_PARTS = 200
MAX_DEPTH = 20
_B64URL_RE = re.compile(r"[A-Za-z0-9_\-=\s]*")
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_KEEP_HEADERS = {
    "from",
    "reply-to",
    "subject",
    "message-id",
    "references",
    "in-reply-to",
    "date",
    "list-unsubscribe",
    "list-id",
    "auto-submitted",
    "precedence",
}
_REPLY_MARKERS = (
    re.compile(r"^\s*On .{1,200} wrote:\s*$", re.I),  # EN
    re.compile(r"^\s*Am .{1,200} schrieb .{0,200}:\s*$", re.I),  # DE
    re.compile(r"^\s*Le .{1,200} a (é|e)crit\s*:\s*$", re.I),  # FR
    re.compile(r"^\s*El .{1,200} escribi(ó|o)\s*:\s*$", re.I),  # ES
    re.compile(r"^\s*Il .{1,200} ha scritto\s*:\s*$", re.I),  # IT
    re.compile(r"^\s*Op .{1,200} schreef .{0,200}:\s*$", re.I),  # NL
    re.compile(r"^\s*Em .{1,200} escreveu\s*:\s*$", re.I),  # PT
    re.compile(
        r"^\s*-{2,}\s*(Original Message|Urspr(ü|ue)ngliche Nachricht|Forwarded message|Weitergeleitete Nachricht|"
        r"Message d.origine|Message transf(é|e)r(é|e)|Mensaje original|Mensaje reenviado|Messaggio originale|"
        r"Messaggio inoltrato|Oorspronkelijk bericht|Doorgestuurd bericht|Mensagem original|Mensagem encaminhada)"
        r"\s*-{2,}\s*$",
        re.I,
    ),
)
_OUTLOOK_HEADER = re.compile(r"^\s*\*?(From|Von|De|Da|Van)\s?:\*?\s.+$", re.I)
_OUTLOOK_FOLLOW = re.compile(
    r"^\s*\*?(Sent|Gesendet|Date|Datum|Envoy(é|e)|Enviado|Inviato|Verzonden|Fecha|Data)\s?:\*?\s.+$", re.I
)
# Inline styles that hide text from the human reader; hidden text never counts as content.
_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?![.\d]*[1-9])|opacity\s*:\s*0(?![.\d]*[1-9])",
    re.I,
)
_VOID_TAGS = frozenset({"br", "hr", "img", "meta", "link", "input", "area", "base", "col", "embed", "source", "wbr"})


class _MimeParseError(Exception):
    pass


def b64url_decode(data: str, max_bytes: int) -> bytes:
    if not isinstance(data, str) or not _B64URL_RE.fullmatch(data):
        raise _MimeParseError("BASE64_CHARSET")
    compact = re.sub(r"\s+", "", data)
    if len(compact) * 3 // 4 > max_bytes:
        raise _MimeParseError("BODY_TOO_LARGE")
    try:
        return base64.urlsafe_b64decode(compact + "=" * (-len(compact) % 4))
    except (binascii.Error, ValueError):
        raise _MimeParseError("BASE64_INVALID") from None


def decode_header_value(value: Any, max_len: int = 998) -> str:
    if not isinstance(value, str):
        return ""
    try:
        text = str(make_header(decode_header(value)))
    except Exception:  # noqa: BLE001 - RFC 2047 garbage must not crash the scan
        text = value
    # Every str.splitlines() boundary (CR, LF, VT, FF, FS/GS/RS, NEL, U+2028, U+2029) becomes a
    # space: the email package rejects any header value that splits into more than one line.
    text = " ".join(_CTRL_RE.sub(" ", text).splitlines())
    return text[:max_len].strip()


def _charset(headers: list[dict[str, Any]]) -> str:
    for h in headers or []:
        if str(h.get("name", "")).lower() == "content-type":
            m = re.search(r"charset\s*=\s*\"?([A-Za-z0-9_\-:.]+)", str(h.get("value", "")), re.I)
            if m:
                return m.group(1)
    return "utf-8"


def _decode_text(raw: bytes, charset: str) -> str:
    try:
        return raw.decode(charset, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


class _HtmlText(HTMLParser):
    _BLOCK = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "table", "blockquote", "hr"}
    _SKIP = {"script", "style", "head", "title", "noscript", "template"}

    def __init__(self, drop_quotes: bool) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.skip_depth = 0
        self.quote_depth = 0
        self.hidden_depth = 0
        self.drop_quotes = drop_quotes
        self.stack: list[tuple[str, bool, bool]] = []

    def _is_quote(self, tag: str, attrs: list[tuple[str, str | None]]) -> bool:
        if not self.drop_quotes:
            return False
        if tag == "blockquote":
            return True
        a = {k.lower(): (v or "") for k, v in attrs}
        cls = a.get("class", "").lower()
        ident = a.get("id", "").lower()
        return "gmail_quote" in cls or ident in {"divrplyfwdmsg", "appendonsend"} or "moz-cite-prefix" in cls

    @staticmethod
    def _is_hidden(attrs: list[tuple[str, str | None]]) -> bool:
        a = {k.lower(): (v or "") for k, v in attrs}
        return "hidden" in a or bool(_HIDDEN_STYLE.search(a.get("style", "")))

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self._SKIP:
            self.skip_depth += 1
        if tag not in _VOID_TAGS:
            quote = self._is_quote(tag, attrs)
            hidden = self._is_hidden(attrs)
            if quote:
                self.quote_depth += 1
            if hidden:
                self.hidden_depth += 1
            self.stack.append((tag, quote, hidden))
        if tag in self._BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP and self.skip_depth:
            self.skip_depth -= 1
        if any(t == tag for t, _, _ in self.stack):
            while self.stack:
                t, quote, hidden = self.stack.pop()
                if quote and self.quote_depth:
                    self.quote_depth -= 1
                if hidden and self.hidden_depth:
                    self.hidden_depth -= 1
                if t == tag:
                    break
        if tag in self._BLOCK:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self.skip_depth and not self.quote_depth and not self.hidden_depth:
            self.parts.append(data)


def html_to_text(markup: str, *, drop_quotes: bool = False) -> str:
    parser = _HtmlText(drop_quotes)
    try:
        parser.feed(markup)
        parser.close()
    except Exception:  # noqa: BLE001 - html.parser is lenient, but stay safe
        return re.sub(r"<[^>]+>", " ", html.unescape(markup))
    text = "".join(parser.parts)
    text = re.sub(r"[ \t ]+", " ", text)
    return re.sub(r"\n\s*\n+", "\n\n", text).strip()


def strip_quoted_text(text: str) -> str:
    """Keep only the newest message: drop '>' lines and everything after a reply marker."""
    lines = text.splitlines()
    out: list[str] = []
    for i, line in enumerate(lines):
        if any(p.match(line) for p in _REPLY_MARKERS):
            break
        if (
            _OUTLOOK_HEADER.match(line)
            and i + 1 < len(lines)
            and any(_OUTLOOK_FOLLOW.match(nxt) for nxt in lines[i + 1 : i + 4])
        ):
            break
        if line.lstrip().startswith(">"):
            continue
        out.append(line)
    return "\n".join(out).strip()


def _walk(payload: dict[str, Any], max_raw: int) -> tuple[list[str], list[str], list[str]]:
    plains: list[str] = []
    htmls: list[str] = []
    errors: list[str] = []
    stack: list[tuple[dict[str, Any], int]] = [(payload, 0)]
    seen = 0
    while stack:
        part, depth = stack.pop()
        seen += 1
        if seen > MAX_PARTS:
            errors.append("TOO_MANY_PARTS")
            break
        if depth > MAX_DEPTH:
            errors.append("TOO_DEEP")
            continue
        if not isinstance(part, dict):
            errors.append("PART_NOT_OBJECT")
            continue
        mime = str(part.get("mimeType", "")).lower()
        children = part.get("parts")
        if isinstance(children, list) and children:
            stack.extend((c, depth + 1) for c in reversed(children))
            continue
        body = part.get("body") or {}
        if not isinstance(body, dict):
            errors.append("BODY_NOT_OBJECT")
            continue
        if part.get("filename") or body.get("attachmentId"):
            continue  # attachments are never read
        data = body.get("data")
        if not data or mime not in {"text/plain", "text/html"}:
            continue
        try:
            raw = b64url_decode(data, max_raw)
        except _MimeParseError as exc:
            errors.append(str(exc))
            continue
        text = _decode_text(raw, _charset(part.get("headers") or []))
        (plains if mime == "text/plain" else htmls).append(text)
    return plains, htmls, errors


def normalize_message(msg: dict[str, Any], *, max_body_chars: int, max_raw_bytes: int) -> NormalizedMessage:
    errors: list[str] = []
    payload = msg.get("payload")
    if not isinstance(payload, dict):
        payload = {}
        errors.append("NO_PAYLOAD")
    headers: dict[str, str] = {}
    for h in payload.get("headers") or []:
        if isinstance(h, dict):
            name = str(h.get("name", "")).lower()
            if name in _KEEP_HEADERS and name not in headers:
                headers[name] = decode_header_value(h.get("value"))
    try:
        plains, htmls, perr = _walk(payload, max_raw_bytes)
        errors.extend(perr)
    except Exception:  # noqa: BLE001
        plains, htmls = [], []
        errors.append("WALK_FAILED")

    plain = "\n".join(p for p in plains if p.strip())
    if plain.strip():
        body, newest, source = plain, strip_quoted_text(plain), "plain"
    elif htmls:
        joined = "\n".join(htmls)
        body = html_to_text(joined)
        newest = strip_quoted_text(html_to_text(joined, drop_quotes=True))
        source = "html"
    else:
        body, newest, source = "", "", "none"
    body, newest = body[:max_body_chars], newest[:max_body_chars]

    name_addr = parseaddr(headers.get("from", ""))[1].lower()
    from_addr = name_addr if "@" in name_addr and not _CTRL_RE.search(name_addr) else ""
    from_domain = from_addr.rsplit("@", 1)[-1] if from_addr else ""
    reply_addr = parseaddr(headers.get("reply-to", ""))[1].lower()
    labels = tuple(str(x) for x in (msg.get("labelIds") or []) if isinstance(x, str))
    try:
        internal = int(msg.get("internalDate") or 0)
    except (TypeError, ValueError):
        internal = 0
        errors.append("BAD_INTERNAL_DATE")
    mid = str(msg.get("id", ""))
    subject = headers.get("subject", "")
    return NormalizedMessage(
        id=mid,
        thread_id=str(msg.get("threadId", "")),
        internal_date=internal,
        label_ids=labels,
        from_address=from_addr,
        from_domain=from_domain,
        reply_to=reply_addr if "@" in reply_addr else "",
        subject=subject,
        message_id_header=headers.get("message-id", ""),
        references=headers.get("references", ""),
        headers_present=frozenset(
            k for k in headers if k in {"list-unsubscribe", "list-id", "auto-submitted", "precedence"}
        ),
        body_text=body,
        newest_text=newest,
        body_source=source,
        parse_errors=tuple(errors),
        fingerprint=fingerprint(mid, internal, subject, newest),
    )
