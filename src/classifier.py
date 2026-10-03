"""Deterministic rules-first classifier.

The classifier returns data (state, confidence, rule id). It holds no Gmail handle and
cannot produce actions. Message text is matched against operator-defined patterns only;
nothing in a message can add rules, change thresholds or request an action.
"""

from __future__ import annotations

import re

from .config import Config, Rule
from .models import Band, Classification, NormalizedMessage, State, ThreadSnapshot

PARSE_ERROR_CONFIDENCE = 0.65
CONFLICT_CONFIDENCE = 0.70
MONEY_GUARD_CONFIDENCE = 0.75
MAX_MATCH_CHARS = 20_000  # regexes only ever see a bounded slice of untrusted text

# Built-in, non-configurable guard: money / payment / credential wording never leads to an
# automatic ACTION (and therefore never to an auto-draft). It routes to REVIEW instead.
_MONEY_GUARD = re.compile(
    r"(?i)(bezahl|zahlung|zahle|überweis|ueberweis|rechnung|mahnung|inkasso|\biban\b|\bbic\b|\bswift\b|"
    r"bankverbindung|kontodaten|kontonummer|gutschein|geschenkkarte|guthaben|gift ?cards?|wire transfer|"
    r"bank transfer|\btransfer|\bpayment|\bpay\b|\binvoice|\bremit|\bgeld\b|\beuro?\b|€|\bbetrag|begleich|"
    r"lastschrift|\bsepa\b|kreditkarte|credit ?card|\bcvv\b|\bcvc\b|bitcoin|\bbtc\b|\busdt\b|\beth\b|"
    r"ethereum|crypto|krypto|wallet|paypal|western union|moneygram|passwort|password|\btan\b|\bpin\b)"
)


def _rule_matches(rule: Rule, msg: NormalizedMessage) -> bool:
    w = rule.when
    # force_review rules are safety rules: they see all text (quoted, hidden, every MIME part).
    source = (msg.guard_text or msg.newest_text) if rule.force_review else msg.newest_text
    newest = source[:MAX_MATCH_CHARS]
    if w.newest_is_sent is not None and msg.is_sent != w.newest_is_sent:
        return False
    if w.from_domains and not any(msg.from_domain == d or msg.from_domain.endswith("." + d) for d in w.from_domains):
        return False
    if w.from_addresses and msg.from_address not in w.from_addresses:
        return False
    if w.header_present and not all(h in msg.headers_present for h in w.header_present):
        return False
    if w.subject_regex is not None and not w.subject_regex.search(msg.subject):
        return False
    if w.body_regex is not None and not w.body_regex.search(newest):
        return False
    if w.any_regex:
        haystacks = [msg.subject if f == "subject" else newest for f in w.any_fields]
        if not any(p.search(h) for p in w.any_regex for h in haystacks):
            return False
    return True


def _band(state: State, confidence: float, cfg: Config) -> tuple[State, Band]:
    if state is not State.REVIEW and confidence >= cfg.auto_threshold:
        return state, Band.AUTO
    if confidence >= cfg.review_threshold:
        return State.REVIEW, Band.REVIEW_LABEL
    return State.REVIEW, Band.REVIEW_ONLY


def classify(msg: NormalizedMessage, thread: ThreadSnapshot | None, cfg: Config) -> Classification:
    if msg.parse_errors:
        state, band = _band(State.REVIEW, PARSE_ERROR_CONFIDENCE, cfg)
        return Classification(
            state,
            PARSE_ERROR_CONFIDENCE,
            band,
            "builtin:parse-error",
            ("message could not be parsed safely: " + ",".join(msg.parse_errors[:3]),),
        )
    matches = [r for r in cfg.rules if _rule_matches(r, msg)]
    if not matches:
        return Classification(State.REVIEW, 0.0, Band.REVIEW_ONLY, "builtin:no-match", ("no rule matched",))

    forced = [r for r in matches if r.force_review]
    if forced:
        top = max(forced, key=lambda r: r.confidence)
        conf = min(top.confidence, round(cfg.auto_threshold - 0.01, 2))
        state, band = _band(State.REVIEW, conf, cfg)
        return Classification(state, conf, band, top.id, (f"force_review by rule {top.id}",))

    strong = [r for r in matches if r.confidence >= cfg.auto_threshold and r.state is not State.REVIEW]
    if len({r.state for r in strong}) > 1:
        ids = ",".join(sorted(r.id for r in strong))
        state, band = _band(State.REVIEW, CONFLICT_CONFIDENCE, cfg)
        return Classification(state, CONFLICT_CONFIDENCE, band, "builtin:conflict", (f"conflicting rules {ids}",))

    best = max(matches, key=lambda r: r.confidence)
    ties = [r for r in matches if r.confidence == best.confidence and r.state is not best.state]
    if ties:
        state, band = _band(State.REVIEW, min(best.confidence, CONFLICT_CONFIDENCE), cfg)
        return Classification(
            state, min(best.confidence, CONFLICT_CONFIDENCE), band, "builtin:tie", ("equal-confidence rules disagree",)
        )
    state, band = _band(best.state, best.confidence, cfg)
    if (
        state is State.ACTION
        and band is Band.AUTO
        and _MONEY_GUARD.search(msg.subject + "\n" + (msg.guard_text or msg.newest_text))  # linear literal scan
    ):
        conf = min(best.confidence, MONEY_GUARD_CONFIDENCE)
        state, band = _band(State.REVIEW, conf, cfg)
        return Classification(state, conf, band, "builtin:money-guard", (f"rule {best.id} + money/credential wording",))
    draft = best.draft_template if (band is Band.AUTO and state is State.ACTION) else None
    return Classification(state, best.confidence, band, best.id, (f"rule {best.id}",), draft_template=draft)
