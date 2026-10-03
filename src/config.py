"""Strict configuration loading. Anything unexpected is a ConfigError (fail closed).

The configuration can never enable sending, permanent deletion or APPLY mode:
APPLY is reachable only through the explicit CLI flag `--apply`.
"""

from __future__ import annotations

import re
import re._constants as sre_c
import re._parser as sre_p
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .errors import ConfigError
from .models import State
from .policy import SYSTEM_LABEL_IDS

CONFIG_VERSION = 1
MAX_CONFIG_BYTES = 256 * 1024
MAX_REGEX_LEN = 500
MAX_RULES = 200
HARD_MAX_MESSAGES = 1000

_TOP_KEYS = {
    "config_version",
    "mode",
    "gmail_query",
    "max_messages_per_run",
    "confidence",
    "label_prefix",
    "labels",
    "capabilities",
    "security",
    "rules",
    "draft_templates",
    "limits",
}
_WHEN_KEYS = {
    "from_domain",
    "from_address",
    "subject_regex",
    "body_regex",
    "any_regex",
    "fields",
    "header_present",
    "newest_is_sent",
}
_ALLOWED_HEADERS = {"list-unsubscribe", "list-id", "auto-submitted", "precedence"}
_RULE_ID_RE = re.compile(r"[a-z0-9][a-z0-9_\-]{0,63}")
_DOMAIN_RE = re.compile(r"[a-z0-9.\-]{1,253}")


@dataclass(frozen=True)
class Conditions:
    from_domains: tuple[str, ...] = ()
    from_addresses: tuple[str, ...] = ()
    subject_regex: re.Pattern[str] | None = None
    body_regex: re.Pattern[str] | None = None
    any_regex: tuple[re.Pattern[str], ...] = ()
    any_fields: tuple[str, ...] = ("subject", "body")
    header_present: tuple[str, ...] = ()
    newest_is_sent: bool | None = None


@dataclass(frozen=True)
class Rule:
    id: str
    state: State
    confidence: float
    when: Conditions
    force_review: bool = False
    draft_template: str | None = None


@dataclass(frozen=True)
class Config:
    gmail_query: str
    max_messages_per_run: int
    auto_threshold: float
    review_threshold: float
    label_prefix: str
    labels: dict[State, str]
    capabilities: frozenset[str]
    rules: tuple[Rule, ...]
    draft_templates: dict[str, str]
    max_body_chars: int = 100_000
    max_thread_messages: int = 200
    max_raw_body_bytes: int = 2_000_000
    source: str = ""
    raw_security: dict[str, Any] = field(default_factory=dict)

    @property
    def review_label(self) -> str:
        return self.labels[State.REVIEW]

    def label_for(self, state: State) -> str:
        return self.labels[state]

    @property
    def app_labels(self) -> frozenset[str]:
        return frozenset(self.labels.values())


def _err(msg: str) -> ConfigError:
    return ConfigError(f"Config invalid: {msg}", code="CONFIG_INVALID")


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise _err(msg)


def _num(v: Any, name: str, lo: float, hi: float) -> float:
    _require(isinstance(v, int | float) and not isinstance(v, bool), f"{name} must be a number")
    f = float(v)
    _require(lo <= f <= hi, f"{name} must be within [{lo}, {hi}]")
    return f


def _int(v: Any, name: str, lo: int, hi: int) -> int:
    _require(isinstance(v, int) and not isinstance(v, bool), f"{name} must be an integer")
    _require(lo <= v <= hi, f"{name} must be within [{lo}, {hi}]")
    return int(v)


_REPEATS = (sre_c.MAX_REPEAT, sre_c.MIN_REPEAT)


def _subpatterns(op: Any, av: Any) -> list[Any]:
    """Child sub-patterns of one parsed regex node (atomic groups / possessive repeats never backtrack)."""
    if op in _REPEATS:
        return [av[2]]
    if op == sre_c.SUBPATTERN:
        return [av[3]]
    if op == sre_c.BRANCH:
        return list(av[1])
    if op in (sre_c.ASSERT, sre_c.ASSERT_NOT):
        return [av[1]]
    if op == sre_c.GROUPREF_EXISTS:
        return [x for x in av[1:] if x is not None]
    return []


_BIG_REPEAT = 10  # an outer repeat with more than this many iterations counts as "large"


def _has_inner_ambiguity(items: Any) -> bool:
    """A repeated sub-pattern is ambiguous if it contains a repeat (bounded or not) or an alternation."""
    for op, av in items:
        if op in _REPEATS and av[1] > 1:
            return True
        if op == sre_c.BRANCH and len(av[1]) > 1:
            return True
        if any(_has_inner_ambiguity(sub) for sub in _subpatterns(op, av)):
            return True
    return False


def _catastrophic(items: Any) -> bool:
    """Shapes with exponential backtracking: (a+)+, (a*)*, (a|a)+, (a{1,10})+, (a+){1,40}, (\\w+\\s*)*."""
    for op, av in items:
        if op in _REPEATS and (av[1] == sre_c.MAXREPEAT or av[1] > _BIG_REPEAT) and _has_inner_ambiguity(av[2]):
            return True
        if any(_catastrophic(sub) for sub in _subpatterns(op, av)):
            return True
    return False


def _regex(v: Any, name: str) -> re.Pattern[str]:
    _require(isinstance(v, str) and 0 < len(v) <= MAX_REGEX_LEN, f"{name} must be a regex string")
    try:
        compiled = re.compile(v)
        parsed = sre_p.parse(v)
    except (re.error, RecursionError, OverflowError) as exc:
        raise _err(f"{name} is not a valid regex: {exc}") from None
    if _catastrophic(parsed):
        raise _err(
            f"{name} nests unbounded quantifiers or repeats an alternation (e.g. (a+)+, (a|b)+) - "
            "catastrophic backtracking on hostile mail; rewrite it, or make the repeat possessive "
            "((?:a|b)++, a++) or atomic ((?>...))"
        )
    return compiled


def _str_list(v: Any, name: str) -> list[str]:
    if isinstance(v, str):
        v = [v]
    _require(
        isinstance(v, list) and all(isinstance(x, str) and x for x in v), f"{name} must be a string or list of strings"
    )
    return [x.strip().lower() for x in v]


def _clean_text(v: Any, name: str, max_len: int) -> str:
    _require(isinstance(v, str), f"{name} must be a string")
    _require(len(v) <= max_len, f"{name} is too long")
    _require(not re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", v), f"{name} contains control characters")
    return str(v)


def _parse_conditions(when: Any, rid: str) -> Conditions:
    _require(isinstance(when, dict) and bool(when), f"rule {rid}: 'when' must be a non-empty mapping")
    unknown = set(when) - _WHEN_KEYS
    _require(not unknown, f"rule {rid}: unknown condition(s) {sorted(unknown)}")
    kw: dict[str, Any] = {}
    if "from_domain" in when:
        doms = _str_list(when["from_domain"], f"rule {rid}.from_domain")
        _require(all(_DOMAIN_RE.fullmatch(d) for d in doms), f"rule {rid}: invalid domain")
        kw["from_domains"] = tuple(doms)
    if "from_address" in when:
        kw["from_addresses"] = tuple(_str_list(when["from_address"], f"rule {rid}.from_address"))
    if "subject_regex" in when:
        kw["subject_regex"] = _regex(when["subject_regex"], f"rule {rid}.subject_regex")
    if "body_regex" in when:
        kw["body_regex"] = _regex(when["body_regex"], f"rule {rid}.body_regex")
    if "any_regex" in when:
        pats = when["any_regex"] if isinstance(when["any_regex"], list) else [when["any_regex"]]
        kw["any_regex"] = tuple(_regex(p, f"rule {rid}.any_regex") for p in pats)
    if "fields" in when:
        fields = _str_list(when["fields"], f"rule {rid}.fields")
        _require(set(fields) <= {"subject", "body"} and bool(fields), f"rule {rid}: fields must be subject/body")
        kw["any_fields"] = tuple(fields)
    if "header_present" in when:
        hdrs = _str_list(when["header_present"], f"rule {rid}.header_present")
        _require(set(hdrs) <= _ALLOWED_HEADERS, f"rule {rid}: header_present allows {sorted(_ALLOWED_HEADERS)}")
        kw["header_present"] = tuple(hdrs)
    if "newest_is_sent" in when:
        _require(isinstance(when["newest_is_sent"], bool), f"rule {rid}: newest_is_sent must be bool")
        kw["newest_is_sent"] = when["newest_is_sent"]
    cond = Conditions(**kw)
    _require(
        any(
            [
                cond.from_domains,
                cond.from_addresses,
                cond.subject_regex,
                cond.body_regex,
                cond.any_regex,
                cond.header_present,
                cond.newest_is_sent is not None,
            ]
        ),
        f"rule {rid}: at least one condition required",
    )
    return cond


def parse_config(data: Any, source: str = "<memory>") -> Config:
    _require(isinstance(data, dict), "top level must be a mapping")
    unknown = set(data) - _TOP_KEYS
    _require(not unknown, f"unknown top-level key(s) {sorted(unknown)}")
    _require(
        data.get("config_version") == CONFIG_VERSION,
        f"config_version must be {CONFIG_VERSION} (partial upgrade or missing)",
    )

    mode = data.get("mode", "dry-run")
    if mode != "dry-run":
        raise ConfigError("Config may not request APPLY. Use the explicit CLI flag --apply.", code="APPLY_FROM_CONFIG")

    sec = data.get("security")
    _require(isinstance(sec, dict), "security block is required")
    _require(
        set(sec) == {"allow_send", "allow_permanent_delete", "forbid_full_mail_scope"},
        "security block must contain exactly allow_send, allow_permanent_delete, forbid_full_mail_scope",
    )
    if sec["allow_send"] is not False:
        raise ConfigError("Invariant violation: allow_send cannot be enabled", code="INVARIANT_SEND")
    if sec["allow_permanent_delete"] is not False:
        raise ConfigError("Invariant violation: allow_permanent_delete cannot be enabled", code="INVARIANT_DELETE")
    if sec["forbid_full_mail_scope"] is not True:
        raise ConfigError("Invariant violation: forbid_full_mail_scope must stay true", code="INVARIANT_SCOPE")

    query = _clean_text(data.get("gmail_query", "in:inbox newer_than:30d"), "gmail_query", 500)
    _require("\n" not in query and "\r" not in query and query.strip() != "", "gmail_query invalid")
    max_msgs = _int(data.get("max_messages_per_run", 100), "max_messages_per_run", 1, HARD_MAX_MESSAGES)

    conf = data.get("confidence", {})
    _require(isinstance(conf, dict) and set(conf) <= {"auto", "review"}, "confidence must have auto/review")
    auto = _num(conf.get("auto", 0.85), "confidence.auto", 0.85, 1.0)
    review = _num(conf.get("review", 0.60), "confidence.review", 0.60, 1.0)
    _require(review < auto, "confidence.review must be below confidence.auto")

    prefix = _clean_text(data.get("label_prefix", "JARVIS/"), "label_prefix", 40)
    _require(prefix.endswith("/") and len(prefix) >= 2, "label_prefix must end with '/'")
    labels_raw = data.get("labels")
    _require(isinstance(labels_raw, dict), "labels mapping is required")
    expected = {s.value.lower() for s in State}
    _require(set(labels_raw) == expected, f"labels must define exactly {sorted(expected)}")
    labels: dict[State, str] = {}
    for key, name in labels_raw.items():
        name = _clean_text(name, f"labels.{key}", 100)
        _require(
            name.startswith(prefix) and len(name) > len(prefix), f"labels.{key} must start with label_prefix {prefix!r}"
        )
        _require(name.upper() not in SYSTEM_LABEL_IDS, f"labels.{key} may not be a system label")
        labels[State(key.upper())] = name
    _require(len(set(labels.values())) == len(labels), "label names must be unique")

    caps_raw = data.get("capabilities", {})
    _require(isinstance(caps_raw, dict), "capabilities must be a mapping")
    _require(
        set(caps_raw) <= {"labels", "drafts"},
        f"unknown capability {sorted(set(caps_raw) - {'labels', 'drafts'})} (V1 knows labels, drafts)",
    )
    _require(all(isinstance(v, bool) for v in caps_raw.values()), "capabilities must be booleans")
    caps = frozenset(k for k, v in caps_raw.items() if v)

    templates_raw = data.get("draft_templates", {}) or {}
    _require(isinstance(templates_raw, dict), "draft_templates must be a mapping")
    templates: dict[str, str] = {}
    for tid, text in templates_raw.items():
        _require(isinstance(tid, str) and _RULE_ID_RE.fullmatch(tid) is not None, f"template id {tid!r} invalid")
        _require(isinstance(text, str) and 0 < len(text) <= 4000, f"template {tid} must be 1..4000 chars")
        templates[tid] = text

    rules_raw = data.get("rules", [])
    _require(isinstance(rules_raw, list) and len(rules_raw) <= MAX_RULES, f"rules must be a list (<= {MAX_RULES})")
    rules: list[Rule] = []
    seen: set[str] = set()
    for i, r in enumerate(rules_raw):
        _require(isinstance(r, dict), f"rule #{i} must be a mapping")
        unknown_r = set(r) - {"id", "state", "confidence", "when", "force_review", "draft_template"}
        _require(not unknown_r, f"rule #{i}: unknown key(s) {sorted(unknown_r)}")
        rid = r.get("id")
        _require(isinstance(rid, str) and _RULE_ID_RE.fullmatch(rid) is not None, f"rule #{i}: invalid id")
        _require(rid not in seen, f"duplicate rule id {rid}")
        seen.add(rid)
        try:
            state = State(str(r.get("state", "")).upper())
        except ValueError:
            raise _err(f"rule {rid}: unknown state {r.get('state')!r}") from None
        confv = _num(r.get("confidence"), f"rule {rid}.confidence", 0.0, 1.0)
        force = r.get("force_review", False)
        _require(isinstance(force, bool), f"rule {rid}: force_review must be bool")
        tpl = r.get("draft_template")
        if tpl is not None:
            _require(state is State.ACTION, f"rule {rid}: draft_template only allowed for ACTION rules")
            _require(tpl in templates, f"rule {rid}: draft_template {tpl!r} not defined")
        rules.append(
            Rule(
                id=rid,
                state=state,
                confidence=confv,
                when=_parse_conditions(r.get("when"), rid),
                force_review=force,
                draft_template=tpl,
            )
        )

    limits = data.get("limits", {}) or {}
    _require(
        isinstance(limits, dict) and set(limits) <= {"max_body_chars", "max_thread_messages", "max_raw_body_bytes"},
        "limits has unknown keys",
    )
    return Config(
        gmail_query=query,
        max_messages_per_run=max_msgs,
        auto_threshold=auto,
        review_threshold=review,
        label_prefix=prefix,
        labels=labels,
        capabilities=caps,
        rules=tuple(rules),
        draft_templates=templates,
        max_body_chars=_int(limits.get("max_body_chars", 100_000), "limits.max_body_chars", 1_000, 500_000),
        max_thread_messages=_int(limits.get("max_thread_messages", 200), "limits.max_thread_messages", 1, 500),
        max_raw_body_bytes=_int(
            limits.get("max_raw_body_bytes", 2_000_000), "limits.max_raw_body_bytes", 10_000, 10_000_000
        ),
        source=source,
        raw_security=dict(sec),
    )


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys (a later key must not silently win)."""


def _construct_unique_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    seen: set[Any] = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in seen
            seen.add(key)
        except TypeError:
            raise yaml.constructor.ConstructorError(None, None, "unhashable mapping key", key_node.start_mark) from None
        if duplicate:
            raise yaml.constructor.ConstructorError(None, None, f"duplicate key {key!r}", key_node.start_mark)
    return loader.construct_mapping(node, deep=deep)


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping)


def load_config(path: Path) -> Config:
    try:
        p = Path(path)
        if not p.is_file():
            raise ConfigError(f"Config file not found: {p}", code="CONFIG_MISSING")
        raw = p.read_bytes()
    except OSError as exc:
        raise ConfigError(f"Config not readable: {exc.__class__.__name__}", code="CONFIG_UNREADABLE") from None
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError("Config file too large", code="CONFIG_TOO_LARGE")
    try:
        data = yaml.load(raw.decode("utf-8"), Loader=_UniqueKeyLoader)  # noqa: S506 - SafeLoader subclass
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        detail = "duplicate key" if "duplicate key" in str(exc) else exc.__class__.__name__
        raise ConfigError(f"Config is not valid UTF-8 YAML: {detail}", code="CONFIG_MALFORMED") from None
    return parse_config(data, source=str(p))
