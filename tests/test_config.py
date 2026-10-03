import copy
from pathlib import Path

import pytest

from src.config import load_config, parse_config
from src.errors import ConfigError
from src.models import State
from tests.conftest import BASE_CONFIG

ROOT = Path(__file__).resolve().parents[1]


def data(**over):
    d = copy.deepcopy(BASE_CONFIG)
    d.update(over)
    return d


def test_example_config_is_valid_and_safe():
    cfg = load_config(ROOT / "config" / "rules.example.yaml")
    assert cfg.capabilities == frozenset()  # nothing enabled by default
    assert cfg.auto_threshold == 0.85 and cfg.review_threshold == 0.60
    assert cfg.labels[State.REVIEW] == "JARVIS/REVIEW"


@pytest.mark.parametrize(
    "key,value,code",
    [
        ("allow_send", True, "INVARIANT_SEND"),
        ("allow_permanent_delete", True, "INVARIANT_DELETE"),
        ("forbid_full_mail_scope", False, "INVARIANT_SCOPE"),
        ("allow_send", "yes", "INVARIANT_SEND"),
    ],
)
def test_security_invariants_cannot_be_lifted(key, value, code):
    d = data()
    d["security"] = {**d["security"], key: value}
    with pytest.raises(ConfigError) as e:
        parse_config(d)
    assert e.value.code == code


@pytest.mark.parametrize("mode", ["apply", "APPLY", "live", True])
def test_apply_cannot_come_from_config(mode):
    with pytest.raises(ConfigError) as e:
        parse_config(data(mode=mode))
    assert e.value.code == "APPLY_FROM_CONFIG"


def test_missing_security_block_fails_closed():
    d = data()
    del d["security"]
    with pytest.raises(ConfigError):
        parse_config(d)


def test_extra_security_key_rejected():
    d = data()
    d["security"] = {**d["security"], "allow_forwarding": False}
    with pytest.raises(ConfigError):
        parse_config(d)


@pytest.mark.parametrize(
    "over",
    [
        {"config_version": 2},
        {"config_version": None},
        {"unexpected_key": 1},
        {"confidence": {"auto": 0.80, "review": 0.60}},
        {"confidence": {"auto": 0.9, "review": 0.5}},
        {"confidence": {"auto": 0.9, "review": 0.95}},
        {"max_messages_per_run": 0},
        {"max_messages_per_run": 50_000},
        {"capabilities": {"labels": True, "send": True}},
        {"capabilities": {"labels": "true"}},
        {"gmail_query": "in:inbox\nrm -rf"},
        {"label_prefix": "JARVIS"},
    ],
)
def test_invalid_values_rejected(over):
    with pytest.raises(ConfigError):
        parse_config(data(**over))


def test_labels_must_be_app_prefixed_and_not_system():
    d = data()
    d["labels"] = {**d["labels"], "action": "INBOX"}
    with pytest.raises(ConfigError):
        parse_config(d)
    d["labels"] = {**BASE_CONFIG["labels"], "action": "JARVIS/TRASH_NOT_SYSTEM"}
    parse_config(d)  # prefixed custom name is fine
    d["labels"] = {**BASE_CONFIG["labels"]}
    del d["labels"]["done"]
    with pytest.raises(ConfigError):
        parse_config(d)


def test_rule_validation():
    bad_rules = [
        [{"id": "x", "state": "ACTION", "confidence": 0.9, "when": {"subject_regex": "(unclosed"}}],
        [{"id": "x", "state": "SEND", "confidence": 0.9, "when": {"subject_regex": "a"}}],
        [{"id": "x", "state": "ACTION", "confidence": 1.5, "when": {"subject_regex": "a"}}],
        [{"id": "x", "state": "ACTION", "confidence": 0.9, "when": {}}],
        [{"id": "x", "state": "ACTION", "confidence": 0.9, "when": {"run_shell": "a"}}],
        [{"id": "x", "state": "WAITING", "confidence": 0.9, "when": {"subject_regex": "a"}, "draft_template": "ack"}],
        [{"id": "x", "state": "ACTION", "confidence": 0.9, "when": {"subject_regex": "a"}, "draft_template": "nope"}],
        [{"id": "x", "state": "ACTION", "confidence": 0.9, "when": {"header_present": ["x-evil"]}}],
        [{"id": "Bad Id", "state": "ACTION", "confidence": 0.9, "when": {"subject_regex": "a"}}],
        [{"id": "x", "state": "ACTION", "confidence": 0.9, "when": {"subject_regex": "a" * 600}}],
    ]
    for rules in bad_rules:
        with pytest.raises(ConfigError):
            parse_config(data(rules=rules))
    dup = [{"id": "x", "state": "ACTION", "confidence": 0.9, "when": {"subject_regex": "a"}}] * 2
    with pytest.raises(ConfigError):
        parse_config(data(rules=dup))


def test_load_config_errors(tmp_path):
    with pytest.raises(ConfigError) as e:
        load_config(tmp_path / "missing.yaml")
    assert e.value.code == "CONFIG_MISSING"
    bad = tmp_path / "bad config.yaml"
    bad.write_text("config_version: [1\n  :", encoding="utf-8")
    with pytest.raises(ConfigError) as e:
        load_config(bad)
    assert e.value.code == "CONFIG_MALFORMED"
    big = tmp_path / "big.yaml"
    big.write_bytes(b"#" * 300_000)
    with pytest.raises(ConfigError) as e:
        load_config(big)
    assert e.value.code == "CONFIG_TOO_LARGE"
    notyaml = tmp_path / "bin.yaml"
    notyaml.write_bytes(b"\xff\xfe\x00bad")
    with pytest.raises(ConfigError):
        load_config(notyaml)


def test_partially_upgraded_config_fails_closed(tmp_path):
    p = tmp_path / "Konfig mit Leerzeichen ü.yaml"
    p.write_text("mode: dry-run\nlabels: {}\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(p)
