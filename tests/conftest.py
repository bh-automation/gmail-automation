from __future__ import annotations

import copy
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from src.audit import AuditLedger
from src.config import Config, parse_config
from src.engine import Engine
from src.gmail_client import GmailClient
from src.models import RunSummary
from src.policy import PolicyContext, Profile
from src.retry import RetryPolicy
from tests.fakes import FakeGmail

BASE_CONFIG: dict[str, Any] = {
    "config_version": 1,
    "mode": "dry-run",
    "gmail_query": "in:inbox newer_than:30d",
    "max_messages_per_run": 100,
    "confidence": {"auto": 0.85, "review": 0.60},
    "label_prefix": "JARVIS/",
    "labels": {
        "action": "JARVIS/ACTION",
        "waiting": "JARVIS/WAITING",
        "project": "JARVIS/PROJECT",
        "reference": "JARVIS/REFERENCE",
        "done": "JARVIS/DONE",
        "review": "JARVIS/REVIEW",
    },
    "capabilities": {"labels": False, "drafts": False},
    "security": {"allow_send": False, "allow_permanent_delete": False, "forbid_full_mail_scope": True},
    "rules": [
        {
            "id": "newsletter",
            "state": "REFERENCE",
            "confidence": 0.90,
            "when": {"header_present": ["list-unsubscribe"]},
        },
        {
            "id": "signature-request",
            "state": "ACTION",
            "confidence": 0.86,
            "when": {"any_regex": [r"(?i)\b(bitte (unterschreiben|unterzeichnen)|signature requested)\b"]},
            "draft_template": "ack",
        },
        {"id": "waiting-for-reply", "state": "WAITING", "confidence": 0.86, "when": {"newest_is_sent": True}},
        {"id": "project-x", "state": "PROJECT", "confidence": 0.75, "when": {"subject_regex": "(?i)projekt x"}},
        {
            "id": "money-review",
            "state": "REVIEW",
            "confidence": 0.70,
            "force_review": True,
            "when": {"any_regex": ["(?i)(zahlung|iban|invoice|rechnung|ueberweisung)"]},
        },
    ],
    "draft_templates": {"ack": "Hallo,\n\nvielen Dank - ich melde mich zeitnah.\n\nViele Gruesse"},
}


def make_config(**over: Any) -> Config:
    data = copy.deepcopy(BASE_CONFIG)
    for key, value in over.items():
        data[key] = value
    return parse_config(data)


@pytest.fixture(autouse=True)
def reset_app_logging():
    """cli.main() binds log handlers to the (captured) stderr of one test - never leak them."""
    yield
    import logging

    logging.getLogger("gmail_automation").handlers.clear()


@pytest.fixture(autouse=True)
def isolated_anchor_dir(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Rollback anchors of test ledgers never touch the real user profile."""
    d = tmp_path_factory.mktemp("anchors")
    monkeypatch.setenv("GMAIL_AUTOMATION_ANCHOR_DIR", str(d))
    return d


@pytest.fixture
def cfg() -> Config:
    return make_config()


@pytest.fixture
def cfg_apply() -> Config:
    return make_config(capabilities={"labels": True, "drafts": True})


@pytest.fixture
def data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    # Windows-like: spaces and non-ASCII characters in the data path
    d = tmp_path / "Benutzer Ä Ö" / "Gmail Automation Däten"
    d.mkdir(parents=True)
    monkeypatch.setenv("GMAIL_AUTOMATION_HOME", str(d))
    return d


@pytest.fixture
def ledger(data_dir: Path) -> AuditLedger:
    led = AuditLedger(data_dir / "audit.sqlite3")
    yield led
    led.close()


@pytest.fixture
def gmail() -> FakeGmail:
    return FakeGmail()


def ctx_for(cfg: Config, *, apply: bool) -> PolicyContext:
    return PolicyContext(
        profile=Profile.APPLY if apply else Profile.OBSERVE,
        apply_flag=apply,
        capabilities=cfg.capabilities,
        auto_threshold=cfg.auto_threshold,
        review_threshold=cfg.review_threshold,
        label_prefix=cfg.label_prefix,
        review_label=cfg.review_label,
    )


def client_for(service: Any, cfg: Config, *, apply: bool, refresh: Callable[[], None] | None = None) -> GmailClient:
    return GmailClient(
        service,
        ctx_for(cfg, apply=apply),
        retry=RetryPolicy(max_attempts=4),
        sleep=lambda s: None,
        refresh_credentials=refresh,
    )


def run_engine(
    service: FakeGmail, cfg: Config, ledger: AuditLedger, *, apply: bool, out: list[str] | None = None
) -> tuple[RunSummary, Engine]:
    client = client_for(service, cfg, apply=apply)
    engine = Engine(
        client, cfg, ctx_for(cfg, apply=apply), ledger, out=(out.append if out is not None else lambda s: None)
    )
    return engine.run(), engine
