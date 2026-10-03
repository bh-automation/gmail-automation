import copy
from pathlib import Path

import pytest
import yaml

from src import cli
from src.policy import Profile
from tests.conftest import BASE_CONFIG
from tests.fakes import FakeGmail, make_message

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def mailbox():
    g = FakeGmail()
    g.add(make_message("m1", "t1", subject="News", extra_headers={"List-Unsubscribe": "<x>"}))
    g.add(make_message("m2", "t2", subject="Vertrag", plain="Bitte unterschreiben Sie."))
    return g


def write_cfg(tmp_path, **over):
    d = copy.deepcopy(BASE_CONFIG)
    d.update(over)
    p = tmp_path / "rules mit leerzeichen.yaml"
    p.write_text(yaml.safe_dump(d, allow_unicode=True), encoding="utf-8")
    return str(p)


def factory_for(g, seen):
    def factory(profile):
        seen.append(profile)
        return g, None

    return factory


def test_scan_is_observe_and_prints_gate_summary(data_dir, tmp_path, mailbox, capsys):
    seen = []
    rc = cli.main(
        ["scan", "--config", write_cfg(tmp_path, capabilities={"labels": True, "drafts": True})],
        service_factory=factory_for(mailbox, seen),
    )
    out = capsys.readouterr().out
    assert rc == 0 and seen == [Profile.OBSERVE]
    lines = [ln for ln in out.splitlines() if " = " in ln and ln.split(" = ")[0].isupper()]
    keys = [ln.split(" = ")[0] for ln in lines][:8]
    assert keys == [
        "MODE",
        "SCANNED",
        "ACTION_CANDIDATES",
        "REVIEW",
        "MUTATIONS",
        "SEND_BLOCK",
        "DELETE_BLOCK",
        "AUDIT",
    ]
    assert "MODE = DRY-RUN" in out and "MUTATIONS = 0" in out and "SEND_BLOCK = PASS" in out
    assert mailbox.mutation_calls() == []


def test_run_without_apply_is_dry_run_even_with_env_and_config(data_dir, tmp_path, mailbox, capsys, monkeypatch):
    monkeypatch.setenv("GMAIL_AUTOMATION_APPLY", "1")
    monkeypatch.setenv("APPLY", "true")
    seen = []
    rc = cli.main(
        ["run", "--config", write_cfg(tmp_path, capabilities={"labels": True})],
        service_factory=factory_for(mailbox, seen),
    )
    assert rc == 0 and seen == [Profile.OBSERVE] and mailbox.mutation_calls() == []
    assert "MODE = DRY-RUN" in capsys.readouterr().out


def test_config_requesting_apply_is_refused(data_dir, tmp_path, mailbox, capsys):
    rc = cli.main(["run", "--config", write_cfg(tmp_path, mode="apply")], service_factory=factory_for(mailbox, []))
    assert rc == 2 and "APPLY_FROM_CONFIG" in capsys.readouterr().out


def test_explicit_apply_flag_uses_apply_profile(data_dir, tmp_path, mailbox, capsys):
    seen = []
    rc = cli.main(
        ["run", "--apply", "--config", write_cfg(tmp_path, capabilities={"labels": True})],
        service_factory=factory_for(mailbox, seen),
    )
    out = capsys.readouterr().out
    assert rc == 0 and seen == [Profile.APPLY] and "MODE = APPLY" in out
    assert "JARVIS/REFERENCE" in mailbox.label_names("m1")


def test_global_apply_failure_returns_fail_closed_exit(data_dir, tmp_path, mailbox, capsys):
    from tests.fakes import http_error

    mailbox.faults["users.messages.modify"] = [http_error(403, "insufficientPermissions")]
    rc = cli.main(
        ["run", "--apply", "--config", write_cfg(tmp_path, capabilities={"labels": True})],
        service_factory=factory_for(mailbox, []),
    )
    assert rc == 8 and "FAILED_CLOSED" in capsys.readouterr().out


def test_message_scoped_failure_returns_partial_exit(data_dir, tmp_path, mailbox, capsys):
    from src.errors import EXIT_PARTIAL
    from tests.fakes import http_error

    mailbox.faults["users.messages.modify"] = [http_error(400, "failedPrecondition")]
    rc = cli.main(
        ["run", "--apply", "--config", write_cfg(tmp_path, capabilities={"labels": True})],
        service_factory=factory_for(mailbox, []),
    )
    out = capsys.readouterr().out
    assert rc == EXIT_PARTIAL and "STATUS = PARTIAL" in out and "FEHLGESCHLAGEN = 1" in out


def test_status_audit_verify_and_undo_flow(data_dir, tmp_path, mailbox, capsys):
    cfg = write_cfg(tmp_path, capabilities={"labels": True})
    cli.main(["run", "--apply", "--config", cfg], service_factory=factory_for(mailbox, []))
    capsys.readouterr()
    assert cli.main(["status"]) == 0
    assert "AUDIT = PASS" in capsys.readouterr().out
    assert cli.main(["audit-verify"]) == 0
    rc = cli.main(["undo", "--last-run", "--config", cfg], service_factory=factory_for(mailbox, []))
    out = capsys.readouterr().out
    assert rc == 0 and "UNDO = PREVIEW" in out and "JARVIS/REFERENCE" in mailbox.label_names("m1")
    mailbox.messages["m1"]["labelIds"].append(mailbox.add_user_label("JARVIS/DONE"))
    rc = cli.main(["undo", "--last-run", "--apply", "--config", cfg], service_factory=factory_for(mailbox, []))
    assert rc == 4 and "CONFLICT" in capsys.readouterr().out
    mailbox.messages["m1"]["labelIds"].remove(mailbox.label_id("JARVIS/DONE"))
    rc = cli.main(["undo", "--last-run", "--apply", "--config", cfg], service_factory=factory_for(mailbox, []))
    assert rc == 0 and "UNDO = DONE" in capsys.readouterr().out
    assert not {n for n in mailbox.label_names("m1") if n.startswith("JARVIS/")}


def test_second_concurrent_instance_refused(data_dir, tmp_path, mailbox, capsys):
    from src import paths
    from src.lock import SingleInstanceLock

    with SingleInstanceLock(paths.lock_path()):
        rc = cli.main(["scan", "--config", write_cfg(tmp_path)], service_factory=factory_for(mailbox, []))
    assert rc == 6 and "LOCKED" in capsys.readouterr().out


def test_doctor_reports_pass_without_tokens(data_dir, capsys):
    rc = cli.main(["doctor", "--config", str(ROOT / "config" / "rules.example.yaml")])
    out = capsys.readouterr().out
    assert rc == 0, out
    for gate in (
        "PYTHON",
        "DEPENDENCIES",
        "CONFIG",
        "SEND/DELETE BLOCK",
        "SECRET LOCATIONS",
        "REPO HYGIENE",
        "FORBIDDEN SCAN",
        "AUDIT",
        "OAUTH TOKENS",
    ):
        assert f"{gate}" in out


def test_config_check_and_missing_config(data_dir, tmp_path, capsys):
    assert cli.main(["config-check", "--config", str(ROOT / "config" / "rules.example.yaml")]) == 0
    assert cli.main(["config-check", "--config", str(tmp_path / "nope.yaml")]) == 2
    assert "CONFIG_MISSING" in capsys.readouterr().out


def test_console_output_masks_addresses(data_dir, tmp_path, capsys):
    g = FakeGmail()
    g.add(make_message("m1", "t1", subject="Antwort von max.mustermann@firma.example\r\nINJECTED", plain="x"))
    cli.main(["scan", "--config", write_cfg(tmp_path)], service_factory=factory_for(g, []))
    out = capsys.readouterr().out
    assert "max.mustermann@" not in out and "m***@firma.example" in out
    assert "\nINJECTED" not in out
