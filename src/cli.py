"""Command line: doctor | auth | scan | run | status | undo | config-check | audit-verify.

Default is always DRY-RUN. Mailbox changes need the explicit flag --apply, the APPLY
OAuth profile and an enabled capability in the config. No environment variable or
config value can switch APPLY on.
"""

from __future__ import annotations

import argparse
import dataclasses
import logging
import logging.handlers
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import __version__, paths
from .audit import AuditLedger
from .auth import (
    PROFILE_SCOPES,
    build_gmail_service,
    check_secret_location,
    load_credentials,
    run_consent_flow,
)
from .config import Config, load_config
from .engine import Engine
from .errors import ConflictError, GmailAutomationError
from .gmail_client import GmailClient
from .lock import SingleInstanceLock
from .policy import PolicyContext, Profile
from .redaction import RedactingFilter, redact

EXIT_OK = 0


def _out(line: str) -> None:
    print(redact(line, mask_emails=True, max_len=500))


def _setup_logging(verbose: bool) -> None:
    root = logging.getLogger("gmail_automation")
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    root.handlers.clear()
    flt = RedactingFilter()
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.DEBUG if verbose else logging.WARNING)
    console.addFilter(flt)
    console.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    root.addHandler(console)
    try:
        paths.ensure_private_dir(paths.log_dir())
        fh = logging.handlers.RotatingFileHandler(
            paths.log_dir() / "gmail-automation.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8"
        )
        fh.addFilter(flt)
        fh.setFormatter(logging.Formatter("%(asctime)sZ %(levelname)s %(name)s %(message)s"))
        root.addHandler(fh)
    except OSError:
        root.warning("log directory not writable - console logging only")


def build_context(cfg: Config, profile: Profile, apply_flag: bool) -> PolicyContext:
    """The ONLY place that can set apply_flag - and only from the parsed CLI flag."""
    if apply_flag and profile is not Profile.APPLY:
        raise GmailAutomationError("--apply requires the APPLY profile", code="APPLY_PROFILE")
    return PolicyContext(
        profile=profile,
        apply_flag=apply_flag,
        capabilities=cfg.capabilities,
        auto_threshold=cfg.auto_threshold,
        review_threshold=cfg.review_threshold,
        label_prefix=cfg.label_prefix,
        review_label=cfg.review_label,
    )


ServiceFactory = Callable[[Profile], tuple[Any, Callable[[], None] | None]]


def default_service_factory(profile: Profile) -> tuple[Any, Callable[[], None] | None]:
    creds, _ = load_credentials(profile, paths.token_path(profile.value))

    def refresh() -> None:
        from google.auth.transport.requests import Request

        creds.refresh(Request())

    return build_gmail_service(creds), refresh


def _open_ledger() -> AuditLedger:
    paths.ensure_private_dir(paths.data_dir())
    return AuditLedger(paths.audit_db_path())


def cmd_config_check(args: argparse.Namespace) -> int:
    cfg = load_config(Path(args.config))
    _out(
        f"CONFIG = PASS ({len(cfg.rules)} Regeln, Labels {cfg.label_prefix}*, "
        f"Capabilities: {', '.join(sorted(cfg.capabilities)) or 'keine'})"
    )
    return EXIT_OK


def cmd_scan_or_run(args: argparse.Namespace, factory: ServiceFactory) -> int:
    apply_flag = bool(getattr(args, "apply", False))
    profile = Profile.APPLY if apply_flag else Profile.OBSERVE
    cfg = load_config(Path(args.config))
    if args.max is not None:
        cfg = dataclasses.replace(cfg, max_messages_per_run=max(1, min(args.max, cfg.max_messages_per_run)))
    ctx = build_context(cfg, profile, apply_flag)
    _out(f"GMAIL-AUTOMATION {__version__} | Modus {ctx.mode} | Profil {profile.value.upper()}")
    if apply_flag:
        caps = ", ".join(sorted(cfg.capabilities)) or "keine"
        _out(f"APPLY aktiv | Capabilities: {caps} | Senden/Loeschen technisch gesperrt")
    with SingleInstanceLock(paths.lock_path()), _open_ledger() as ledger:
        service, refresh = factory(profile)
        client = GmailClient(service, ctx, refresh_credentials=refresh)
        engine = Engine(client, cfg, ctx, ledger, out=_out)
        summary = engine.run()
    _out("")
    for line in summary.gate_lines():
        _out(line)
    _out(f"RUN_ID = {summary.run_id} | STATUS = {summary.status}")
    if engine.error is not None:
        _out(f"FEHLER: {engine.error}")
        return engine.error.exit_code
    return EXIT_OK


def cmd_status(args: argparse.Namespace) -> int:
    with _open_ledger() as ledger:
        ok, msg = ledger.verify()
        _out(f"AUDIT = {'PASS' if ok else 'FAIL'} ({msg})")
        pend = ledger.pending()
        _out(f"OFFENE AKTIONEN = {len(pend)}" + (" (naechster APPLY-Lauf gleicht ab)" if pend else ""))
        for r in ledger.runs(limit=args.runs):
            end = r.get("end") or {}
            _out(f"  {r['run_id']}  {r['mode']:<7} {r['profile']:<7} {r['ts'][:19]}Z  {end.get('outcome') or 'OFFEN'}")
        return EXIT_OK if ok else 5


def cmd_undo(args: argparse.Namespace, factory: ServiceFactory) -> int:
    from .undo import undo_run

    cfg = load_config(Path(args.config))
    with SingleInstanceLock(paths.lock_path()), _open_ledger() as ledger:
        run_id = args.run_id or ledger.last_undoable_run()
        if not run_id:
            _out("UNDO = NOTHING (kein rueckgaengig zu machender APPLY-Lauf)")
            return EXIT_OK
        profile = Profile.APPLY if args.apply else Profile.OBSERVE
        ctx = build_context(cfg, profile, bool(args.apply))
        service, refresh = factory(profile)
        client = GmailClient(service, ctx, refresh_credentials=refresh)
        res = undo_run(client, cfg, ctx, ledger, run_id, apply=bool(args.apply), out=_out)
    _out(f"UNDO = {res.status} | Ziel-Lauf {res.run_id} | Undo-Lauf {res.undo_run_id}")
    for c in res.conflicts:
        _out(f"  CONFLICT {c['message_id'][:8]}... {c['reason']} - Postfach unveraendert")
    for p in res.planned:
        _out(
            f"  {'zurueckgesetzt' if res.status == 'DONE' else 'wuerde zuruecksetzen'}: {p['message_id'][:8]}... "
            f"{p['from']} -> {p['to']}"
        )
    for d in res.manual_drafts:
        _out(f"  MANUELL: Entwurf {d[:10]}... bitte selbst pruefen/loeschen (V1 loescht nie)")
    if res.status == "PREVIEW":
        _out("Vorschau. Ausfuehren mit: python -m src.cli undo --run-id " + res.run_id + " --apply")
    if res.status == "CONFLICT":
        raise ConflictError("Undo refused: mailbox changed since the run", code="UNDO_CONFLICT")
    return EXIT_OK


def cmd_auth(args: argparse.Namespace) -> int:
    profile = Profile(args.profile)
    _out(
        f"Google-Anmeldung fuer Profil {profile.value.upper()} - Scopes: "
        + ", ".join(s.rsplit("/", 1)[-1] for s in PROFILE_SCOPES[profile].request)
    )
    granted = run_consent_flow(
        profile, paths.client_secret_path(), paths.token_path(profile.value), paths.token_meta_path(profile.value)
    )
    _out("AUTH = PASS | gewaehrte Scopes: " + ", ".join(sorted(s.rsplit("/", 1)[-1] for s in granted)))
    return EXIT_OK


def cmd_audit_verify(args: argparse.Namespace) -> int:
    with _open_ledger() as ledger:
        ok, msg = ledger.verify()
    _out(f"AUDIT = {'PASS' if ok else 'FAIL'} ({msg})")
    return EXIT_OK if ok else 5


def cmd_doctor(args: argparse.Namespace) -> int:
    from .gmail_client import guard_self_test
    from .policy import self_test

    results: list[tuple[str, str, str]] = []

    def check(name: str, fn: Callable[[], str]) -> None:
        try:
            results.append((name, "PASS", fn()))
        except GmailAutomationError as exc:
            results.append((name, "FAIL", f"{exc.code}: {exc}"))
        except Exception as exc:  # noqa: BLE001 - doctor reports, never crashes
            results.append((name, "FAIL", exc.__class__.__name__))

    def py() -> str:
        if sys.version_info < (3, 12):  # noqa: UP036 - doctor reports a wrong interpreter clearly
            raise GmailAutomationError("Python >= 3.12 required", code="PYTHON_VERSION")
        return sys.version.split()[0]

    def deps() -> str:
        import google.auth  # noqa: F401
        import google_auth_oauthlib  # noqa: F401
        import googleapiclient  # noqa: F401
        import yaml  # noqa: F401

        return "google-api-python-client, google-auth, oauthlib, PyYAML"

    def cfg() -> str:
        c = load_config(Path(args.config))
        return f"{len(c.rules)} rules, capabilities={sorted(c.capabilities) or 'none'}"

    def blocks() -> str:
        p, g = self_test(), guard_self_test()
        if not (all(p.values()) and all(g.values())):
            raise GmailAutomationError(f"self-test failed {p} {g}", code="BLOCK_SELFTEST")
        return "send/draft-send/delete/trash blocked (policy + adapter)"

    def secrets_loc() -> str:
        notes = []
        cs = paths.client_secret_path()
        check_secret_location(cs)
        notes.append("client_secret " + ("ok" if cs.exists() else "fehlt (Schritt 1 der Anleitung)"))
        for prof in Profile:
            tp = paths.token_path(prof.value)
            check_secret_location(tp)
            notes.append(f"token_{prof.value} " + ("vorhanden" if tp.exists() else "fehlt"))
        return "; ".join(notes) + f" | {paths.data_dir()}"

    def repo_hygiene() -> str:
        bad = [
            p.name
            for pat in ("credentials*.json", "client_secret*.json", "token*.json", ".env")
            for p in paths.PROJECT_ROOT.rglob(pat)
            if ".venv" not in p.parts and "node_modules" not in p.parts
        ]
        if bad:
            raise GmailAutomationError(f"secret-like files inside project: {sorted(set(bad))}", code="REPO_SECRETS")
        return "no secret files in project tree"

    def forbidden() -> str:
        tool = paths.PROJECT_ROOT / "tools" / "forbidden_scan.py"
        r = subprocess.run(  # noqa: S603 - fixed interpreter + fixed in-repo tool, no user input
            [sys.executable, str(tool)],
            capture_output=True,
            text=True,
            cwd=paths.PROJECT_ROOT,
            timeout=60,
            check=False,
        )
        if r.returncode != 0:
            raise GmailAutomationError(r.stdout.strip()[-300:], code="FORBIDDEN_SCAN")
        return "no forbidden Gmail calls in src/"

    def audit() -> str:
        if not paths.audit_db_path().exists():
            return "noch kein Audit (erster Lauf legt es an)"
        with _open_ledger() as led:
            ok, msg = led.verify()
            if not ok:
                raise GmailAutomationError(msg, code="AUDIT_FAIL")
            return msg + f", offene Aktionen {len(led.pending())}"

    def tokens() -> str:
        out = []
        for prof in Profile:
            if paths.token_path(prof.value).exists():
                if args.online:
                    load_credentials(prof, paths.token_path(prof.value))
                    out.append(f"{prof.value}: scopes ok")
                else:
                    out.append(f"{prof.value}: vorhanden (online pruefen mit --online)")
        return "; ".join(out) or "keine Tokens (auth --profile observe)"

    for name, fn in (
        ("PYTHON", py),
        ("DEPENDENCIES", deps),
        ("CONFIG", cfg),
        ("SEND/DELETE BLOCK", blocks),
        ("SECRET LOCATIONS", secrets_loc),
        ("REPO HYGIENE", repo_hygiene),
        ("FORBIDDEN SCAN", forbidden),
        ("AUDIT", audit),
        ("OAUTH TOKENS", tokens),
    ):
        check(name, fn)
    for name, status, detail in results:
        _out(f"{name:<18} = {status}  {detail}")
    return EXIT_OK if all(s == "PASS" for _, s, _ in results) else 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m src.cli", description="GMAIL-AUTOMATION (Standard: DRY-RUN)")
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    def with_config(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--config", default=str(paths.default_config_path()))

    d = sub.add_parser("doctor", help="Umgebung, Konfiguration, Sperren und Audit pruefen")
    with_config(d)
    d.add_argument("--online", action="store_true", help="Token-Scopes live bei Google pruefen")
    a = sub.add_parser("auth", help="Google-Anmeldung fuer ein Profil (Browser)")
    a.add_argument("--profile", choices=[x.value for x in Profile], default="observe")
    s = sub.add_parser("scan", help="Nur lesen + klassifizieren (immer DRY-RUN)")
    with_config(s)
    s.add_argument("--max", type=int)
    r = sub.add_parser("run", help="Lauf; ohne --apply DRY-RUN")
    with_config(r)
    r.add_argument("--max", type=int)
    r.add_argument("--apply", action="store_true", help="Postfach-Aenderungen ausdruecklich erlauben")
    st = sub.add_parser("status", help="Letzte Laeufe + Audit-Integritaet")
    st.add_argument("--runs", type=int, default=10)
    u = sub.add_parser("undo", help="Lauf rueckgaengig machen (ohne --apply nur Vorschau)")
    with_config(u)
    g = u.add_mutually_exclusive_group(required=True)
    g.add_argument("--last-run", action="store_true")
    g.add_argument("--run-id")
    u.add_argument("--apply", action="store_true")
    cc = sub.add_parser("config-check", help="Konfiguration validieren")
    with_config(cc)
    sub.add_parser("audit-verify", help="Hash-Kette des Audit-Ledgers pruefen")
    return p


def main(argv: list[str] | None = None, *, service_factory: ServiceFactory | None = None) -> int:
    try:
        sys.stdout.reconfigure(errors="replace")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass
    args = build_parser().parse_args(argv)
    _setup_logging(args.verbose)
    factory = service_factory or default_service_factory
    try:
        if args.command == "doctor":
            return cmd_doctor(args)
        if args.command == "auth":
            return cmd_auth(args)
        if args.command == "scan":
            args.apply = False  # scan is observe-only by construction
            return cmd_scan_or_run(args, factory)
        if args.command == "run":
            return cmd_scan_or_run(args, factory)
        if args.command == "status":
            return cmd_status(args)
        if args.command == "undo":
            return cmd_undo(args, factory)
        if args.command == "config-check":
            return cmd_config_check(args)
        if args.command == "audit-verify":
            return cmd_audit_verify(args)
    except GmailAutomationError as exc:
        _out(f"ABBRUCH ({exc.code}): {exc}")
        return exc.exit_code
    except KeyboardInterrupt:
        _out("ABBRUCH durch Benutzer - offene Aktionen werden beim naechsten APPLY-Lauf abgeglichen.")
        return 130
    return 1  # pragma: no cover


if __name__ == "__main__":
    raise SystemExit(main())
