"""Command line: doctor | auth | scan | run | status | undo | config-check | audit-verify | audit-rebaseline.

Default is always DRY-RUN. Mailbox changes need the explicit flag --apply, the APPLY
OAuth profile and an enabled capability in the config. No environment variable or
config value can switch APPLY on.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import logging
import logging.handlers
import subprocess
import sys
from collections.abc import Callable
from importlib import metadata
from pathlib import Path
from typing import Any

from . import __version__, paths
from .audit import AuditLedger
from .auth import (
    PROFILE_SCOPES,
    build_gmail_service,
    check_secret_location,
    load_credentials,
    make_refresher,
    run_consent_flow,
)
from .config import Config, load_config
from .engine import MESSAGE_SCOPED_CODES, QUARANTINE_AFTER, Engine, new_run_id
from .errors import (
    EXIT_INTERNAL,
    EXIT_PARTIAL,
    AuditUnavailableError,
    ConflictError,
    FailClosed,
    GmailAutomationError,
)
from .gmail_client import GmailClient
from .lock import SingleInstanceLock
from .policy import PolicyContext, Profile
from .redaction import RedactingFilter, redact

EXIT_OK = 0
RUN_DEADLINE_SECONDS = 30 * 60  # one run never holds the instance lock longer than this


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
    return build_gmail_service(creds, profile), make_refresher(creds)


def _new_client(service: Any, ctx: PolicyContext, refresh: Callable[[], None] | None) -> GmailClient:
    return GmailClient(service, ctx, refresh_credentials=refresh, deadline_seconds=RUN_DEADLINE_SECONDS)


def _open_ledger(*, check_anchor: bool = True) -> AuditLedger:
    try:
        paths.ensure_private_dir(paths.data_dir())
    except OSError as exc:
        raise AuditUnavailableError(
            f"Data folder not writable ({exc.__class__.__name__}): {paths.data_dir()}", code="DATA_DIR_UNWRITABLE"
        ) from None
    return AuditLedger(paths.audit_db_path(), check_anchor=check_anchor)


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
        client = _new_client(service, ctx, refresh)
        engine = Engine(
            client, cfg, ctx, ledger, out=_out, retry_quarantined=bool(getattr(args, "retry_quarantined", False))
        )
        summary = engine.run()
    _out("")
    for line in summary.gate_lines():
        _out(line)
    extras = []
    for label, value in (
        ("FEHLGESCHLAGEN", summary.message_failures),
        ("QUARANTAENE", summary.quarantined),
        ("MANUELL_GEAENDERT", summary.human_override),
        ("ABWEICHUNG", summary.drift),
    ):
        if value:
            extras.append(f"{label} = {value}")
    if extras:
        _out(" | ".join(extras))
    _out(f"RUN_ID = {summary.run_id} | STATUS = {summary.status}")
    if engine.error is not None:
        _out(f"FEHLER: {engine.error}")
        return engine.error.exit_code
    if summary.status == "PARTIAL":
        _out("Teilweise erfolgreich - Details: python -m src.cli status")
        return EXIT_PARTIAL
    return EXIT_OK


def cmd_status(args: argparse.Namespace) -> int:
    with _open_ledger() as ledger:
        ok, msg = ledger.verify()
        _out(f"AUDIT = {'PASS' if ok else 'FAIL'} ({msg})")
        pend = ledger.pending()
        _out(f"OFFENE AKTIONEN = {len(pend)}" + (" (naechster APPLY-Lauf gleicht ab)" if pend else ""))
        quarantined = ledger.quarantined(MESSAGE_SCOPED_CODES, QUARANTINE_AFTER)
        _out(
            f"QUARANTAENE = {len(quarantined)}"
            + (" (erneut versuchen: run --apply --retry-quarantined)" if quarantined else "")
        )
        for mid in quarantined[:20]:
            _out(f"  Nachricht {mid[:10]}...")
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
        client = _new_client(service, ctx, refresh)
        res = undo_run(client, cfg, ctx, ledger, run_id, apply=bool(args.apply), out=_out)
    _out(f"UNDO = {res.status} | Ziel-Lauf {res.run_id} | Undo-Lauf {res.undo_run_id}")
    for c in res.conflicts:
        hint = " (erst den spaeteren Lauf rueckgaengig machen)" if c["reason"] == "LATER_RUN" else ""
        _out(f"  CONFLICT {c['message_id'][:8]}... {c['reason']} - Postfach unveraendert{hint}")
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
    if res.status == "ROLLED_BACK":
        _out(f"Undo fehlgeschlagen ({res.error_code}) und vollstaendig zurueckgerollt - Postfach wie vor dem Undo.")
        return FailClosed.exit_code
    if res.status == "PARTIAL":
        _out(f"UNDO TEILWEISE ({res.error_code}) - bitte diese Nachrichten pruefen:")
        for mid in res.still_reverted:
            _out(f"  zurueckgesetzt geblieben: {mid[:10]}...")
        for mid in res.unknown:
            _out(f"  Zustand unbekannt (naechster APPLY-Lauf gleicht ab): {mid[:10]}...")
        return EXIT_PARTIAL
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


def cmd_audit_rebaseline(args: argparse.Namespace) -> int:
    """Explicit, audited repair of the rollback anchor (never automatic)."""
    with SingleInstanceLock(paths.lock_path()), _open_ledger(check_anchor=False) as ledger:
        ok, msg = ledger.verify_chain()
        seq, _ = ledger.head()
        _out(f"HASH-KETTE = {'PASS' if ok else 'FAIL'} ({msg}) | Eintraege: {seq}")
        if not ok:
            _out("Neu-Verankerung abgelehnt: die Kette selbst ist beschaedigt.")
            return 5
        verdict, detail = ledger.anchor_verdict()
        _out(f"ANKER-BEFUND = {verdict} ({detail})")
        if verdict == "OK":
            _out("Nichts zu tun - der Anker passt zum Ledger.")
            return EXIT_OK
        extra = {"AUDIT_ROLLBACK": "accept_rollback", "AUDIT_HEAD_MISMATCH": "accept_rewrite"}.get(verdict)
        if verdict == "AUDIT_ROLLBACK":
            _out("WARNUNG: Das Ledger ist AELTER als der Anker (Backup zurueckgespielt?). Neu-Verankern")
            _out("verwirft die Historie seit dem Backup: Idempotenz und Undo fuer diese Laeufe gehen verloren.")
        if verdict == "AUDIT_HEAD_MISMATCH":
            _out("WARNUNG: Die Ledger-Historie wurde UMGESCHRIEBEN. Nur fortfahren, wenn Sie das selbst waren.")
        accepted = {"accept_rollback": args.accept_rollback, "accept_rewrite": args.accept_rewrite}
        missing_flag = bool(extra) and not accepted.get(extra or "", False)
        if not args.confirm or missing_flag:
            flag = f" --{extra.replace('_', '-')}" if extra else ""
            _out("Vorschau. Ausfuehren mit:")
            _out(f"  python -m src.cli audit-rebaseline --confirm{flag}")
            return 2
        ledger.rebaseline(run_id=new_run_id(), reason="cli", verdict=verdict)
    _out(f"AUDIT-ANKER = NEU GESETZT (Befund {verdict}, Ereignis HEAD_REBASELINE protokolliert)")
    return EXIT_OK


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
        names = ("google-api-python-client", "google-auth", "google-auth-oauthlib", "google-auth-httplib2", "PyYAML")
        found = [f"{n} {metadata.version(n)}" for n in names]
        marker = paths.PROJECT_ROOT / ".venv" / ".bootstrap-ok"
        if marker.exists():
            want = hashlib.sha256((paths.PROJECT_ROOT / "requirements-lock.txt").read_bytes()).hexdigest()
            if want not in marker.read_text(encoding="utf-8", errors="replace"):
                raise GmailAutomationError(
                    "requirements-lock.txt changed since setup - run scripts/bootstrap.ps1 again", code="DEPS_STALE"
                )
        return ", ".join(found)

    def cfg() -> str:
        c = load_config(Path(args.config))
        return f"{len(c.rules)} rules, capabilities={sorted(c.capabilities) or 'none'}"

    def blocks() -> str:
        from .gmail_client import transport_self_test

        p, g, t = self_test(), guard_self_test(), transport_self_test()
        if not (all(p.values()) and all(g.values()) and all(t.values())):
            raise GmailAutomationError(f"self-test failed {p} {g} {t}", code="BLOCK_SELFTEST")
        return "send/draft-send/delete/trash blocked (policy + adapter + transport)"

    def secrets_loc() -> str:
        notes = []
        cs = paths.client_secret_path()
        check_secret_location(cs)
        notes.append("client_secret " + ("ok" if cs.exists() else "fehlt (README, Schnellstart Schritt 2)"))
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
        return "no forbidden Gmail calls / transports / reflection in src/ and tools/"

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
    # allow_abbrev=False: "--app" / "--a" must never be accepted as "--apply"
    p = argparse.ArgumentParser(
        prog="python -m src.cli", description="GMAIL-AUTOMATION (Standard: DRY-RUN)", allow_abbrev=False
    )
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    def with_config(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--config", default=str(paths.default_config_path()))

    d = sub.add_parser("doctor", help="Umgebung, Konfiguration, Sperren und Audit pruefen", allow_abbrev=False)
    with_config(d)
    d.add_argument("--online", action="store_true", help="Token-Scopes live bei Google pruefen")
    a = sub.add_parser("auth", help="Google-Anmeldung fuer ein Profil (Browser)", allow_abbrev=False)
    a.add_argument("--profile", choices=[x.value for x in Profile], default="observe")
    s = sub.add_parser("scan", help="Nur lesen + klassifizieren (immer DRY-RUN)", allow_abbrev=False)
    with_config(s)
    s.add_argument("--max", type=int)
    r = sub.add_parser("run", help="Lauf; ohne --apply DRY-RUN", allow_abbrev=False)
    with_config(r)
    r.add_argument("--max", type=int)
    r.add_argument("--apply", action="store_true", help="Postfach-Aenderungen ausdruecklich erlauben")
    r.add_argument(
        "--retry-quarantined", action="store_true", help="Nachrichten in Quarantaene in diesem Lauf erneut versuchen"
    )
    st = sub.add_parser("status", help="Letzte Laeufe + Audit-Integritaet", allow_abbrev=False)
    st.add_argument("--runs", type=int, default=10)
    u = sub.add_parser("undo", help="Lauf rueckgaengig machen (ohne --apply nur Vorschau)", allow_abbrev=False)
    with_config(u)
    g = u.add_mutually_exclusive_group(required=True)
    g.add_argument("--last-run", action="store_true")
    g.add_argument("--run-id")
    u.add_argument("--apply", action="store_true")
    cc = sub.add_parser("config-check", help="Konfiguration validieren", allow_abbrev=False)
    with_config(cc)
    sub.add_parser("audit-verify", help="Hash-Kette des Audit-Ledgers pruefen", allow_abbrev=False)
    rb = sub.add_parser(
        "audit-rebaseline", help="Audit-Anker nach Pruefung neu setzen (nur mit --confirm)", allow_abbrev=False
    )
    rb.add_argument("--confirm", action="store_true")
    rb.add_argument("--accept-rollback", action="store_true", help="nur bei Befund AUDIT_ROLLBACK")
    rb.add_argument("--accept-rewrite", action="store_true", help="nur bei Befund AUDIT_HEAD_MISMATCH")
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
        if args.command == "audit-rebaseline":
            return cmd_audit_rebaseline(args)
    except GmailAutomationError as exc:
        _out(f"ABBRUCH ({exc.code}): {exc}")
        return exc.exit_code
    except KeyboardInterrupt:
        _out("ABBRUCH durch Benutzer - offene Aktionen werden beim naechsten APPLY-Lauf abgeglichen.")
        return 130
    except Exception as exc:  # noqa: BLE001 - last line of defence: no raw traceback, type name only
        logging.getLogger("gmail_automation").error("internal error %s", type(exc).__name__)
        _out(f"ABBRUCH (INTERNAL_{type(exc).__name__}): unerwarteter Fehler - nichts wurde unkontrolliert geaendert.")
        return EXIT_INTERNAL
    return 1  # pragma: no cover


if __name__ == "__main__":
    raise SystemExit(main())
