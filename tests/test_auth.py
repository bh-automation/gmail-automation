import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from src import auth
from src.auth import (
    FORBIDDEN_SCOPES,
    SCOPE_LABELS,
    SCOPE_MODIFY,
    SCOPE_READONLY,
    check_secret_location,
    load_credentials,
    run_consent_flow,
    validate_scopes,
)
from src.errors import AuthError, ScopeError, SecretLocationError
from src.policy import Profile

FULL_MAIL = "https://mail." + "google.com/"  # built at runtime; never as a literal in the repo
G = "https://www.googleapis.com/auth/gmail."


def test_full_mail_scope_is_forbidden_everywhere():
    assert FULL_MAIL in FORBIDDEN_SCOPES
    for profile in Profile:
        with pytest.raises(ScopeError) as e:
            validate_scopes(profile, [FULL_MAIL, SCOPE_READONLY, SCOPE_MODIFY])
        assert e.value.code == "FORBIDDEN_SCOPE"


@pytest.mark.parametrize("scope", [G + "send", G + "insert", G + "settings.basic", G + "settings.sharing"])
def test_send_and_settings_scopes_forbidden(scope):
    with pytest.raises(ScopeError):
        validate_scopes(Profile.APPLY, [SCOPE_MODIFY, scope])


def test_observe_profile_scopes():
    assert validate_scopes(Profile.OBSERVE, SCOPE_READONLY) == {SCOPE_READONLY}
    with pytest.raises(ScopeError) as e:  # broader than expected -> refuse
        validate_scopes(Profile.OBSERVE, [SCOPE_READONLY, SCOPE_MODIFY])
    assert e.value.code == "UNEXPECTED_SCOPE"
    with pytest.raises(ScopeError) as e:
        validate_scopes(Profile.OBSERVE, [])
    assert e.value.code == "MISSING_SCOPE"


def test_apply_profile_scopes():
    assert validate_scopes(Profile.APPLY, f"{SCOPE_MODIFY} {SCOPE_LABELS}") == {SCOPE_MODIFY, SCOPE_LABELS}
    with pytest.raises(ScopeError):  # compose would allow sending - not in allow-list
        validate_scopes(Profile.APPLY, [SCOPE_MODIFY, G + "compose"])
    with pytest.raises(ScopeError):
        validate_scopes(Profile.APPLY, [SCOPE_READONLY])
    with pytest.raises(ScopeError):
        validate_scopes(Profile.APPLY, [SCOPE_MODIFY, "openid", "email"])


# ---------------------------------------------------------------------------- token location
def test_secret_inside_project_refused():
    root = Path(auth.__file__).resolve().parents[1]
    with pytest.raises(SecretLocationError) as e:
        check_secret_location(root / "token_observe.json")
    assert e.value.code == "SECRET_IN_REPO"


def test_secret_path_traversal_refused(tmp_path):
    with pytest.raises(SecretLocationError) as e:
        check_secret_location(tmp_path / "a" / ".." / "token.json")
    assert e.value.code == "PATH_TRAVERSAL"


def test_secret_inside_any_git_tree_refused(tmp_path):
    repo = tmp_path / "other repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    with pytest.raises(SecretLocationError) as e:
        check_secret_location(repo / "sub" / "token_apply.json", project_root=tmp_path / "proj")
    assert e.value.code == "SECRET_IN_GIT"


def test_secret_symlink_and_permissions_refused(data_dir):
    target = data_dir / "real.json"
    target.write_text("{}", encoding="utf-8")
    link = data_dir / "token_observe.json"
    try:
        link.symlink_to(target)
    except OSError as exc:  # Windows without the symlink privilege (WinError 1314): nothing to test here
        pytest.skip(f"symlinks not permitted for this user ({exc.__class__.__name__})")
    with pytest.raises(SecretLocationError) as e:
        check_secret_location(link)
    assert e.value.code == "SECRET_SYMLINK"
    if os.name == "posix":
        os.chmod(target, 0o644)
        with pytest.raises(SecretLocationError) as e:
            check_secret_location(target)
        assert e.value.code == "SECRET_PERMISSIONS"
        os.chmod(target, 0o600)
        assert check_secret_location(target) == target.resolve()


# ---------------------------------------------------------------------------- runtime validation
def _token(data_dir, name="token_observe.json"):
    p = data_dir / name
    p.write_text(
        json.dumps({"refresh_token": "r" * 30, "client_id": "cid", "client_secret": "cs" * 8}), encoding="utf-8"
    )
    os.chmod(p, 0o600)
    return p


def _grant(scope):
    calls = []

    def grant(req, uri, refresh_token, client_id, client_secret, scopes=None):
        calls.append(scopes)
        return "access-token-value", refresh_token, None, ({"scope": scope} if scope is not None else {}), None

    grant.calls = calls
    return grant


def test_load_credentials_validates_google_reported_scopes(data_dir):
    tok = _token(data_dir)
    grant = _grant(SCOPE_READONLY)
    creds, granted = load_credentials(Profile.OBSERVE, tok, refresh_grant=grant, request=object())
    assert granted == {SCOPE_READONLY}
    assert grant.calls == [None], "refresh must not narrow scopes, so Google reports the full grant"
    assert creds.token == "access-token-value"


def test_load_credentials_refuses_broad_refresh_token(data_dir):
    tok = _token(data_dir)
    with pytest.raises(ScopeError) as e:
        load_credentials(Profile.OBSERVE, tok, refresh_grant=_grant(f"{SCOPE_READONLY} {FULL_MAIL}"), request=object())
    assert e.value.code == "FORBIDDEN_SCOPE"


def test_load_credentials_refuses_unknown_scope_report(data_dir):
    tok = _token(data_dir)
    with pytest.raises(ScopeError) as e:
        load_credentials(Profile.OBSERVE, tok, refresh_grant=_grant(None), request=object())
    assert e.value.code == "SCOPE_UNKNOWN"


def test_refresh_failure_and_malformed_token(data_dir):
    tok = _token(data_dir)

    def boom(*a, **k):
        raise RuntimeError("invalid_grant " + "ya29" + ".secret-should-not-leak")

    with pytest.raises(AuthError) as e:
        load_credentials(Profile.OBSERVE, tok, refresh_grant=boom, request=object())
    assert "secret-should-not-leak" not in str(e.value)
    tok.write_text("not json", encoding="utf-8")
    with pytest.raises(AuthError) as e:
        load_credentials(Profile.OBSERVE, tok, refresh_grant=_grant(SCOPE_READONLY), request=object())
    assert e.value.code == "TOKEN_MALFORMED"
    with pytest.raises(AuthError) as e:
        load_credentials(Profile.OBSERVE, data_dir / "missing.json", refresh_grant=_grant(SCOPE_READONLY))
    assert e.value.code == "SECRET_MISSING"


# ---------------------------------------------------------------------------- consent flow
class _Flow:
    def __init__(self, creds):
        self.creds = creds
        self.kwargs = None

    def run_local_server(self, **kwargs):
        self.kwargs = kwargs
        return self.creds


def _consent(data_dir, scope, profile=Profile.OBSERVE):
    secret = data_dir / "client_secret.json"
    secret.write_text("{}", encoding="utf-8")
    os.chmod(secret, 0o600)
    creds = SimpleNamespace(refresh_token="r" * 30, client_id="cid", client_secret="cs" * 8)
    flows = []

    def factory(path, scopes):
        f = _Flow(creds)
        f.scopes = scopes
        flows.append(f)
        return f

    granted = run_consent_flow(
        profile,
        secret,
        data_dir / f"token_{profile.value}.json",
        data_dir / f"token_{profile.value}.meta.json",
        flow_factory=factory,
        refresh_grant=_grant(scope),
        request=object(),
    )
    return granted, flows


def test_consent_stores_token_only_after_scope_validation(data_dir):
    granted, flows = _consent(data_dir, SCOPE_READONLY)
    assert granted == {SCOPE_READONLY}
    assert flows[0].scopes == [SCOPE_READONLY]
    assert flows[0].kwargs["prompt"] == "consent"
    tok = data_dir / "token_observe.json"
    assert tok.exists()
    if os.name == "posix":
        assert oct(os.stat(tok).st_mode & 0o777) == "0o600"
    meta = json.loads((data_dir / "token_observe.meta.json").read_text(encoding="utf-8"))
    assert meta["granted_scopes"] == [SCOPE_READONLY]


def test_consent_with_forbidden_scope_writes_nothing(data_dir):
    with pytest.raises(ScopeError):
        _consent(data_dir, f"{SCOPE_MODIFY} {FULL_MAIL}", profile=Profile.APPLY)
    assert not (data_dir / "token_apply.json").exists()


def test_apply_profile_requests_no_forbidden_scope(data_dir):
    _, flows = _consent(data_dir, SCOPE_MODIFY, profile=Profile.APPLY)
    assert set(flows[0].scopes) == {SCOPE_MODIFY, SCOPE_LABELS}
    assert not set(flows[0].scopes) & FORBIDDEN_SCOPES
