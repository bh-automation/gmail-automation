"""OAuth profiles, scope validation and token-location checks.

* OBSERVE profile: gmail.readonly only. No mutation endpoint is reachable.
* APPLY profile: gmail.modify (+ optional gmail.labels). Needs a separate consent.
* The full-mail scope (mail.google.com root, allows permanent delete) is forbidden.

Granted scopes are verified at runtime against Google's own token-endpoint answer:
the refresh grant is executed WITHOUT a scope parameter, so Google reports every
scope attached to the stored refresh token. Anything unexpected fails closed.
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .errors import AuthError, ScopeError, SecretLocationError
from .paths import PROJECT_ROOT, enclosing_git_root, ensure_private_dir, is_within
from .policy import Profile

GMAIL = "https://www.googleapis.com/auth/gmail."
SCOPE_READONLY = GMAIL + "readonly"
SCOPE_MODIFY = GMAIL + "modify"
SCOPE_LABELS = GMAIL + "labels"

FORBIDDEN_SCOPES = frozenset(
    {
        "https://mail.google.com/",
        GMAIL + "send",
        GMAIL + "insert",
        GMAIL + "settings.basic",
        GMAIL + "settings.sharing",
    }
)


@dataclass(frozen=True)
class ScopeProfile:
    request: tuple[str, ...]
    required: frozenset[str]
    allowed: frozenset[str]


PROFILE_SCOPES: dict[Profile, ScopeProfile] = {
    Profile.OBSERVE: ScopeProfile(
        request=(SCOPE_READONLY,),
        required=frozenset({SCOPE_READONLY}),
        allowed=frozenset({SCOPE_READONLY}),
    ),
    Profile.APPLY: ScopeProfile(
        request=(SCOPE_MODIFY, SCOPE_LABELS),
        required=frozenset({SCOPE_MODIFY}),
        allowed=frozenset({SCOPE_MODIFY, SCOPE_LABELS, SCOPE_READONLY}),
    ),
}

assert not any(s in FORBIDDEN_SCOPES for p in PROFILE_SCOPES.values() for s in p.allowed)  # noqa: S101


def _normalize(scopes: Any) -> frozenset[str]:
    """Accept only None, a space-separated string or a list/tuple/set of strings; anything else fails closed."""
    if scopes is None:
        return frozenset()
    if isinstance(scopes, str):
        scopes = scopes.split()
    if not isinstance(scopes, list | tuple | set | frozenset) or not all(isinstance(s, str) for s in scopes):
        raise ScopeError("Granted scopes have an unexpected format - refusing to continue", code="SCOPE_FORMAT")
    return frozenset(s.strip() for s in scopes if s and s.strip())


def validate_scopes(profile: Profile, granted: Any) -> frozenset[str]:
    """Fail closed unless required <= granted <= allowed and nothing forbidden is present."""
    g = _normalize(granted)
    spec = PROFILE_SCOPES[profile]
    forbidden = g & FORBIDDEN_SCOPES
    if forbidden:
        raise ScopeError(
            f"Forbidden scope granted: {sorted(forbidden)}. Revoke access and re-authorise.", code="FORBIDDEN_SCOPE"
        )
    missing = spec.required - g
    if missing:
        raise ScopeError(f"Profile {profile.value} is missing scope(s) {sorted(missing)}", code="MISSING_SCOPE")
    extra = g - spec.allowed
    if extra:
        raise ScopeError(
            f"Profile {profile.value} has unexpected scope(s) {sorted(extra)} - refusing broader privilege",
            code="UNEXPECTED_SCOPE",
        )
    return g


def check_secret_location(path: Path, *, project_root: Path = PROJECT_ROOT, must_exist: bool = False) -> Path:
    """Secrets must live outside the repository / any Git work tree and must not be symlinks."""
    p = Path(path).expanduser()
    if ".." in p.parts:
        raise SecretLocationError("Secret path may not contain '..'", code="PATH_TRAVERSAL")
    if p.is_symlink():
        raise SecretLocationError("Secret path may not be a symlink", code="SECRET_SYMLINK")
    resolved = p.resolve(strict=False)
    if is_within(resolved, project_root):
        raise SecretLocationError(
            f"Secret file inside the project directory is not allowed: {p.name}", code="SECRET_IN_REPO"
        )
    git_root = enclosing_git_root(resolved.parent)
    if git_root is not None:
        raise SecretLocationError(f"Secret file inside a Git work tree is not allowed: {p.name}", code="SECRET_IN_GIT")
    if must_exist and not resolved.is_file():
        raise AuthError(f"Required file not found: {p.name} (expected in {resolved.parent})", code="SECRET_MISSING")
    if os.name == "posix" and resolved.exists():
        mode = stat.S_IMODE(resolved.stat().st_mode)
        if mode & 0o077:
            raise SecretLocationError(
                f"{p.name} is readable by other users (mode {oct(mode)}); chmod 600", code="SECRET_PERMISSIONS"
            )
        parent_mode = stat.S_IMODE(resolved.parent.stat().st_mode)
        if parent_mode & 0o022:
            raise SecretLocationError(
                f"Folder of {p.name} is writable by other users (mode {oct(parent_mode)}); chmod 700",
                code="SECRET_DIR_PERMISSIONS",
            )
    return resolved


def _default_refresh_grant() -> Callable[..., Any]:
    from google.oauth2 import reauth

    return reauth.refresh_grant


def _default_request() -> Any:
    """Token-refresh transport that can reach ONLY the OAuth token endpoint (POST, no redirects)."""
    import requests
    from google.auth.transport.requests import Request

    from .errors import PolicyViolation

    class _TokenOnlySession(requests.Session):
        def request(self, method: str | bytes, url: str | bytes, *args: Any, **kwargs: Any) -> Any:
            m = method.decode() if isinstance(method, bytes) else method
            u = url.decode() if isinstance(url, bytes) else url
            if m.upper() != "POST" or u != TOKEN_URI:
                raise PolicyViolation("Refresh transport: token endpoint only", code="TRANSPORT_TOKEN")
            kwargs["allow_redirects"] = False
            return super().request(m, u, *args, **kwargs)

    return Request(session=_TokenOnlySession())


TOKEN_URI = "https://oauth2.googleapis.com/token"  # noqa: S105 - endpoint URL, not a secret


def _read_token(path: Path) -> dict[str, Any]:
    try:
        info = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise AuthError("Token file unreadable or malformed - run `auth` again", code="TOKEN_MALFORMED") from None
    if not isinstance(info, dict) or not all(
        isinstance(info.get(k), str) and info.get(k) for k in ("refresh_token", "client_id", "client_secret")
    ):
        raise AuthError("Token file lacks refresh_token/client_id/client_secret", code="TOKEN_MALFORMED")
    return info


def load_credentials(
    profile: Profile,
    token_file: Path,
    *,
    project_root: Path = PROJECT_ROOT,
    refresh_grant: Callable[..., Any] | None = None,
    request: Any = None,
) -> tuple[Any, frozenset[str]]:
    """Load + refresh the profile token and validate the scopes Google actually granted."""
    path = check_secret_location(token_file, project_root=project_root, must_exist=True)
    info = _read_token(path)
    grant = refresh_grant or _default_refresh_grant()
    req = request if request is not None else _default_request()
    try:
        access_token, refresh_token, expiry, grant_response, rapt = grant(
            req, TOKEN_URI, info["refresh_token"], info["client_id"], info["client_secret"], scopes=None
        )
    except Exception as exc:  # noqa: BLE001 - map every refresh failure to a closed AuthError
        raise AuthError(
            f"Token refresh failed ({exc.__class__.__name__}) - run `auth --profile {profile.value}` again",
            code="REFRESH_FAILED",
        ) from None
    if not isinstance(grant_response, dict) or "scope" not in grant_response:
        raise ScopeError("Google did not report granted scopes - refusing to continue", code="SCOPE_UNKNOWN")
    granted = validate_scopes(profile, grant_response.get("scope"))

    from google.oauth2.credentials import Credentials

    creds = Credentials(
        token=access_token,
        refresh_token=refresh_token or info["refresh_token"],
        token_uri=TOKEN_URI,
        client_id=info["client_id"],
        client_secret=info["client_secret"],
        scopes=sorted(granted),
        expiry=expiry,
        rapt_token=rapt,
    )
    return creds, granted


def _write_private(path: Path, content: str) -> None:
    ensure_private_dir(path.parent)
    tmp = path.with_suffix(path.suffix + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(tmp, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.replace(tmp, path)
    if os.name == "posix":
        os.chmod(path, 0o600)


def run_consent_flow(
    profile: Profile,
    client_secret_file: Path,
    token_file: Path,
    meta_file: Path,
    *,
    project_root: Path = PROJECT_ROOT,
    flow_factory: Callable[..., Any] | None = None,
    refresh_grant: Callable[..., Any] | None = None,
    request: Any = None,
) -> frozenset[str]:
    """Interactive Google consent (browser). The token is only stored if its scopes validate."""
    secret = check_secret_location(client_secret_file, project_root=project_root, must_exist=True)
    check_secret_location(token_file, project_root=project_root)
    spec = PROFILE_SCOPES[profile]
    if flow_factory is None:
        from google_auth_oauthlib.flow import InstalledAppFlow

        flow_factory = InstalledAppFlow.from_client_secrets_file
    flow = flow_factory(str(secret), scopes=list(spec.request))
    creds = flow.run_local_server(
        port=0,
        open_browser=True,
        timeout_seconds=300,
        prompt="consent",
        authorization_prompt_message="Browser-Anmeldung bei Google ({url})",
        success_message="Anmeldung abgeschlossen. Dieses Fenster kann geschlossen werden.",
    )
    if not getattr(creds, "refresh_token", None):
        raise AuthError("Google returned no refresh token - remove the app grant and retry", code="NO_REFRESH")

    grant = refresh_grant or _default_refresh_grant()
    req = request if request is not None else _default_request()
    try:
        _, _, _, grant_response, _ = grant(
            req, TOKEN_URI, creds.refresh_token, creds.client_id, creds.client_secret, scopes=None
        )
    except Exception as exc:  # noqa: BLE001
        raise AuthError(f"Post-consent verification failed ({exc.__class__.__name__})", code="REFRESH_FAILED") from None
    granted = validate_scopes(profile, (grant_response or {}).get("scope"))
    token_json = json.dumps(
        {
            "refresh_token": creds.refresh_token,
            "client_id": creds.client_id,
            "client_secret": creds.client_secret,
            "token_uri": TOKEN_URI,
            "scopes": sorted(granted),
        }
    )
    _write_private(token_file, token_json)
    _write_private(
        meta_file,
        json.dumps(
            {
                "profile": profile.value,
                "granted_scopes": sorted(granted),
                "created_utc": datetime.now(UTC).isoformat(timespec="seconds"),
            },
            indent=2,
        ),
    )
    return granted


def make_refresher(creds: Any) -> Callable[[], None]:
    """Explicit single credential refresh used by GmailClient after a 401 (token endpoint only)."""

    def refresh() -> None:
        creds.refresh(_default_request())

    return refresh


def build_gmail_service(creds: Any, profile: Profile) -> Any:
    """googleapiclient service whose ONLY transport is the allow-listing GuardedHttp.

    Transport-level 401 auto-refresh is disabled (refresh_status_codes=()), so GmailClient's
    single explicit refresh is the only 401-driven refresh. Expiry-based refresh before a
    request still works and goes through the guarded transport to the token endpoint.
    """
    from google_auth_httplib2 import AuthorizedHttp
    from googleapiclient.discovery import build

    from .gmail_client import GuardedHttp

    authed = AuthorizedHttp(creds, http=GuardedHttp(profile), refresh_status_codes=())
    return build("gmail", "v1", http=authed, cache_discovery=False, static_discovery=True)
