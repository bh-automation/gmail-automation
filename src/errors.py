"""Exception hierarchy. Every error maps to a stable exit code; nothing fails open."""

from __future__ import annotations


class GmailAutomationError(Exception):
    """Base class. `code` is a stable machine-readable error code."""

    exit_code = 1

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code or type(self).__name__.upper()


class PolicyViolation(GmailAutomationError):
    exit_code = 2


class ConfigError(GmailAutomationError):
    exit_code = 2


class AuthError(GmailAutomationError):
    exit_code = 3


class ScopeError(AuthError):
    exit_code = 3


class SecretLocationError(AuthError):
    exit_code = 3


class ConflictError(GmailAutomationError):
    exit_code = 4


class AuditIntegrityError(GmailAutomationError):
    exit_code = 5


class AuditUnavailableError(GmailAutomationError):
    exit_code = 5


class LockError(GmailAutomationError):
    exit_code = 6


class GmailApiError(GmailAutomationError):
    exit_code = 7

    def __init__(self, message: str, *, code: str | None = None, status: int | None = None) -> None:
        super().__init__(message, code=code)
        self.status = status


class TransientExhaustedError(GmailApiError):
    """Retries for a transient error (429/5xx/network) were exhausted."""


class AmbiguousWriteError(GmailApiError):
    """A non-idempotent write failed in a way that leaves its outcome unknown."""


class FailClosed(GmailAutomationError):
    """Raised to stop a run after a mutation failed. Already-applied work stays audited."""

    exit_code = 8


class MimeError(GmailAutomationError):
    exit_code = 1
