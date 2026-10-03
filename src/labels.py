"""Label resolver/cache. Only application labels (configured prefix) are ever touched."""

from __future__ import annotations

from typing import Any

from .config import Config
from .errors import GmailApiError, PolicyViolation
from .gmail_client import GmailClient, LabelRef
from .policy import is_user_label_id


class LabelResolver:
    def __init__(self, client: GmailClient, cfg: Config) -> None:
        self._client = client
        self._cfg = cfg
        self.by_name: dict[str, LabelRef] = {}
        self.id_to_name: dict[str, str] = {}

    def refresh(self) -> None:
        by_name: dict[str, LabelRef] = {}
        id_to_name: dict[str, str] = {}
        for lab in self._client.list_labels():
            lid, name, ltype = str(lab.get("id", "")), str(lab.get("name", "")), str(lab.get("type", "user"))
            if ltype != "user" or not is_user_label_id(lid):
                continue
            id_to_name[lid] = name
            if name in self._cfg.app_labels:
                by_name[name] = LabelRef(lid, name)
        self.by_name, self.id_to_name = by_name, id_to_name

    def resolve(self, name: str) -> LabelRef | None:
        return self.by_name.get(name)

    def require(self, name: str) -> LabelRef:
        if name not in self._cfg.app_labels:
            raise PolicyViolation(f"Not an application label: {name}", code="LABEL_NOT_APPROVED")
        ref = self.by_name.get(name)
        if ref is None:
            raise GmailApiError(f"Application label missing in mailbox: {name}", code="LABEL_MISSING")
        return ref

    def missing(self, names: set[str]) -> list[str]:
        return sorted(n for n in names if n in self._cfg.app_labels and n not in self.by_name)

    def app_label_names(self, label_ids: Any) -> tuple[str, ...]:
        """Application label names present in a Gmail labelIds list (system/other labels ignored)."""
        names = {self.id_to_name.get(str(i), "") for i in (label_ids or [])}
        return tuple(sorted(n for n in names if n in self._cfg.app_labels))

    def create(self, name: str) -> LabelRef:
        ref = self._client.create_label(name)
        self.by_name[name] = ref
        self.id_to_name[ref.id] = name
        return ref
