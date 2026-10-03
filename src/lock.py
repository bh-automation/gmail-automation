"""Single-instance lock (OS-level, released automatically if the process dies)."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import IO

from .errors import LockError


class SingleInstanceLock:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._fh: IO[str] | None = None

    def acquire(self) -> SingleInstanceLock:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fh = open(self.path, "a+", encoding="ascii")  # noqa: SIM115 - held for the process lifetime
        try:
            if sys.platform == "win32":
                import msvcrt

                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            fh.close()
            raise LockError("Another GMAIL-AUTOMATION instance is running (lock held)", code="LOCKED") from None
        fh.seek(0)
        fh.truncate()
        fh.write(str(os.getpid()))
        fh.flush()
        self._fh = fh
        return self

    def release(self) -> None:
        if self._fh is None:
            return
        try:
            if sys.platform == "win32":
                import msvcrt

                self._fh.seek(0)
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)
        finally:
            self._fh.close()
            self._fh = None

    def __enter__(self) -> SingleInstanceLock:
        return self.acquire()

    def __exit__(self, *exc: object) -> None:
        self.release()
