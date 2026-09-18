"""Content-addressed record cache keyed on wheel hash and analyser identity.

Scanning tens of thousands of wheels is only cheap the second time if the cache is
trustworthy, and a cache that serves a stale record is worse than no cache at all. So
the key covers everything that can change a record for an unchanged wheel: the wheel's
own hash, the ruleset version, the schema version, the analyser version and the
evidence level, plus the tool version because the record embeds it.

`analyzer_version` is the one people forget. Without it, fixing a bug in the ELF reader
would leave every previously scanned wheel serving the records that bug produced.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path

from . import ANALYZER_VERSION, SCHEMA_VERSION, __version__

_CACHE_DIR_NAME = "wheel-crypto-scan"


def default_cache_root() -> Path:
    base = os.environ.get("XDG_CACHE_HOME")
    root = Path(base) if base else Path.home() / ".cache"
    return root / _CACHE_DIR_NAME


class RecordCache:
    """A read-through cache of serialised records, keyed by content."""

    def __init__(
        self,
        root: Path | None = None,
        *,
        ruleset_version: str,
        evidence_level: str,
        analyzer_version: int = ANALYZER_VERSION,
        schema_version: int = SCHEMA_VERSION,
        tool_version: str = __version__,
        limits: str = "",
        enabled: bool = True,
    ) -> None:
        self.enabled = enabled
        self.root = Path(root) if root is not None else default_cache_root()
        self._salt = "|".join(
            (
                str(schema_version),
                str(analyzer_version),
                ruleset_version,
                evidence_level,
                tool_version,
                # Scan limits change what the binary layer looked at, so a constrained
                # run must not poison the cache for an unconstrained one.
                limits,
            )
        )

    def key(self, wheel_sha256: str, filename: str) -> str:
        """Identify a record by content *and* filename.

        The filename is authoritative for the record's name, version and tags, so two
        byte-identical archives published under different names are two different
        records. Keying on the digest alone would make one of them disappear.
        """
        return hashlib.sha256(f"{wheel_sha256}|{filename}|{self._salt}".encode()).hexdigest()

    def _path(self, wheel_sha256: str, filename: str) -> Path:
        key = self.key(wheel_sha256, filename)
        return self.root / key[:2] / f"{key}.json"

    def get(self, wheel_sha256: str, filename: str) -> str | None:
        """The cached record line, or None. A damaged entry is a miss, never an error."""
        if not self.enabled:
            return None
        try:
            return self._path(wheel_sha256, filename).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None

    def put(self, wheel_sha256: str, filename: str, line: str) -> None:
        """Store a record line. Written atomically so an interrupted run leaves no half-entry."""
        if not self.enabled:
            return
        path = self._path(wheel_sha256, filename)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            handle, temporary = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
            try:
                with os.fdopen(handle, "w", encoding="utf-8") as stream:
                    stream.write(line)
                os.replace(temporary, path)
            except BaseException:
                Path(temporary).unlink(missing_ok=True)
                raise
        except OSError:
            # A cache that cannot be written is a performance problem, not a scan failure.
            return
