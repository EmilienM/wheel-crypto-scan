"""Scans one wheel end to end: archive, three layers, rules, verdict, record.

This is the unit of work a worker process runs. It never raises for a bad wheel: an
archive that cannot be opened at all still produces a full-shaped record carrying the
error, because a scan of thirty thousand wheels that stops on the first broken one is
not useful, and a wheel silently missing from the output is worse than a wheel marked
opaque.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import errors
from .engine import apply_rules
from .evidence import STAGE_ARCHIVE, ArtifactInventory, Evidence, ScanError
from .layers.binaries import scan_binaries
from .layers.inventory import build_inventory
from .layers.metadata import read_metadata
from .layers.python_ast import scan_python_files
from .linkage import resolve_linkage
from .record import build_record
from .ruleset import Ruleset, ScanPatterns
from .verdict import classify
from .wheelfile import ArchiveLimits, WheelArchive, hash_wheel


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Everything a worker needs, built once per process rather than per wheel."""

    ruleset: Ruleset
    patterns: ScanPatterns
    evidence_level: str = "standard"
    archive_limits: ArchiveLimits = field(default_factory=ArchiveLimits)
    max_python_bytes: int = 8 * 1024 * 1024
    # Caps the *record's* binaries[] list so a wheel with thousands of objects cannot
    # produce an unbounded single JSONL line that no line-at-a-time consumer can read.
    # Every object read is still evaluated by linkage and the rules regardless of this
    # cap; it only bounds what gets serialised. See "A cap bounds the record, not the
    # evaluation" in DESIGN.md.
    max_binaries_per_record: int = 256

    @classmethod
    def build(cls, ruleset: Ruleset, **kwargs: Any) -> ScanContext:
        return cls(ruleset=ruleset, patterns=ruleset.compile_patterns(), **kwargs)


def scan_wheel(path: str | Path, context: ScanContext, sha256: str | None = None) -> dict[str, Any]:
    """Produce the record for one wheel. Never raises for a malformed wheel."""
    path = Path(path)
    try:
        digest = sha256 if sha256 is not None else hash_wheel(path)
    except OSError as exc:
        # Unreadable, deleted between discovery and scan, or a broken symlink. The
        # wheel still gets a record: a scan that loses wheels is worse than one that
        # marks them opaque.
        return _unreadable_record(path, "", type(exc).__name__, context)
    try:
        evidence = _collect(path, context, digest)
    except errors.WheelReadError as exc:
        evidence = _unreadable(path, digest, str(exc))
    except Exception as exc:  # noqa: BLE001 - never lose a wheel to an unexpected failure
        # Not `errors.BAD_ZIP`: this branch catches whatever `_collect` did not
        # specifically anticipate, which says nothing about whether the archive itself
        # is readable -- a `MemoryError` under load leaves the wheel's own bytes
        # untouched. See errors.UNEXPECTED_ERROR and DESIGN.md.
        evidence = _unreadable(
            path, digest, f"unexpected {type(exc).__name__}", kind=errors.UNEXPECTED_ERROR
        )

    # Linkage, the rules and the verdict all run over the full, untruncated
    # `evidence.binaries` that was actually read. The cap only ever slices the
    # `binaries[]` array `build_record` serialises, below.
    linkage = resolve_linkage(context.ruleset, evidence)
    findings = apply_rules(context.ruleset, evidence, linkage)
    verdict = classify(context.ruleset, findings, linkage)
    return build_record(
        evidence,
        findings,
        verdict,
        context.ruleset,
        evidence_level=context.evidence_level,
        max_binaries=context.max_binaries_per_record,
    )


def _collect(path: Path, context: ScanContext, digest: str) -> Evidence:
    with WheelArchive.open(path, context.archive_limits, sha256=digest) as archive:
        metadata, metadata_errors = read_metadata(archive.names, archive.read, archive.filename)
        binaries, binary_errors = scan_binaries(
            archive, context.patterns.binary, context.ruleset.conventions
        )
        sites, python_errors = scan_python_files(
            archive, context.patterns.python, max_bytes=context.max_python_bytes
        )
        unparsed = len({error.path for error in python_errors if error.path})
        inventory = build_inventory(
            archive,
            binaries,
            metadata.sbom_paths if metadata else (),
            metadata.record_entries if metadata else 0,
            py_files_unparsed=unparsed,
            max_binaries=context.max_binaries_per_record,
        )
        all_errors = (
            *archive.errors,
            *metadata_errors,
            *binary_errors,
            *python_errors,
        )
        return Evidence(
            filename=archive.filename,
            sha256=archive.sha256,
            size_bytes=archive.size_bytes,
            artifacts=inventory,
            metadata=metadata,
            # Untruncated. Every object here was already decompressed and read in
            # full, and linkage and the rules must see all of it: a cap that dropped
            # objects here before the rules ran would let a wheel with more than
            # `max_binaries_per_record` native objects read clean regardless of what
            # the dropped objects actually held. `build_record` is where the cap
            # applies, to the *serialised* list alone.
            binaries=binaries,
            py_sites=sites,
            errors=tuple(sorted(set(all_errors), key=ScanError.sort_key)),
        )


def _unreadable(path: Path, digest: str, message: str, *, kind: str = errors.BAD_ZIP) -> Evidence:
    """A wheel we could not open at all still gets a record, marked for what it is.

    `kind` defaults to `BAD_ZIP`, the specific claim that the archive itself would not
    open. A caller whose failure makes no claim about the archive's own bytes -- an
    exception `_collect` did not anticipate -- passes `errors.UNEXPECTED_ERROR` instead.
    """
    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    return Evidence(
        filename=path.name,
        sha256=digest,
        size_bytes=size,
        artifacts=ArtifactInventory(source_available=False, pyc_files=0),
        errors=(ScanError(stage=STAGE_ARCHIVE, kind=kind, message=message, path=None),),
    )


def _unreadable_record(
    path: Path, digest: str, reason: str, context: ScanContext
) -> dict[str, Any]:
    """A record for a wheel we could not even hash."""
    evidence = _unreadable(path, digest, reason)
    linkage = resolve_linkage(context.ruleset, evidence)
    findings = apply_rules(context.ruleset, evidence, linkage)
    verdict = classify(context.ruleset, findings, linkage)
    return build_record(
        evidence,
        findings,
        verdict,
        context.ruleset,
        evidence_level=context.evidence_level,
        max_binaries=context.max_binaries_per_record,
    )
