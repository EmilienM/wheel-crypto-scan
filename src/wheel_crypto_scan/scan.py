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
from .evidence import STAGE_ARCHIVE, STAGE_PYTHON, ArtifactInventory, Evidence, ScanError
from .layers.binaries import build_inventory, scan_binaries
from .layers.metadata import read_metadata
from .layers.python_ast import scan_python_source
from .linkage import resolve_linkage
from .record import build_record
from .ruleset import Ruleset, ScanPatterns
from .verdict import classify
from .wheelfile import ArchiveLimits, WheelArchive, hash_wheel

_SOURCE_SUFFIX = ".py"


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Everything a worker needs, built once per process rather than per wheel."""

    ruleset: Ruleset
    patterns: ScanPatterns
    evidence_level: str = "standard"
    archive_limits: ArchiveLimits = field(default_factory=ArchiveLimits)
    max_python_bytes: int = 8 * 1024 * 1024

    @classmethod
    def build(cls, ruleset: Ruleset, **kwargs: Any) -> ScanContext:
        return cls(ruleset=ruleset, patterns=ruleset.compile_patterns(), **kwargs)


def scan_wheel(path: str | Path, context: ScanContext, sha256: str | None = None) -> dict[str, Any]:
    """Produce the record for one wheel. Never raises for a malformed wheel."""
    path = Path(path)
    digest = sha256 if sha256 is not None else hash_wheel(path)
    try:
        evidence = _collect(path, context, digest)
    except errors.WheelReadError as exc:
        evidence = _unreadable(path, digest, str(exc))

    linkage = resolve_linkage(context.ruleset, evidence)
    findings = apply_rules(context.ruleset, evidence, linkage)
    verdict = classify(context.ruleset, findings, linkage)
    return build_record(
        evidence,
        findings,
        verdict,
        context.ruleset,
        evidence_level=context.evidence_level,
    )


def _collect(path: Path, context: ScanContext, digest: str) -> Evidence:
    with WheelArchive.open(path, context.archive_limits, sha256=digest) as archive:
        metadata, metadata_errors = read_metadata(archive.names, archive.read, archive.filename)
        binaries, binary_errors = scan_binaries(
            archive, context.patterns, context.ruleset.conventions
        )
        sites, python_errors = _scan_python(archive, context)
        inventory = build_inventory(
            archive,
            binaries,
            metadata.sbom_paths if metadata else (),
            metadata.record_entries if metadata else 0,
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
            binaries=binaries,
            py_sites=sites,
            errors=tuple(sorted(set(all_errors), key=ScanError.sort_key)),
        )


def _scan_python(archive: WheelArchive, context: ScanContext):  # type: ignore[no-untyped-def]
    sites = []
    found: list[ScanError] = []
    for member in archive.members:
        if member.is_symlink or not member.name.endswith(_SOURCE_SUFFIX):
            continue
        if member.size > context.max_python_bytes:
            found.append(
                ScanError(
                    stage=STAGE_PYTHON,
                    kind=errors.PYTHON_TOO_LARGE,
                    message=f"source is {member.size} bytes",
                    path=member.name,
                )
            )
            continue
        try:
            source = archive.read(member.name)
        except errors.WheelReadError as exc:
            found.append(
                ScanError(
                    stage=STAGE_PYTHON,
                    kind=errors.MEMBER_READ_ERROR,
                    message=str(exc),
                    path=member.name,
                )
            )
            continue
        member_sites, member_errors = scan_python_source(source, member.name, context.patterns)
        sites.extend(member_sites)
        found.extend(member_errors)
    return tuple(sorted(sites, key=lambda site: site.sort_key())), tuple(found)


def _unreadable(path: Path, digest: str, message: str) -> Evidence:
    """A wheel we could not open at all still gets a record, marked for what it is."""
    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    return Evidence(
        filename=path.name,
        sha256=digest,
        size_bytes=size,
        artifacts=ArtifactInventory(source_available=False, pyc_files=0),
        errors=(ScanError(stage=STAGE_ARCHIVE, kind=errors.BAD_ZIP, message=message, path=None),),
    )
