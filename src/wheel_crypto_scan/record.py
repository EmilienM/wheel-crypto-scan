"""Assembles the output record and serialises it canonically.

This module owns the contract that component teams consume, so two properties matter
more than convenience here. The shape is stable: every record has the same keys, in
the same places, whether or not the wheel had metadata, binaries or Python source, so
a consumer never has to guard against a missing key. And the bytes are canonical: keys
sorted, ASCII only, no floats, no whitespace, exactly one trailing newline. The same
wheel scanned twice produces the same line.

See SCHEMA.md for the field-by-field documentation and the versioning rules.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

from . import ANALYZER_VERSION, SCHEMA_VERSION, TOOL_NAME, __version__
from .evidence import ArtifactInventory, BinaryEvidence, Evidence, MetadataEvidence, ScanError
from .findings import Finding
from .ruleset import Ruleset
from .verdict import Verdict

EVIDENCE_LEVELS = ("minimal", "standard")


def build_record(
    evidence: Evidence,
    findings: Sequence[Finding],
    verdict: Verdict,
    ruleset: Ruleset,
    *,
    evidence_level: str = "standard",
    tool_version: str = __version__,
) -> dict[str, Any]:
    """Build the JSON-ready record for one wheel."""
    if evidence_level not in EVIDENCE_LEVELS:
        raise ValueError(f"unknown evidence level: {evidence_level!r}")
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {
            "name": TOOL_NAME,
            "version": tool_version,
            "ruleset_version": ruleset.version,
            "analyzer_version": ANALYZER_VERSION,
            # Recorded because `binaries[].matched_symbols` being empty means "none
            # found" at standard and "not recorded" at minimal, and nothing else in
            # the record distinguishes those two.
            "evidence_level": evidence_level,
        },
        "wheel": _wheel_block(evidence),
        "artifacts": _artifacts_block(evidence.artifacts),
        "binaries": [_binary_block(binary, evidence_level) for binary in evidence.binaries],
        "findings": [_finding_block(finding) for finding in findings],
        "verdict": _verdict_block(verdict),
        "errors": [_error_block(error) for error in evidence.errors],
    }


def to_json_line(record: dict[str, Any]) -> str:
    """Serialise one record as a canonical JSONL line."""
    return json.dumps(record, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n"


def _wheel_block(evidence: Evidence) -> dict[str, Any]:
    meta: MetadataEvidence | None = evidence.metadata
    if meta is None:
        # An unreadable wheel still gets a full-shaped record. Nulls say "we could not
        # tell", which a consumer can act on; a missing key just breaks them.
        return {
            "filename": evidence.filename,
            "name": None,
            "canonical_name": None,
            "version": None,
            "sha256": evidence.sha256,
            "size_bytes": evidence.size_bytes,
            "tags": [],
            "platform_tags": [],
            "generator": None,
            "requires_python": None,
            "requires_dist": [],
            "root_is_purelib": None,
        }
    return {
        "filename": evidence.filename,
        "name": meta.name,
        "canonical_name": meta.canonical_name,
        "version": meta.version,
        "sha256": evidence.sha256,
        "size_bytes": evidence.size_bytes,
        "tags": list(meta.tags),
        "platform_tags": list(meta.platform_tags),
        "generator": _generator_block(meta),
        "requires_python": meta.requires_python,
        "requires_dist": list(meta.requires_dist),
        "root_is_purelib": meta.root_is_purelib,
    }


def _generator_block(meta: MetadataEvidence) -> dict[str, Any] | None:
    if not meta.generator_raw:
        return None
    return {
        "name": meta.generator_name,
        "version": meta.generator_version,
        "raw": meta.generator_raw,
    }


def _artifacts_block(artifacts: ArtifactInventory) -> dict[str, Any]:
    return {
        "py_files": artifacts.py_files,
        "pyc_files": artifacts.pyc_files,
        "py_files_unparsed": artifacts.py_files_unparsed,
        "source_available": artifacts.source_available,
        "binaries_truncated": artifacts.binaries_truncated,
        "record_entries": artifacts.record_entries,
        "total_uncompressed_bytes": artifacts.total_uncompressed_bytes,
        "extensions": [{"path": path, "format": fmt} for path, fmt in artifacts.extensions],
        "bundled_libs": list(artifacts.bundled_libs),
        "sboms": list(artifacts.sboms),
        "symlinks": [{"path": path, "target": target} for path, target in artifacts.symlinks],
        "skipped": [{"path": path, "reason": reason} for path, reason in artifacts.skipped],
    }


def _binary_block(binary: BinaryEvidence, level: str) -> dict[str, Any]:
    detailed = level == "standard"
    return {
        "path": binary.path,
        "format": binary.format,
        "vendored_path": binary.vendored_path,
        "machine": binary.machine,
        "bits": binary.bits,
        "endian": binary.endian,
        "elf_type": binary.elf_type,
        "soname": binary.soname,
        "needed": list(binary.needed),
        "rpath": list(binary.rpath),
        "runpath": list(binary.runpath),
        "stripped": binary.stripped,
        "symbol_counts": {"dynsym": binary.dynsym_count, "symtab": binary.symtab_count},
        "matched_symbols": [
            {"name": symbol.name, "group": symbol.group, "binding": symbol.binding}
            for symbol in (binary.matched_symbols if detailed else ())
        ],
        "matched_strings": [
            {"group": match.group, "value": match.value}
            for match in (binary.matched_strings if detailed else ())
        ],
        "rust_crates": [
            {"name": crate.name, "version": crate.version}
            for crate in (binary.rust_crates if detailed else ())
        ],
        "go": _go_block(binary),
        "truncated": {
            "symbols": binary.symbols_truncated,
            "strings": binary.strings_truncated,
        },
        "partial_analysis": binary.partial_analysis,
    }


def _go_block(binary: BinaryEvidence) -> dict[str, Any] | None:
    if binary.go is None:
        return None
    return {
        "go_version": binary.go.go_version,
        "boring_crypto": binary.go.boring_crypto,
        "markers": list(binary.go.markers),
    }


def _finding_block(finding: Finding) -> dict[str, Any]:
    return {
        "rule_id": finding.rule_id,
        "subject": finding.subject,
        "subject_kind": finding.subject_kind,
        "severity": finding.severity,
        "category": finding.category,
        "layer": finding.layer,
        "confidence": finding.confidence,
        "verdict": finding.verdict,
        "needs_human_review": finding.needs_human_review,
        "occurrences": finding.occurrences,
        "truncated": finding.truncated,
        "locations": [
            {"path": location.path, "line": location.line, "evidence": location.evidence}
            for location in finding.locations
        ],
    }


def _verdict_block(verdict: Verdict) -> dict[str, Any]:
    return {
        "class": verdict.verdict_class,
        "classes": list(verdict.classes),
        "rule_ids": list(verdict.rule_ids),
        "reasons": list(verdict.reasons),
        "conditions": dict(verdict.conditions),
        "needs_human_review": verdict.needs_human_review,
    }


def _error_block(error: ScanError) -> dict[str, Any]:
    return {
        "stage": error.stage,
        "kind": error.kind,
        "path": error.path,
        "message": error.message,
    }
