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
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, TypeVar

from . import ANALYZER_VERSION, SCHEMA_VERSION, TOOL_NAME, __version__
from .caps import cap
from .evidence import ArtifactInventory, BinaryEvidence, Evidence, MetadataEvidence, ScanError
from .findings import Finding
from .ruleset import Ruleset
from .verdict import Verdict

EVIDENCE_LEVELS = ("minimal", "standard")

T = TypeVar("T")


def build_record(
    evidence: Evidence,
    findings: Sequence[Finding],
    verdict: Verdict,
    ruleset: Ruleset,
    *,
    evidence_level: str = "standard",
    tool_version: str = __version__,
    max_binaries: int | None = None,
) -> dict[str, Any]:
    """Build the JSON-ready record for one wheel.

    `evidence.binaries` is expected to be the *full* set of objects that were actually
    read: `findings` and `verdict` were computed over all of it, not a truncated view.
    `max_binaries`, when given, also caps the `binaries[]`, `artifacts.bundled_libs`,
    `artifacts.skipped`, `artifacts.symlinks` and `errors[]` arrays built here, so the
    record stays bounded without the cap ever having withheld evidence from a rule --
    every object and every error is still fully evaluated regardless of what this cap
    keeps. A finding's `locations[].path` can therefore legitimately name an object
    that this cap left out of `binaries[]`, when even the finding-aware selection
    below could not make room for it -- see SCHEMA.md.
    """
    if evidence_level not in EVIDENCE_LEVELS:
        raise ValueError(f"unknown evidence level: {evidence_level!r}")
    binaries = (
        evidence.binaries
        if max_binaries is None
        else _cap_by_findings(evidence.binaries, lambda binary: binary.path, findings, max_binaries)
    )
    if max_binaries is None:
        errors, errors_truncated = evidence.errors, False
    else:
        errors, errors_truncated = cap(evidence.errors, max_binaries)
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
        "artifacts": _artifacts_block(evidence.artifacts, findings, max_binaries),
        "binaries": [_binary_block(binary, evidence_level) for binary in binaries],
        "findings": [_finding_block(finding) for finding in findings],
        "verdict": _verdict_block(verdict),
        "errors": [_error_block(error) for error in errors],
        # Set when thousands of errors (typically the same kind repeated across many
        # members) would otherwise produce an unbounded record. `caps.cap`
        # keeps one representative `(stage, kind)` pair before filling the rest, so a
        # wheel drowning in one failure never crowds out a different, rarer one --
        # see ScanError.cap_key.
        "errors_truncated": errors_truncated,
    }


def _cap_by_findings(
    items: Sequence[T],
    path_of: Callable[[T], str],
    findings: Sequence[Finding],
    max_binaries: int,
) -> tuple[T, ...]:
    """Cap `items` to `max_binaries`, keeping what a finding points at first.

    Shared by `binaries[]`, `artifacts.extensions` and `artifacts.bundled_libs`, each
    keyed by the object path `path_of` reads off each item -- a `BinaryEvidence` for
    the first, a bare `(path, format)` pair for the second, the bare path string
    itself for the third. `binaries[]` and `extensions` are always the same length,
    one entry per object read, so keeping them on one function is what keeps those two
    agreeing on which objects survive the cap -- the same thing that was true of them
    before this existed, when both were the identical plain prefix. `bundled_libs` is
    a different, usually smaller universe of paths (only the vendored objects), so it
    is never expected to list the same objects as the other two; what it shares with
    them is only the *selection rule* -- a finding-referenced object wins a slot first
    -- not the resulting set.

    Mirrors `caps.cap()`'s fix for the per-binary string/symbol/crate caps
    (DECISIONS.md, "A cap bounds the record, it does not pick the evidence", #51), one
    layer up: there the cap picked which *matches inside an object* a rule got to see;
    here it only ever picked which *objects* the serialised record lists, since #55
    made evaluation itself see every object regardless of this cap. A plain
    path-sorted prefix has no reason to agree with where the objects a finding
    actually names happen to sort, so a wheel whose crypto-relevant objects sort last
    could cap them straight out of `binaries[]` while `findings[]` and `verdict` still
    named them (#75).

    Three passes fill the room in the order a reader would miss it most, the same
    shape `caps.cap()` uses for its own three passes:

      1. One representative object per `(rule_id, subject)` a finding names, visited
         in that order -- so a finding does not lose *every* one of its objects to an
         unrelated finding's objects simply because its own objects' paths, or its own
         `subject`, happen to sort later. This is the fix a flat "referenced, then
         rest, in path order" pass was still missing: sorting the referenced set by
         path alone just moves the same sorting problem from object paths to finding
         subjects, and a subject like a crate name sorts exactly as arbitrarily with
         respect to severity as a filename does.
      2. Every other referenced object, in path order.
      3. Everything else, in path order -- the same rule the plain prefix already used
         for everything, when there was nothing to prefer.

    A `Location.path` that names no item here (a `kind = "linkage"` rule's Hit, for
    one, always carries the wheel's own filename, never an object path) is not part of
    any group and cannot win a slot through this function; it was never going to be an
    entry in `binaries[]` or `extensions` regardless of the wheel's content.

    Unlike `caps.cap()`'s per-binary caps, there is no fixed, ruleset-declared
    vocabulary of finding subjects to guarantee room for one of: how many distinct
    `(rule_id, subject)` groups and objects a wheel's own findings reference is data
    the wheel supplies, not policy the ruleset declares, so nothing here can be
    validated at load time the way `parse_ruleset` validates the string/symbol/crate
    caps against the ruleset's own group counts. The real bound is not unbounded,
    though: `[limits] max_locations_per_finding` already caps every finding to at most
    ten locations before it reaches here, so the number of distinct objects any one
    finding can put forward is small and fixed. What is not fixed is how many
    *findings* a wheel can have naming distinct objects -- when the number of distinct
    `(rule_id, subject)` groups alone exceeds `max_binaries`, group 1 above cannot
    give every group its one slot, and the groups are visited in the same
    deterministic, arbitrary order every time: sorted by `(rule_id, subject)`, so the
    lowest-sorting groups win, the same posture `caps.cap()` documents for its
    own analogous case. `binaries_truncated` and `WHEEL_BINARIES_TRUNCATED` still fire
    whenever the result is a prefix of anything, referenced or not, so this case is
    never silent -- see DECISIONS.md and SCHEMA.md.
    """
    if len(items) <= max_binaries:
        return tuple(items)
    by_path: dict[str, T] = {path_of(item): item for item in items}
    valid_paths = frozenset(by_path)

    groups: dict[tuple[str, str | None], set[str]] = {}
    referenced_paths: set[str] = set()
    for finding in findings:
        key = (finding.rule_id, finding.subject)
        for location in finding.locations:
            if location.path not in valid_paths:
                continue
            groups.setdefault(key, set()).add(location.path)
            referenced_paths.add(location.path)

    kept_paths: list[str] = []
    seen: set[str] = set()

    def _take(path: str) -> bool:
        if len(kept_paths) >= max_binaries:
            return False
        if path in seen:
            return True
        seen.add(path)
        kept_paths.append(path)
        return True

    for key in sorted(groups, key=lambda group_key: (group_key[0], group_key[1] or "")):
        if not _take(min(groups[key])):
            break

    for path in sorted(referenced_paths):
        if not _take(path):
            break

    for path in sorted(valid_paths):
        if not _take(path):
            break

    kept = [by_path[path] for path in kept_paths]
    return tuple(sorted(kept, key=path_of))


@dataclass(frozen=True, slots=True)
class _SkippedEntry:
    """Wraps one `artifacts.skipped` `(path, reason)` pair to cap it through
    `caps.cap`, the same `Capped` protocol `ScanError` already implements for
    `errors[]` -- `reason` is `ScanError.kind` projected onto this array, so the same
    starvation `ScanError.cap_key` exists to prevent applies here too. Local to
    `record.py`: `ArtifactInventory.skipped` itself stays a plain tuple, since nothing
    outside serialisation needs this wrapper.
    """

    path: str
    reason: str

    def sort_key(self) -> tuple[str, str]:
        return (self.path, self.reason)

    def cap_key(self) -> str:
        return self.reason


@dataclass(frozen=True, slots=True)
class _SymlinkEntry:
    """Wraps one `artifacts.symlinks` `(path, target)` pair to cap it through
    `caps.cap`. `target` is the axis a consumer actually keys on (#57: a bundled
    library is reachable only through the one symlink naming it), so one
    representative per target survives a flood of boring ones before the rest, the
    same shape `caps.py`'s own crate-list example exists to prevent one array over.
    """

    path: str
    target: str

    def sort_key(self) -> tuple[str, str]:
        return (self.path, self.target)

    def cap_key(self) -> str:
        return self.target


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


def _artifacts_block(
    artifacts: ArtifactInventory, findings: Sequence[Finding], max_binaries: int | None
) -> dict[str, Any]:
    # `extensions` is capped the same finding-aware way `binaries[]` is, through the
    # same function, so the two never disagree on which objects survive the cap --
    # they always agreed before this existed, when both were the identical plain
    # prefix. `ArtifactInventory.extensions` itself holds the full, untruncated set;
    # `build_inventory` stopped capping it for the same reason `_collect` stopped
    # truncating `Evidence.binaries` for #55 -- capping it before this point would
    # have been capping it before the cap could know what a finding cared about.
    extensions = (
        artifacts.extensions
        if max_binaries is None
        else _cap_by_findings(artifacts.extensions, lambda item: item[0], findings, max_binaries)
    )
    # `bundled_libs` is a *subset* of the objects `binaries[]`/`extensions` list --
    # only the vendored ones -- so it can be smaller than `max_binaries` even when
    # `artifacts.binaries_truncated` is true, and it needs its own truncation flag
    # rather than reusing that one: a wheel that vendors thousands of small libraries
    # under `*.libs/`/`.dylibs/` produced an unbounded `bundled_libs` array before
    # this, independently of how many native objects were read in total (#76).
    bundled_libs = (
        artifacts.bundled_libs
        if max_binaries is None
        else _cap_by_findings(artifacts.bundled_libs, lambda path: path, findings, max_binaries)
    )
    bundled_libs_truncated = max_binaries is not None and len(artifacts.bundled_libs) > max_binaries
    # `skipped`'s `reason` is `ScanError.kind` projected onto `(path, kind)`: the same
    # rules that match `evidence.errors` by `error_kinds` (`BIN_TOO_LARGE`,
    # `WHEEL_MEMBER_UNREADABLE`) name paths that live in `skipped` too, and a plain
    # prefix can crowd an entire reason out -- the same starvation `errors[]`'s own
    # `cap_key` exists to prevent, one array over. `symlinks`' `target` is the axis a
    # consumer actually keys on (#57: a bundled `libcrypto.dylib` reachable only
    # through one symlink's target), and a plain prefix can crowd the one crypto
    # target out behind a flood of boring ones, `caps.py`'s own `ring`-behind-`anyhow`
    # example one array over. Both go through `caps.cap` with one representative per
    # `(reason,)`/`(target,)` kept before the rest, not a plain sorted prefix. See
    # DECISIONS.md, "`skipped` and `symlinks` reuse `caps.cap`, not a plain prefix"
    # (#119).
    if max_binaries is None:
        skipped, skipped_truncated = artifacts.skipped, False
        symlinks, symlinks_truncated = artifacts.symlinks, False
    else:
        capped_skipped, skipped_truncated = cap(
            (_SkippedEntry(path, reason) for path, reason in artifacts.skipped), max_binaries
        )
        skipped = tuple((entry.path, entry.reason) for entry in capped_skipped)
        capped_symlinks, symlinks_truncated = cap(
            (_SymlinkEntry(path, target) for path, target in artifacts.symlinks), max_binaries
        )
        symlinks = tuple((entry.path, entry.target) for entry in capped_symlinks)
    return {
        "py_files": artifacts.py_files,
        "pyc_files": artifacts.pyc_files,
        "py_files_unparsed": artifacts.py_files_unparsed,
        "source_available": artifacts.source_available,
        "binaries_truncated": artifacts.binaries_truncated,
        "record_entries": artifacts.record_entries,
        "total_uncompressed_bytes": artifacts.total_uncompressed_bytes,
        "extensions": [{"path": path, "format": fmt} for path, fmt in extensions],
        "bundled_libs": list(bundled_libs),
        "bundled_libs_truncated": bundled_libs_truncated,
        "sboms": list(artifacts.sboms),
        "symlinks": [{"path": path, "target": target} for path, target in symlinks],
        "symlinks_truncated": symlinks_truncated,
        "skipped": [{"path": path, "reason": reason} for path, reason in skipped],
        "skipped_truncated": skipped_truncated,
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
        "partial_reasons": list(binary.partial_reasons),
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
        "class": verdict.headline,
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
