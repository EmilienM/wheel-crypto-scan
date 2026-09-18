"""Applies ruleset matchers to extracted evidence to produce findings.

The engine holds no policy. It knows how each matcher *kind* works; which names,
symbols, crates and patterns those matchers look for comes entirely from the ruleset.
Adding a package to the watch list is a TOML edit; only a genuinely new *way* of
looking at a wheel needs code here.

Evidence in, findings out. No verdict is decided at this stage.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from packaging.utils import canonicalize_name

from .evidence import Evidence
from .findings import Finding, Location
from .ruleset import CryptoLibrary, Limits, Rule, Ruleset

__all__ = ["Hit", "apply_rules"]

_PRINTABLE = frozenset(range(0x20, 0x7F))


@dataclass(frozen=True, slots=True)
class Hit:
    """One match, before matches are grouped into findings.

    Public because a new matcher is the one thing a contributor writes in this module,
    and this is everything such a matcher has to produce.
    """

    subject: str | None
    location: Location
    # What kind of thing `subject` names. Without it a consumer would need a private
    # rule-id lookup table to interpret the field at all.
    subject_kind: str | None = None
    severity: str | None = None
    verdict: str | None = None
    needs_human_review: bool | None = None


def apply_rules(
    ruleset: Ruleset, evidence: Evidence, linkage: Mapping[str, str]
) -> tuple[Finding, ...]:
    """Match every rule against the evidence and return findings, sorted and capped."""
    index = _SonameIndex(ruleset)
    grouped: dict[tuple[str, str | None], list[Hit]] = {}
    rules: dict[tuple[str, str | None], Rule] = {}

    for rule in ruleset.rules:
        # A rule's match tables are alternatives, and hits key on (rule id, subject):
        # one finding per subject, not one per matcher. Two tables that spot the same
        # subject make one finding; two that spot different subjects still make two.
        for match in rule.matches:
            matcher = _MATCHERS.get(match["kind"])
            if matcher is None:
                continue
            for hit in matcher(rule, match, ruleset, evidence, linkage, index):
                key = (rule.id, hit.subject)
                grouped.setdefault(key, []).append(hit)
                rules[key] = rule

    findings = [
        _build_finding(rules[key], hits, ruleset.limits)
        for key, hits in sorted(grouped.items(), key=lambda item: (item[0][0], item[0][1] or ""))
    ]
    return _apply_suppression(findings, ruleset)


def _build_finding(rule: Rule, hits: Sequence[Hit], limits: Limits) -> Finding:
    locations = sorted({hit.location for hit in hits}, key=Location.sort_key)
    first = hits[0]
    return Finding(
        rule_id=rule.id,
        severity=first.severity or rule.severity,
        category=rule.category,
        layer=rule.layer,
        confidence=rule.confidence,
        needs_human_review=(
            rule.needs_human_review
            if first.needs_human_review is None
            else first.needs_human_review
        ),
        verdict=first.verdict if first.verdict is not None else rule.verdict,
        subject=first.subject,
        subject_kind=first.subject_kind,
        occurrences=len(locations),
        locations=tuple(locations[: limits.max_locations_per_finding]),
        truncated=len(locations) > limits.max_locations_per_finding,
    )


def _apply_suppression(findings: Sequence[Finding], ruleset: Ruleset) -> tuple[Finding, ...]:
    """Drop a broad finding when a more specific one already fired."""
    present = {finding.rule_id for finding in findings}
    kept = [
        finding
        for finding in findings
        if not (set(ruleset.rule(finding.rule_id).suppressed_by) & present)
    ]
    return tuple(sorted(kept, key=Finding.sort_key))


class _SonameIndex:
    """Reverse lookup from a normalised library base name to its ruleset entry."""

    def __init__(self, ruleset: Ruleset) -> None:
        self._index: dict[str, CryptoLibrary] = {}
        for name in sorted(ruleset.libraries):
            library = ruleset.libraries[name]
            for soname in library.sonames:
                self._index.setdefault(soname, library)

    def get(self, base: str) -> CryptoLibrary | None:
        return self._index.get(base)


def _clean(text: str, limit: int) -> str:
    """Printable ASCII only, capped. Binary noise must not reach the JSON record."""
    kept = "".join(char if ord(char) in _PRINTABLE else " " for char in text).strip()
    return kept[:limit]


def _attrs(site) -> dict[str, str]:  # type: ignore[no-untyped-def]
    return dict(site.attrs)


def _owns(rule: Rule, entry_rule: str | None, default: Rule | None, *, unowned: bool) -> bool:
    """Whether a table entry belongs to this rule.

    An entry names the rule it fires, and failing that the table's default rule owns
    it. `unowned` decides what happens to an entry with neither, and the callers do not
    agree. `python_module` drops it, as it always has, so a module no rule owns fires
    nothing. `crypto_library` and `rust_crate` keep it, because `crypto_library` names
    no default and its two `bundled_library` rules separate themselves by `library` and
    `exclude_libraries` filters instead of by ownership. Changing either changes
    records.

    Routing is only a guarantee against double-firing where there is an owner to
    compare against: two rules of the same kind over a table with no default and an
    entry that names none both fire, by design.
    """
    owner = entry_rule or (default.id if default is not None else None)
    if owner is None:
        return unowned
    return owner == rule.id


# --- matchers ---------------------------------------------------------------
#
# Each takes (rule, match, ruleset, evidence, linkage, index) and yields Hit values.
# `match` is the one table this matcher was dispatched for, never the rule's whole list.


def _match_dist_name(rule, match, ruleset, evidence, linkage, index) -> Iterator[Hit]:
    meta = evidence.metadata
    if meta is None:
        return
    entry = ruleset.distributions.get(meta.canonical_name)
    if entry is None or entry.rule != rule.id:
        return
    yield Hit(
        subject_kind="distribution",
        subject=entry.name,
        location=Location(
            path=meta.dist_info_dir or evidence.filename,
            evidence=_clean(f"{meta.name} {meta.version}", ruleset.limits.max_evidence_chars),
        ),
        severity=entry.severity,
        verdict=entry.verdict,
        needs_human_review=entry.needs_human_review,
    )


def _match_requires_dist(rule, match, ruleset, evidence, linkage, index) -> Iterator[Hit]:
    meta = evidence.metadata
    if meta is None:
        return
    any_entry = bool(match.get("any_entry"))
    for name in meta.requires_dist_names:
        entry = ruleset.distributions.get(name)
        if entry is None or (not any_entry and entry.rule != rule.id):
            continue
        # An `any_entry` rule is a dependency edge, not the dependency's own risk, so
        # it deliberately does not inherit the entry's severity or verdict.
        yield Hit(
            subject_kind="distribution",
            subject=name,
            location=Location(
                path=f"{meta.dist_info_dir}/METADATA" if meta.dist_info_dir else evidence.filename,
                evidence=_clean(f"Requires-Dist: {name}", ruleset.limits.max_evidence_chars),
            ),
            severity=None if any_entry else entry.severity,
            verdict=None if any_entry else entry.verdict,
        )


def _match_wheel_generator(rule, match, ruleset, evidence, linkage, index) -> Iterator[Hit]:
    meta = evidence.metadata
    if meta is None or not meta.generator_raw:
        return
    yield Hit(
        subject_kind="generator",
        subject=meta.generator_name,
        location=Location(
            path=f"{meta.dist_info_dir}/WHEEL" if meta.dist_info_dir else evidence.filename,
            evidence=_clean(f"Generator: {meta.generator_raw}", ruleset.limits.max_evidence_chars),
        ),
    )


def _match_no_source(rule, match, ruleset, evidence, linkage, index) -> Iterator[Hit]:
    artifacts = evidence.artifacts
    # Fires when the wheel contains Python we could not read: bytecode without source,
    # or source that would not parse. Both leave Layer 3 with nothing to say, and the
    # record must not present that the same way as a wheel with nothing to find.
    if artifacts.source_available or (artifacts.pyc_files == 0 and artifacts.py_files == 0):
        return
    if artifacts.py_files_unparsed:
        detail = f"{artifacts.py_files_unparsed} of {artifacts.py_files} source files unparsed"
    else:
        detail = f"{artifacts.pyc_files} bytecode files, 0 source files"
    yield Hit(
        subject=None,
        location=Location(path=evidence.filename, evidence=detail),
    )


def _match_record_mismatch(rule, match, ruleset, evidence, linkage, index) -> Iterator[Hit]:
    meta = evidence.metadata
    if meta is None:
        return
    for path in meta.record_mismatches:
        yield Hit(
            subject=None,
            location=Location(path=path, evidence="not reconciled with RECORD"),
        )


def _match_scan_error(rule, match, ruleset, evidence, linkage, index) -> Iterator[Hit]:
    wanted = frozenset(match["error_kinds"])
    for error in evidence.errors:
        if error.kind not in wanted:
            continue
        yield Hit(
            subject=None,
            location=Location(
                path=error.path or evidence.filename,
                evidence=_clean(
                    f"{error.kind}: {error.message}", ruleset.limits.max_evidence_chars
                ),
            ),
        )


def _match_sbom_component(rule, match, ruleset, evidence, linkage, index) -> Iterator[Hit]:
    meta = evidence.metadata
    if meta is None:
        return
    tables = match.get("tables", [])
    for component in meta.sbom_components:
        entry = _sbom_entry(ruleset, tables, component.name)
        if entry is None:
            continue
        version = f" {component.version}" if component.version else ""
        yield Hit(
            subject_kind="component",
            subject=component.name,
            location=Location(
                path=component.source,
                evidence=_clean(
                    f"SBOM component {component.name}{version}", ruleset.limits.max_evidence_chars
                ),
            ),
            severity=entry.severity,
            verdict=entry.verdict,
            needs_human_review=entry.needs_human_review,
        )


def _sbom_entry(ruleset: Ruleset, tables: Sequence[str], name: str):  # type: ignore[no-untyped-def]
    for table in tables:
        if table == "crypto_library" and name in ruleset.libraries:
            return ruleset.libraries[name]
        if table == "rust_crate" and name in ruleset.rust_crates:
            return ruleset.rust_crates[name]
        if table == "crypto_distribution":
            entry = ruleset.distributions.get(canonicalize_name(name))
            if entry is not None:
                return entry
    return None


def _match_bundled_library(rule, match, ruleset, evidence, linkage, index) -> Iterator[Hit]:
    wanted = match.get("library")
    excluded = frozenset(match.get("exclude_libraries", ()))
    default = ruleset.default_rule_for_table("crypto_library", "bundled_library")
    for binary in evidence.binaries:
        if not binary.vendored_path:
            continue
        library = index.get(ruleset.conventions.own_base(binary.soname, binary.path))
        if library is None or library.name in excluded:
            continue
        if wanted is not None and library.name != wanted:
            continue
        if not _owns(rule, library.rule, default, unowned=True):
            continue
        detail = f"DT_SONAME={binary.soname}" if binary.soname else f"file {binary.path}"
        banners = [
            banner.value
            for banner in binary.matched_strings
            if library.string_group and banner.group == library.string_group
        ]
        if banners:
            detail = f"{detail}; string={banners[0]!r}"
        yield Hit(
            subject_kind="library",
            subject=library.name,
            location=Location(
                path=binary.path, evidence=_clean(detail, ruleset.limits.max_evidence_chars)
            ),
            severity=library.severity,
            verdict=library.verdict,
            needs_human_review=library.needs_human_review,
        )


def _match_dt_needed(rule, match, ruleset, evidence, linkage, index) -> Iterator[Hit]:
    wanted = match.get("library")
    want_mangled = match.get("mangled")
    for binary in evidence.binaries:
        for needed in binary.needed:
            info = ruleset.conventions.normalise_soname(needed)
            library = index.get(info.base)
            if library is None:
                continue
            if wanted is not None and library.name != wanted:
                continue
            if want_mangled is not None and info.mangled is not want_mangled:
                continue
            yield Hit(
                subject_kind="library",
                subject=library.name,
                location=Location(
                    path=binary.path,
                    evidence=_clean(f"DT_NEEDED={needed}", ruleset.limits.max_evidence_chars),
                ),
                severity=library.severity if want_mangled else None,
                verdict=library.verdict if want_mangled else None,
            )


def _match_dynamic_symbol(rule, match, ruleset, evidence, linkage, index) -> Iterator[Hit]:
    groups = _groups(match)
    binding = match["binding"]
    for binary in evidence.binaries:
        for symbol in binary.matched_symbols:
            if symbol.group not in groups:
                continue
            if binding not in ("any", symbol.binding):
                continue
            yield Hit(
                subject_kind="symbol_group",
                subject=symbol.group,
                location=Location(
                    path=binary.path,
                    evidence=_clean(
                        f"{symbol.binding} symbol {symbol.name}",
                        ruleset.limits.max_evidence_chars,
                    ),
                ),
            )


def _match_binary_string(rule, match, ruleset, evidence, linkage, index) -> Iterator[Hit]:
    groups = _groups(match)
    for binary in evidence.binaries:
        for found in binary.matched_strings:
            if found.group not in groups:
                continue
            yield Hit(
                subject_kind="string_group",
                subject=found.group,
                location=Location(
                    path=binary.path,
                    evidence=_clean(f"string={found.value!r}", ruleset.limits.max_evidence_chars),
                ),
            )


def _match_rust_crate(rule, match, ruleset, evidence, linkage, index) -> Iterator[Hit]:
    default = ruleset.default_rule_for_table("rust_crate", "rust_crate")
    for binary in evidence.binaries:
        for crate in binary.rust_crates:
            entry = ruleset.rust_crates.get(crate.name)
            if entry is None or not _owns(rule, entry.rule, default, unowned=True):
                continue
            yield Hit(
                subject_kind="crate",
                subject=crate.name,
                location=Location(
                    path=binary.path,
                    evidence=_clean(
                        f"cargo path for {crate.name} {crate.version}",
                        ruleset.limits.max_evidence_chars,
                    ),
                ),
                severity=entry.severity,
                verdict=entry.verdict,
                needs_human_review=entry.needs_human_review,
            )


def _match_linkage(rule, match, ruleset, evidence, linkage, index) -> Iterator[Hit]:
    """Match a resolved linkage posture, for one named library or a whole table.

    The table form exists so that every crypto library with a verdict is reachable.
    Without it a resolved linkage could sit in `verdict.conditions` while the verdict
    class said nothing was found, which is the one thing the headline field must not do.
    """
    values = frozenset(match.get("values", ())) or frozenset({match["value"]})
    inherit = "table" in match
    if "name" in match:
        names: list[str] = [str(match["name"])]
    else:
        excluded = frozenset(match.get("exclude_libraries", ()))
        names = [name for name in sorted(linkage) if name not in excluded]

    for name in names:
        value = linkage.get(name)
        if value not in values:
            continue
        library = ruleset.libraries.get(name)
        yield Hit(
            subject=name,
            subject_kind="library",
            location=Location(
                path=evidence.filename, evidence=f"{name} linkage resolved to {value}"
            ),
            severity=library.severity if inherit and library else None,
            verdict=library.verdict if inherit and library else None,
            needs_human_review=library.needs_human_review if inherit and library else None,
        )


def _match_opaque_binary(rule, match, ruleset, evidence, linkage, index) -> Iterator[Hit]:
    for binary in evidence.binaries:
        if not binary.is_opaque:
            continue
        yield Hit(
            subject=None,
            location=Location(
                path=binary.path,
                evidence="no dependencies, no dynamic symbols, no readable strings",
            ),
        )


def _match_partial_binary(rule, match, ruleset, evidence, linkage, index) -> Iterator[Hit]:
    for binary in evidence.binaries:
        if not binary.partial_analysis:
            continue
        # Name the causes here too. A triager reads `findings` and `verdict.reasons`;
        # without this the tokens would only reach someone opening the raw record. The
        # suffix is conditional rather than defaulted: every reader that sets the flag
        # also names a reason, so an empty tuple means someone built the evidence by
        # hand, and inventing text for it would be worse than saying less.
        detail = f"{binary.format} object was only partially read"
        if binary.partial_reasons:
            detail = f"{detail}: {', '.join(binary.partial_reasons)}"
        yield Hit(
            subject_kind="format",
            subject=binary.format,
            location=Location(path=binary.path, evidence=detail),
        )


def _match_py_import(rule, match, ruleset, evidence, linkage, index) -> Iterator[Hit]:
    default = ruleset.default_rule_for_table("python_module", "py_import")
    for site in evidence.py_sites:
        if site.kind != "py_import":
            continue
        entry = ruleset.python_modules.get(site.target)
        if entry is None or not _owns(rule, entry.rule, default, unowned=False):
            continue
        yield Hit(
            subject_kind="module",
            subject=entry.name,
            location=_site_location(site, ruleset.limits),
            severity=entry.severity,
            verdict=entry.verdict,
            needs_human_review=entry.needs_human_review,
        )


def _match_py_call(rule, match, ruleset, evidence, linkage, index) -> Iterator[Hit]:
    targets = frozenset(match.get("targets", ()))
    weak_only = bool(match.get("weak_algorithms_only"))
    want_used = match.get("usedforsecurity")
    want_algorithm = match.get("algorithm")
    weak = ruleset.conventions.weak_hash_algorithms
    for site in evidence.py_sites:
        if site.kind != "py_call" or not _target_matches(site.target, targets):
            continue
        attrs = _attrs(site)
        algorithm = attrs.get("algorithm")
        if weak_only and (algorithm is None or algorithm not in weak):
            continue
        if want_algorithm is not None and algorithm != want_algorithm:
            continue
        if want_used is not None and attrs.get("usedforsecurity") != want_used:
            continue
        yield Hit(subject=None, location=_site_location(site, ruleset.limits))


def _match_py_attr(rule, match, ruleset, evidence, linkage, index) -> Iterator[Hit]:
    attributes = frozenset(match.get("attributes", ()))
    values = match.get("values")
    for site in evidence.py_sites:
        if site.kind != "py_attr" or site.target not in attributes:
            continue
        if values is not None and _attrs(site).get("value") not in values:
            continue
        yield Hit(
            subject_kind="attribute",
            subject=site.target,
            location=_site_location(site, ruleset.limits),
        )


def _match_py_constant(rule, match, ruleset, evidence, linkage, index) -> Iterator[Hit]:
    constants = frozenset(match.get("constants", ()))
    for site in evidence.py_sites:
        if site.kind == "py_constant" and site.target in constants:
            yield Hit(
                subject_kind="constant",
                subject=site.target,
                location=_site_location(site, ruleset.limits),
            )


def _match_py_ctypes_load(rule, match, ruleset, evidence, linkage, index) -> Iterator[Hit]:
    for site in evidence.py_sites:
        if site.kind == "py_ctypes_load":
            yield Hit(
                subject_kind="library",
                subject=site.target,
                location=_site_location(site, ruleset.limits),
            )


def _target_matches(target: str, targets: frozenset[str]) -> bool:
    """Match a plain dotted target, or a `*.name` wildcard on any receiver."""
    if target in targets:
        return True
    return f"*.{target.rsplit('.', 1)[-1]}" in targets


def _site_location(site, limits: Limits) -> Location:  # type: ignore[no-untyped-def]
    return Location(
        path=site.path, line=site.line, evidence=_clean(site.detail, limits.max_evidence_chars)
    )


def _groups(match: Mapping[str, Any]) -> frozenset[str]:
    names = list(match.get("groups", ()))
    if "group" in match:
        names.append(match["group"])
    return frozenset(names)


_MATCHERS = {
    "dist_name": _match_dist_name,
    "requires_dist": _match_requires_dist,
    "wheel_generator": _match_wheel_generator,
    "no_source": _match_no_source,
    "record_mismatch": _match_record_mismatch,
    "scan_error": _match_scan_error,
    "sbom_component": _match_sbom_component,
    "bundled_library": _match_bundled_library,
    "dt_needed": _match_dt_needed,
    "dynamic_symbol": _match_dynamic_symbol,
    "binary_string": _match_binary_string,
    "rust_crate": _match_rust_crate,
    "linkage": _match_linkage,
    "opaque_binary": _match_opaque_binary,
    "partial_binary": _match_partial_binary,
    "py_import": _match_py_import,
    "py_call": _match_py_call,
    "py_attr": _match_py_attr,
    "py_constant": _match_py_constant,
    "py_ctypes_load": _match_py_ctypes_load,
}
