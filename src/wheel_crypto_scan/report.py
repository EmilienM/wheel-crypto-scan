"""Human-readable views of the records. The JSONL contract lives in `record.py`.

Markdown is for reading over someone's shoulder: the summary table leads with the
crypto inventory -- families, libraries and their linkage, the relations that follow
from it -- because a wheel's evidence is what a reader needs first, and the class badge
comes after it as the FIPS compatibility lens's own summary, not the wheel's headline
identity. HTML is for browsing and drill-down: one self-contained page with the same
columns, sortable and filterable, with a detail view per wheel that repeats the same
inventory-first split: "Cryptography in this wheel", then "FIPS compatibility". Both
are views; the JSONL is the contract.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from importlib.resources import files
from typing import Any

from .ruleset import Ruleset

_HEADERS = (
    "wheel",
    "version",
    "families",
    "libraries",
    "relations",
    "class",
    "review",
    "reasons",
)

_FINDING_HEADERS = (
    "rule",
    "subject",
    "family",
    "relation",
    "basis",
    "severity",
    "verdict",
    "occurrences",
)

# Verbatim from SCHEMA.md's "Verdict classes" table. A class with no entry here
# renders "No description; see the output schema." in the page -- never a blank and
# never a positive default, so an unlisted class still cannot look like a pass.
CLASS_HELP: dict[str, str] = {
    "NON_APPROVED_CRYPTO": (
        "Implements or bundles cryptography that no validated module provides: a "
        "primitive no approved standard specifies, or an approved algorithm outside "
        "any validated module."
    ),
    "FIPS_BREAKING": "Will raise at runtime under FIPS-enforcing mode.",
    "CONDITIONAL": "Approved only under a stated condition; read conditions.",
    "CONTEXT_DEPENDENT": "Non-approved primitive that may be a non-security use.",
    "OPAQUE": "Stripped, unreadable or source-free. Cannot determine.",
    "NO_CRYPTO_DETECTED": "Nothing found. Absence of evidence, not evidence of absence.",
}

# A short form of SCHEMA.md's `conditions.openssl_linkage` value table: several of its
# rows run to a paragraph, too long for a tooltip. A test holds this to the same set of
# values and requires each entry to name an input (today, the SBOM) exactly when its
# SCHEMA.md row does, so a short form cannot silently drop where a value's evidence came
# from.
LINKAGE_HELP: dict[str, str] = {
    "system": (
        "Resolves libcrypto/libssl from the host, so it inherits the host's FIPS "
        "provider and crypto policy. Can still carry an OPAQUE finding beside this if "
        "an object uses OpenSSL, or the wheel's own SBOM names it, without saying "
        "which copy."
    ),
    "bundled": (
        "Ships its own copy: in a vendor directory, via a hash-renamed dependency, "
        "or via an unrenamed vendored file."
    ),
    "static": (
        "Compiled in, with no library file and no declared dependency. Same "
        "consequence as bundled, harder to spot."
    ),
    "mixed": "Both postures found, across different objects or within one object.",
    "none": (
        "No OpenSSL evidence in any binary object, and no shipped SBOM entry naming "
        "the library or a crate that binds it, from objects read far enough to say so."
    ),
    "unknown": (
        "An object uses OpenSSL without naming where it comes from, or the wheel's "
        "own SBOM names the library or a crate that binds it and no object answers, "
        "or the evidence needed to tell is incomplete."
    ),
}

# What a `relation` names in remediation terms: what would have to change for a finding
# carrying it to go away, the question a reader of the FIPS compatibility section
# actually asks. A test holds this to `RELATIONS`, the loader's own closed vocabulary,
# the same way `test_every_precedence_class_has_help` holds `LINKAGE_HELP` to
# `LINKAGE_VALUES` -- a relation added to the vocabulary without a matching entry here
# must fail that test, the way an unknown relation already fails to load.
RELATION_HELP: dict[str, str] = {
    "not_specified": (
        "No approved standard specifies an equivalent construction: only a protocol "
        "or algorithm change removes the finding, not a different module."
    ),
    "restricted": (
        "Approved only for a stated restricted use (for example blockchain "
        "applications); acceptable there, non-approved or context-dependent "
        "elsewhere."
    ),
    "outside_module": (
        "An approved algorithm, implemented or compiled outside any validated "
        "module: relinking against a validated module removes the finding."
    ),
    "boundary_unresolved": (
        "Whether this reaches a validated module cannot be told from the wheel "
        "alone; read conditions for the linkage that decides it."
    ),
    "runtime_refusal": (
        "Raises at runtime under FIPS-enforcing mode; the call itself has to change."
    ),
    "policy_bypass": (
        "Overrides or bypasses the host's TLS or crypto policy: removing the "
        "override, not the library, is what fixes it."
    ),
    "use_unresolved": (
        "The construction itself is not disapproved; whether this particular use "
        "is a security use is what remains open."
    ),
}

# What a `family` names: the kind of primitive a finding is evidence of, independent of
# the FIPS lens -- see `FAMILIES` in `ruleset.py`. A closed, static vocabulary shipped
# in full on every page, the same way `CLASS_HELP`/`LINKAGE_HELP` are: small enough that
# narrowing it to only the values a given run's records use would save nothing. A test
# holds this to `FAMILIES` the same way `RELATION_HELP` is held to `RELATIONS`.
FAMILY_HELP: dict[str, str] = {
    "hash": "A cryptographic hash function (message digest), independent of any specific use.",
    "checksum": "A non-cryptographic hash or CRC used for integrity checking, not security.",
    "block_cipher": "A symmetric block cipher, such as AES or Blowfish.",
    "stream_cipher": "A symmetric stream cipher, such as ChaCha20 or RC4.",
    "aead": (
        "An authenticated-encryption construction that combines confidentiality and "
        "integrity in one primitive."
    ),
    "mac": "A message authentication code, such as HMAC, that authenticates rather than encrypts.",
    "kdf": "A key derivation function that turns input material into cryptographic key bytes.",
    "password_hash": (
        "A password-hashing construction, such as bcrypt or Argon2, built to be slow "
        "rather than fast."
    ),
    "signature": "A digital signature algorithm, such as RSA, ECDSA or EdDSA.",
    "key_agreement": (
        "A key-agreement or key-exchange construction, such as Diffie-Hellman or ECDH."
    ),
    "kem": "A key encapsulation mechanism, including post-quantum constructions such as ML-KEM.",
    "drbg": "A deterministic random bit generator that stretches a seed into pseudorandom output.",
    "entropy": "A source of entropy feeding a DRBG, such as an OS random device.",
    "tls": (
        "TLS/SSL protocol handling: version negotiation, cipher suites and certificate "
        "verification."
    ),
    "ssh": "SSH protocol handling.",
    "trust_store": "A bundled certificate trust store.",
    "library": (
        "A general-purpose cryptography library or stack whose own primitives span "
        "several other families."
    ),
}


def render_markdown(records: Sequence[dict[str, Any]]) -> str:
    """A summary table, one row per wheel, sorted by filename, followed by each
    wheel's own two-section detail: its crypto inventory first, then what the FIPS
    compatibility lens makes of it. A wheel whose class is `NO_CRYPTO_DETECTED` still
    gets an inventory section -- it says so explicitly rather than disappearing, the
    same absence-is-not-evidence rule the class itself states.
    """
    if not records:
        return "No wheels scanned.\n"

    ordered = sorted(records, key=lambda record: str(record.get("wheel", {}).get("filename", "")))
    rows = [_row(record) for record in ordered]
    widths = [
        max(len(header), *(len(row[index]) for row in rows))
        for index, header in enumerate(_HEADERS)
    ]

    summary = "\n".join(
        [
            _line(_HEADERS, widths),
            _line(tuple("-" * width for width in widths), widths),
            *(_line(row, widths) for row in rows),
        ]
    )
    blocks = [summary, *(_wheel_section(record) for record in ordered)]
    return "\n\n".join(blocks) + "\n"


def _row(record: dict[str, Any]) -> tuple[str, ...]:
    wheel = record.get("wheel", {})
    verdict = record.get("verdict", {})
    crypto = record.get("crypto", {})
    reasons = verdict.get("reasons", [])
    return (
        str(wheel.get("filename", "?")),
        str(wheel.get("version") or "?"),
        _join(crypto.get("families", [])),
        _join_libraries(crypto.get("libraries", [])),
        _join(verdict.get("relations", [])),
        str(verdict.get("class", "?")),
        "yes" if verdict.get("needs_human_review") else "no",
        _summarise(reasons),
    )


def _join(values: Sequence[str]) -> str:
    return ", ".join(values) if values else "-"


def _join_libraries(libraries: Sequence[dict[str, Any]]) -> str:
    if not libraries:
        return "-"
    return ", ".join(f"{library['name']}:{library['linkage']}" for library in libraries)


def _summarise(reasons: Sequence[str], limit: int = 3) -> str:
    if not reasons:
        return "-"
    shown = [reason.split(":", 1)[0] for reason in reasons[:limit]]
    if len(reasons) > limit:
        shown.append(f"+{len(reasons) - limit} more")
    return ", ".join(shown)


def _line(cells: Sequence[str], widths: Sequence[int]) -> str:
    padded = " | ".join(cell.ljust(width) for cell, width in zip(cells, widths, strict=True))
    return f"| {padded} |"


def _wheel_section(record: dict[str, Any]) -> str:
    """One wheel's own detail: its crypto inventory, then its FIPS compatibility lens
    over the same evidence, then -- only when the wheel has any -- the coverage and
    wheel-hygiene findings that are evidence of neither: no `family` (not crypto
    inventory) and no `relation` (not the FIPS lens either), such as `WHEEL_GENERATOR`
    or an unreadable-object rule that assigns no verdict at all. Those two named
    sections are never optional, so a wheel with nothing to say in either still shows
    both, explicitly; the third is omitted entirely when there is nothing for it to
    say, rather than an empty heading with nothing under it.
    """
    wheel = record.get("wheel", {})
    filename = str(wheel.get("filename", "?"))
    parts = [f"## {filename}", _inventory_section(record), _compatibility_section(record)]
    other = _other_evidence_section(record)
    if other is not None:
        parts.append(other)
    return "\n\n".join(parts)


# Its own wording, not CLASS_HELP["OPAQUE"]'s ("Stripped, unreadable or source-free.
# Cannot determine."): an empty inventory needs a sentence about the inventory being
# empty, not the class badge's own summary. Duplicated verbatim in
# data/report.html's `UNREADABLE_INVENTORY_NOTE`, since the HTML report's inventory
# section is written in JS rather than filled from this string;
# test_html_unreadable_inventory_note_matches_the_markdown_one pins the two copies
# together.
_UNREADABLE_INVENTORY_NOTE = (
    "This wheel could not be read well enough to say what cryptography it carries -- "
    "absence of evidence, not evidence of absence."
)


def _inventory_section(record: dict[str, Any]) -> str:
    """The "Cryptography in this wheel" section: libraries and their linkage first, then every
    finding grouped by the family of primitive it is evidence of. A finding with no
    `family` is not crypto evidence (an informational rule such as `WHEEL_GENERATOR`,
    say) and does not appear here -- `crypto.families` already skips it the same way;
    see `_other_evidence_section` for where it does appear.

    Empty and says so explicitly, rather than being left out, when the wheel carries
    no crypto evidence at all -- what makes acceptance criterion 1 hold for a
    `NO_CRYPTO_DETECTED` wheel's Markdown output, not only its HTML. An `OPAQUE` wheel
    also reaches this branch (nothing readable carries a `family` either), and must
    say something different here: "no families, no libraries" is true of both a wheel
    read in full that carries no crypto and a wheel this tool could not read at all,
    and only the first of those is the absence this sentence is allowed to claim.
    """
    crypto = record.get("crypto", {})
    families = crypto.get("families", [])
    libraries = crypto.get("libraries", [])
    parts = ["### Cryptography in this wheel"]
    if not families and not libraries:
        verdict_class = record.get("verdict", {}).get("class")
        is_opaque = verdict_class == "OPAQUE"
        parts.append(_UNREADABLE_INVENTORY_NOTE if is_opaque else "No cryptography detected.")
        return "\n\n".join(parts)
    parts.append(f"Families: {_join(families)}\n\nLibraries: {_join_libraries(libraries)}")
    findings = [finding for finding in record.get("findings", []) if finding.get("family")]
    if findings:
        parts.append(_findings_by_family(findings))
    return "\n\n".join(parts)


def _findings_by_family(findings: Sequence[dict[str, Any]]) -> str:
    groups: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        groups.setdefault(str(finding["family"]), []).append(finding)
    sections = []
    for family in sorted(groups):
        sections.append(f"**{family}**\n\n{_findings_table(groups[family])}")
    return "\n\n".join(sections)


def _compatibility_section(record: dict[str, Any]) -> str:
    """The "FIPS compatibility" section: the class badge as this section's own summary, then
    every contributing finding grouped by `relation`, in the relation table's
    remediation wording, with the standards each one cites."""
    verdict = record.get("verdict", {})
    cls = str(verdict.get("class", "?"))
    class_help = CLASS_HELP.get(cls, "No description; see the output schema.")
    parts = ["### FIPS compatibility", f"Class: {cls} -- {class_help}"]

    findings = [finding for finding in record.get("findings", []) if finding.get("relation")]
    by_relation: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        by_relation.setdefault(str(finding["relation"]), []).append(finding)

    for relation in sorted(verdict.get("relations", [])):
        help_text = RELATION_HELP.get(relation, "No description; see the output schema.")
        heading = f"**{relation}** -- {help_text}"
        bullets = "\n".join(
            f"- {finding.get('rule_id', '?')}: {finding.get('subject') or '-'} "
            f"(basis: {_join(finding.get('basis', []))})"
            for finding in by_relation.get(relation, [])
        )
        parts.append(f"{heading}\n\n{bullets}" if bullets else heading)

    return "\n\n".join(parts)


def _other_evidence_section(record: dict[str, Any]) -> str | None:
    """The "Other evidence" section: findings with no `family` (excluded from the crypto
    inventory) and no `relation` (excluded from the FIPS compatibility lens) --
    coverage and wheel-hygiene findings, verdict-bearing or not: an unreadable-object
    rule that carries `OPAQUE` and neither vocabulary, or a purely informational rule
    such as `WHEEL_GENERATOR` that carries no verdict at all. Without this section
    such a finding was visible nowhere but the JSONL and the Raw JSON tab, which is
    exactly the evidence a reader needs most when `_inventory_section` above is about
    to say the wheel carries no cryptography -- see its own docstring. `None` when
    there is nothing to say, so the wheel section never carries a third heading with
    nothing under it.
    """
    findings = [
        finding
        for finding in record.get("findings", [])
        if not finding.get("family") and not finding.get("relation")
    ]
    if not findings:
        return None
    return "\n\n".join(["### Other evidence", _findings_table(findings)])


def _findings_table(findings: Sequence[dict[str, Any]]) -> str:
    rows = [_finding_row(finding) for finding in findings]
    widths = [
        max(len(header), *(len(row[index]) for row in rows))
        for index, header in enumerate(_FINDING_HEADERS)
    ]
    return "\n".join(
        [
            _line(_FINDING_HEADERS, widths),
            _line(tuple("-" * width for width in widths), widths),
            *(_line(row, widths) for row in rows),
        ]
    )


def _finding_row(finding: dict[str, Any]) -> tuple[str, ...]:
    return (
        str(finding.get("rule_id", "?")),
        str(finding.get("subject") or "-"),
        str(finding.get("family") or "-"),
        str(finding.get("relation") or "-"),
        _join(finding.get("basis", [])),
        str(finding.get("severity", "?")),
        str(finding.get("verdict") or "-"),
        str(finding.get("occurrences", 0)),
    )


# --- HTML report --------------------------------------------------------------------

_DATA_TOKEN = "/*WCS_DATA*/"


def render_html(records: Sequence[dict[str, Any]], ruleset: Ruleset) -> str:
    """A self-contained HTML page: one row per wheel, with a drill-down detail view.

    The page is a pure function of `records`, `ruleset` and the shipped template: no
    timestamp, host path or hostname, so the same input renders byte-identical output.
    The template is filled through a sentinel-token `str.replace`, never `str.format`,
    because the page's own CSS braces would otherwise need escaping.
    """
    ordered = sorted(records, key=_html_sort_key)
    payload = {
        "records": ordered,
        "rules": _referenced_rules(ordered, ruleset),
        "standards": _referenced_standards(ordered, ruleset),
        "classes": _all_classes(ordered, ruleset),
        "class_help": CLASS_HELP,
        "linkage_help": LINKAGE_HELP,
        "family_help": FAMILY_HELP,
        "relation_help": RELATION_HELP,
        "tool": _tool_variants(ordered),
    }
    template = files("wheel_crypto_scan").joinpath("data/report.html").read_text(encoding="utf-8")
    return template.replace(_DATA_TOKEN, _embed_json(payload))


def _html_sort_key(record: dict[str, Any]) -> tuple[str, str]:
    """Sort by filename; the canonical JSON line is the tiebreak so two records that
    happen to share a filename still land in a stable, deterministic order."""
    filename = str(record.get("wheel", {}).get("filename") or "")
    canonical = json.dumps(record, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return (filename, canonical)


def _all_classes(records: Sequence[dict[str, Any]], ruleset: Ruleset) -> list[str]:
    """The class filter and legend read this list straight off the payload, so it
    must cover every class a record can actually carry, not only the ones named in
    the given ruleset's own precedence: the loader requires a ruleset's `[verdict]
    precedence` to name every class `classify()` can emit, including the
    `NO_CRYPTO_DETECTED` fallback, but `render_html` takes any `Ruleset`, including
    one built without the loader, so the union still protects a record whose class
    that ruleset's precedence leaves out. Computing it here, rather than in the
    page's own JavaScript, keeps the page a plain renderer of what it is handed and
    lets a Python test check the payload directly."""
    seen: dict[str, None] = dict.fromkeys(ruleset.precedence)
    for record in records:
        cls = record.get("verdict", {}).get("class")
        if cls and cls not in seen:
            seen[cls] = None
    return list(seen)


def _referenced_rules(records: Sequence[dict[str, Any]], ruleset: Ruleset) -> dict[str, Any]:
    """`{rule_id: {title, why, verdict, severity, family, relation, basis}}` for only
    the rule ids the embedded records actually name, so the page need not ship the
    whole ruleset to power its reason and finding tooltips."""
    by_id = {rule.id: rule for rule in ruleset.rules}
    wanted: set[str] = set()
    for record in records:
        for finding in record.get("findings", ()):
            rule_id = finding.get("rule_id")
            if rule_id:
                wanted.add(rule_id)
        wanted.update(record.get("verdict", {}).get("rule_ids", ()))
    return {
        rule_id: {
            "title": by_id[rule_id].title,
            "why": by_id[rule_id].why,
            "verdict": by_id[rule_id].verdict,
            "severity": by_id[rule_id].severity,
            "family": by_id[rule_id].family,
            "relation": by_id[rule_id].relation,
            "basis": sorted(by_id[rule_id].basis),
        }
        for rule_id in wanted
        if rule_id in by_id
    }


def _referenced_standards(records: Sequence[dict[str, Any]], ruleset: Ruleset) -> dict[str, Any]:
    """`{standard_id: {title, edition, status, successor, url}}` for only the standard
    ids some embedded record's findings cite in their own `basis`, the same narrowing
    `_referenced_rules` does for rule ids: the page ships only the citations its own
    findings actually use, not the ruleset's whole `[[standard]]` table."""
    wanted: set[str] = set()
    for record in records:
        for finding in record.get("findings", ()):
            wanted.update(finding.get("basis", ()))
    return {
        standard_id: {
            "title": ruleset.standards[standard_id].title,
            "edition": ruleset.standards[standard_id].edition,
            "status": ruleset.standards[standard_id].status,
            "successor": ruleset.standards[standard_id].successor,
            "url": ruleset.standards[standard_id].url,
        }
        for standard_id in wanted
        if standard_id in ruleset.standards
    }


def _tool_variants(records: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sorted, distinct `(version, ruleset_version, analyzer_version, evidence_level)`
    tuples across the embedded records. The page shows every variant it finds among
    the records it is given rather than picking one and hiding the rest."""
    seen = set()
    for record in records:
        tool = record.get("tool", {})
        seen.add(
            (
                tool.get("version"),
                tool.get("ruleset_version"),
                tool.get("analyzer_version"),
                tool.get("evidence_level"),
            )
        )
    return [
        {
            "version": version,
            "ruleset_version": ruleset_version,
            "analyzer_version": analyzer_version,
            "evidence_level": evidence_level,
        }
        for version, ruleset_version, analyzer_version, evidence_level in sorted(
            seen, key=lambda item: tuple(str(part) for part in item)
        )
    ]


def _embed_json(payload: Any) -> str:
    """Canonical JSON, escaped so no wheel-controlled string (a filename, a matched
    string, an evidence snippet) can close the `<script>` element it is embedded in.

    `<`, `>` and `&` are replaced with their JSON `\\u` escapes, not HTML entities.
    `<script>` is an HTML "raw text" element: its content is never scanned for
    character references, only for the literal bytes `</script`, so `.textContent`
    hands JavaScript back `&lt;` completely unchanged -- an HTML-entity escape would
    survive `JSON.parse` as four extra characters inside the string it was supposed to
    protect, corrupting exactly the data it was meant to carry safely. A JSON `\\u`
    escape has no literal `<`, so it can never form `</script`, and it round-trips:
    `JSON.parse` decodes `\\u003c` the same way it decodes any other escape in a JSON
    string. Verified against a real browser, not just the two specs this reasons from.
    """
    text = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
