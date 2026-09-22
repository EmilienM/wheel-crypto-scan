"""Human-readable views of the records. The JSONL contract lives in `record.py`.

Markdown is for reading over someone's shoulder: the summary deliberately leads with
the verdict class and the OpenSSL linkage, because those are the two columns a
component team actually triages on. HTML is for browsing and drill-down: one
self-contained page with the same columns, sortable and filterable, with a detail
view per wheel. Both are views; the JSONL is the contract.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from importlib.resources import files
from typing import Any

from .ruleset import Ruleset

_HEADERS = ("wheel", "version", "class", "openssl", "review", "reasons")

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


def render_markdown(records: Sequence[dict[str, Any]]) -> str:
    """A summary table, one row per wheel, sorted by filename."""
    if not records:
        return "No wheels scanned.\n"

    rows = [_row(record) for record in records]
    rows.sort(key=lambda row: row[0])
    widths = [
        max(len(header), *(len(row[index]) for row in rows))
        for index, header in enumerate(_HEADERS)
    ]

    lines = [
        _line(_HEADERS, widths),
        _line(tuple("-" * width for width in widths), widths),
        *(_line(row, widths) for row in rows),
    ]
    return "\n".join(lines) + "\n"


def _row(record: dict[str, Any]) -> tuple[str, ...]:
    wheel = record.get("wheel", {})
    verdict = record.get("verdict", {})
    conditions = verdict.get("conditions", {})
    reasons = verdict.get("reasons", [])
    return (
        str(wheel.get("filename", "?")),
        str(wheel.get("version") or "?"),
        str(verdict.get("class", "?")),
        str(conditions.get("openssl_linkage", "-")),
        "yes" if verdict.get("needs_human_review") else "no",
        _summarise(reasons),
    )


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
        "classes": _all_classes(ordered, ruleset),
        "class_help": CLASS_HELP,
        "linkage_help": LINKAGE_HELP,
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
    """`{rule_id: {title, why, verdict, severity}}` for only the rule ids the embedded
    records actually name, so the page need not ship the whole ruleset to power its
    reason and finding tooltips."""
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
        }
        for rule_id in wanted
        if rule_id in by_id
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
