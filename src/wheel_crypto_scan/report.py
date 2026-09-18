"""The human-readable Markdown summary. The JSONL contract lives in `record.py`.

Markdown is for reading over someone's shoulder. The summary deliberately leads with
the verdict class and the OpenSSL linkage, because those are the two columns a
component team actually triages on.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

_HEADERS = ("wheel", "version", "class", "openssl", "review", "reasons")


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
