"""What a rule produces when evidence matches it.

A finding is keyed by rule and subject, not by occurrence. One wheel calling
`hashlib.md5()` two hundred times produces one finding with `occurrences: 200` and a
capped list of locations, so a record stays a readable size and a diff between two
scans stays legible.

`subject` is the table entry that matched, where there was one: the crate, library,
module or distribution. Without it a rule like BIN_RUST_CRYPTO_CRATE would have to
collapse `ring` and `blake3` into a single finding and lose their different verdicts.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Location:
    """Where inside the wheel the evidence was found, and what it literally was."""

    path: str
    line: int | None = None
    evidence: str = ""

    def sort_key(self) -> tuple[str, int, str]:
        return (self.path, -1 if self.line is None else self.line, self.evidence)


@dataclass(frozen=True, slots=True)
class Finding:
    """One rule, one subject, and every place it matched."""

    rule_id: str
    severity: str
    category: str
    layer: str
    confidence: str
    needs_human_review: bool
    occurrences: int
    locations: tuple[Location, ...]
    truncated: bool = False
    verdict: str | None = None
    subject: str | None = None

    def sort_key(self) -> tuple[str, str]:
        return (self.rule_id, self.subject or "")
