"""Printable-string extraction and string-group matching.

The scanner never shells out to `strings(1)`: that would depend on a host tool whose
version, locale and flags are not part of our contract, which is fatal to the
determinism this tool promises. Extraction here is a single regex over raw bytes, so
the same bytes always produce the same runs everywhere.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from ..evidence import StringMatch
from ..ruleset import StringGroup


@dataclass(frozen=True, slots=True)
class ExtractedStrings:
    """Printable runs from one binary, joined so a match can recover its context."""

    text: str
    truncated: bool


def extract_printable(data: bytes, min_length: int, max_bytes: int) -> ExtractedStrings:
    """Pull out runs of printable ASCII, each at least `min_length` bytes long.

    `data` is truncated to `max_bytes` first, so a caller that already bounded its
    read gets a no-op here; one that did not still gets a hard cap. Runs are joined
    with "\\n", which both `match_string_groups` and `find_rust_crates` rely on to
    recover the whole run around a match rather than just the matched substring.
    """
    truncated = False
    if len(data) > max_bytes:
        data = data[:max_bytes]
        truncated = True
    length = max(min_length, 1)
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % length)
    runs = [match.group().decode("ascii") for match in pattern.finditer(data)]
    return ExtractedStrings(text="\n".join(runs), truncated=truncated)


def match_string_groups(
    extracted: ExtractedStrings, groups: Sequence[StringGroup], max_matches: int
) -> tuple[tuple[StringMatch, ...], bool]:
    """Find every string group hit, each reported with its enclosing printable run.

    A match's `value` is the whole run that contains it (recovered via the "\\n"
    separators `extract_printable` left behind), not just the substring the group's
    pattern matched: a banner like "OpenSSL 3.0.14 4 Jun 2024" is far more useful
    evidence than the "OpenSSL 3." fragment that triggered the match. Results are
    deduplicated, then sorted, then capped, so truncation is stable.
    """
    text = extracted.text
    found: set[StringMatch] = set()
    for group in groups:
        for m in group.pattern.finditer(text):
            start = text.rfind("\n", 0, m.start())
            start = 0 if start == -1 else start + 1
            end = text.find("\n", m.end())
            end = len(text) if end == -1 else end
            found.add(StringMatch(group=group.name, value=text[start:end]))
    ordered = tuple(sorted(found, key=lambda match: match.sort_key()))
    truncated = len(ordered) > max_matches
    return ordered[:max_matches], truncated
