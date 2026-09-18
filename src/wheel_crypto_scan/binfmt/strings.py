"""What "printable" means here, and everything that follows from it.

The scanner never shells out to `strings(1)`: that would depend on a host tool whose
version, locale and flags are not part of our contract, which is fatal to the
determinism this tool promises. Extraction here is a single regex over raw bytes, so
the same bytes always produce the same runs everywhere.

Four things live here. `PRINTABLE` is the definition; `sanitize` and `extract_printable`
are its two expressions, which is why `sanitize` is in this module despite not being
about extraction at all: it is applied to names the readers pull out of their own
structural tables, and a second spelling of the same character range in a second file
is a thing that drifts. `match_string_groups` and `scan_strings` build on them.

`scan_strings` is the whole sequence every reader runs over its bytes. It is the one
part of a reader's work with no per-format variation at all, which is what makes it
worth naming: it was four copies of the same four calls, in the same order, with the
same limits, that four readers had to keep in step by hand.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, replace

from ..evidence import RustCrate, StringMatch
from ..ruleset import BinaryPatterns, StringGroup
from .rust import find_rust_crates

# Printable characters only, so a corrupt string table entry can never smuggle control
# bytes or non-ASCII garbage into the (supposedly stable) JSON record. This is the one
# definition: `sanitize` filters by it and `extract_printable`'s regex class is derived
# from it, because the same range spelled twice is two things that can drift apart.
PRINTABLE = range(0x20, 0x7F)
_PRINTABLE_CLASS = rb"[\x%02x-\x%02x]" % (PRINTABLE.start, PRINTABLE.stop - 1)


def sanitize(text: str) -> str:
    """Drop anything outside printable ASCII, so recorded values are JSON-stable."""
    return "".join(ch for ch in text if ord(ch) in PRINTABLE)


# How much of one object every reader pulls into memory. It bounds the strings pass in
# all of them, and in `binfmt.pe` it bounds the structural read as well, because that
# reader resolves every directory inside this same buffer. Defined once: four copies of
# the number are four things that can drift apart.
MAX_STRINGS_BYTES = 64 * 1024 * 1024


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
    pattern = re.compile(_PRINTABLE_CLASS + b"{%d,}" % length)
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


@dataclass(frozen=True, slots=True)
class StringsPass:
    """Everything one run of bytes yields, for the reader that produced them.

    `text` is the joined printable runs and is not dead weight: all three structural
    readers hand it to `binfmt.golang.build_go_info`, which reads its markers out of
    the same runs rather than paying for a second extraction.

    `truncated` covers only what happened inside this pass. How `raw` was bounded in
    the first place is the caller's business and the caller ORs it in.
    """

    matched_strings: tuple[StringMatch, ...]
    rust_crates: tuple[RustCrate, ...]
    text: str
    truncated: bool


def scan_strings(raw: bytes, patterns: BinaryPatterns, max_bytes: int) -> StringsPass:
    """Extract printable runs, match the string groups, and find the cargo paths.

    Deliberately ignorant of how `raw` was produced: `binfmt.elf` passes the
    concatenated read-only sections, the other readers pass a bounded prefix of the
    whole object, and a shared pass that knew the difference would couple their read
    strategies to each other for nothing.

    It stops short of `build_go_info`, which every structural reader calls next, and
    that is the line rather than an oversight. `binfmt.elf` passes it the
    `.go.buildinfo` section bytes read during its structural parse, where Mach-O and PE
    pass `None`, and then overrides a `None` result when the object carries a Go build
    id. A `go` field here would be a field one reader in three has to correct, and a
    format-specific input in a helper whose whole justification is having none.
    """
    extracted = extract_printable(raw, patterns.limits.min_string_length, max_bytes)
    string_matches, string_match_truncated = match_string_groups(
        extracted, patterns.string_groups, patterns.limits.max_strings_per_binary
    )
    matched_strings = tuple(
        replace(match, value=match.value[: patterns.limits.max_evidence_chars])
        for match in string_matches
    )
    rust_crates, rust_truncated = find_rust_crates(
        extracted.text, patterns.cargo_path_regex, patterns.limits.max_rust_crates_per_binary
    )
    return StringsPass(
        matched_strings=matched_strings,
        rust_crates=rust_crates,
        text=extracted.text,
        truncated=extracted.truncated or string_match_truncated or rust_truncated,
    )
