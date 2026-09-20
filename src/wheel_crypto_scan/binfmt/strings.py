"""What "printable" means here, and everything that follows from it.

The scanner never shells out to `strings(1)`: that would depend on a host tool whose
version, locale and flags are not part of our contract, which is fatal to the
determinism this tool promises. Extraction here is a single regex over raw bytes, so
the same bytes always produce the same runs everywhere.

Three things live here. `sanitize` and `extract_printable` are both expressions of
`evidence.PRINTABLE` (`sanitize`'s own complement class included, derived from the same
range rather than spelled again), which is why `sanitize` is in this module despite not
being about extraction at all: it is applied to names the readers pull out of their own
structural tables, and a second spelling of the same character range in a second file is
a thing that drifts. `match_string_groups` and `scan_strings` build on them.

`scan_strings` is the whole sequence every reader runs over its bytes. It is the one
part of a reader's work with no per-format variation at all, which is what makes it
worth naming: it was four copies of the same four calls, in the same order, with the
same limits, that four readers had to keep in step by hand.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, replace

from ..evidence import PRINTABLE, RustCrate, StringMatch
from ..ruleset import BinaryPatterns, StringGroup
from .caps import cap
from .rust import find_rust_crates

# `sanitize` filters by `PRINTABLE` and `extract_printable`'s regex class is derived
# from it, because the same range spelled twice is two things that can drift apart.
_PRINTABLE_CLASS = rb"[\x%02x-\x%02x]" % (PRINTABLE.start, PRINTABLE.stop - 1)
# The complement of `_PRINTABLE_CLASS`, over `str` rather than `bytes`: what `sanitize`
# strips. Same derivation, same one definition -- a `re.sub` over this is byte-identical
# to filtering character by character and doesn't pay per character for it. The `+` is
# not cosmetic: `symtab.py` bounds one row's own name at `_MAX_NAME_BYTES` (8 KiB), but
# nothing bounds how much of it is control bytes, and a class with no quantifier makes
# `re.sub` perform one substitution per non-printable character -- slower than the
# generator it replaced on exactly that input, because a run of them still costs one
# substitution apiece. Quantified, a whole run of non-printable bytes is one
# substitution, so the adversarial case is faster, not merely the ordinary one.
_NON_PRINTABLE_RE = re.compile(rf"[^\x{PRINTABLE.start:02x}-\x{PRINTABLE.stop - 1:02x}]+")

# What `extract_printable` joins runs with, and what `match_string_groups` searches for
# to recover a hit's enclosing run. Not itself printable ASCII (`ord("\n") == 0x0a`,
# outside `PRINTABLE`), which is the one fact `match_string_groups`'s own optimization
# depends on: `ruleset_loader` refuses any `[[string_group]]` substring that is not
# printable ASCII, so no group's pattern can ever match across this separator, and a
# hit's run boundaries are safe to reuse across hits instead of resolved fresh each
# time. `tests/test_binfmt_strings.py` pins that this constant stays outside `PRINTABLE`.
RUN_SEPARATOR = "\n"


def sanitize(text: str) -> str:
    """Drop anything outside printable ASCII, so recorded values are JSON-stable."""
    return _NON_PRINTABLE_RE.sub("", text)


# How much of one object every reader pulls into memory. It bounds the strings pass in
# all of them, and in `binfmt.pe` it bounds the structural read as well, because that
# reader resolves every directory inside this same buffer. Defined once: four copies of
# the number are four things that can drift apart.
#
# Reaching it is recorded. A region nothing looked at is why an object can carry a
# version banner and report none, so every reader names `strings_bytes_unread` when its
# own cut bites.
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
    with `RUN_SEPARATOR`, which both `match_string_groups` and `find_rust_crates` rely
    on to recover the whole run around a match rather than just the matched substring.
    """
    truncated = False
    if len(data) > max_bytes:
        data = data[:max_bytes]
        truncated = True
    length = max(min_length, 1)
    pattern = re.compile(_PRINTABLE_CLASS + b"{%d,}" % length)
    runs = [match.group().decode("ascii") for match in pattern.finditer(data)]
    return ExtractedStrings(text=RUN_SEPARATOR.join(runs), truncated=truncated)


def match_string_groups(
    extracted: ExtractedStrings, groups: Sequence[StringGroup], max_matches: int
) -> tuple[tuple[StringMatch, ...], bool]:
    """Find every string group hit, each reported with its enclosing printable run.

    A match's `value` is the whole run that contains it (recovered via the
    `RUN_SEPARATOR` boundaries `extract_printable` left behind), not just the
    substring the group's pattern matched: a banner like "OpenSSL 3.0.14 4 Jun 2024"
    is far more useful evidence than the "OpenSSL 3." fragment that triggered the
    match. Results are deduplicated, then sorted, then capped a group at a time, so
    truncation is stable and cannot silence a group outright.

    `finditer` yields a group's hits left to right, so once a run has been sliced for
    a group, every later hit whose start falls before that run's end is the same run
    again: recomputing its boundaries and re-slicing it would build the identical
    `StringMatch` the set already has (`__eq__` is by value, not position), just paid
    for again. Skipping those hits changes nothing the set ends up holding -- a run
    matched twice by the same group, or two separate runs that happen to share content,
    still land in `found` exactly as they would without the skip -- it only makes the
    cost one full-run copy per distinct run instead of one per hit.

    This assumes a group's pattern can never match text containing `RUN_SEPARATOR`, so
    a later hit's start falling inside the previous claim really does mean the same run
    rather than a stray one past it. `ruleset_loader` is what keeps that true: it
    refuses a `[[string_group]]` substring outside printable ASCII, and `RUN_SEPARATOR`
    is the only non-printable character an escaped-literal pattern built from printable
    substrings could ever match at all -- every other excluded character can't match
    anything in `text`, printable or not, so it costs a rule author nothing a run could
    have contained anyway. `tests/test_ruleset.py` pins this property against the
    shipped ruleset directly, rather than trusting the substrings-are-printable check
    as a proxy for it.
    """
    text = extracted.text
    found: set[StringMatch] = set()
    for group in groups:
        claimed_run_end = -1
        for m in group.pattern.finditer(text):
            if m.start() < claimed_run_end:
                continue
            start = text.rfind(RUN_SEPARATOR, 0, m.start())
            start = 0 if start == -1 else start + 1
            end = text.find(RUN_SEPARATOR, m.end())
            end = len(text) if end == -1 else end
            claimed_run_end = end
            found.add(StringMatch(group=group.name, value=text[start:end]))
    return cap(found, max_matches)


@dataclass(frozen=True, slots=True)
class StringsPass:
    """Everything one run of bytes yields, for the reader that produced them.

    `text` is the joined printable runs and is not dead weight: all three structural
    readers hand it to `binfmt.golang.build_go_info`, which reads its markers out of
    the same runs rather than paying for a second extraction.

    `truncated` covers only what happened inside this pass, and **it must never reach
    `partial_reasons`.** Everything behind it is a *recording* cap -- more group matches
    or more crates than the limits keep -- and a recording cap is not a partial read:
    the object was read, and what was capped is what got written down. What a cap costs
    is bounded by `binfmt.caps`, which keeps a representative of every key before it
    fills the remainder, so a cap can no longer silence a group or a named crate
    outright.

    Whether bytes went unread is the caller's question, because the caller is what
    bounded them: every reader here hands this function a buffer it has already cut to
    `max_strings_bytes`, so the cut is a fact only the reader holds. `binfmt.elf` cuts a
    concatenation of sections, the other three a prefix of the object, and each names
    `strings_bytes_unread` off its own flag rather than off anything in here.
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
        extracted.text,
        patterns.cargo_path_regex,
        patterns.limits.max_rust_crates_per_binary,
        claimed=patterns.rust_crate_names,
    )
    return StringsPass(
        matched_strings=matched_strings,
        rust_crates=rust_crates,
        text=extracted.text,
        truncated=extracted.truncated or string_match_truncated or rust_truncated,
    )
