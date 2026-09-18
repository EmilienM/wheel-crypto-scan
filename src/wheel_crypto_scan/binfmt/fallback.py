"""The reader for objects this package has no structural reader for.

It exists so that "we could not parse this" and "there was nothing to find" never
produce the same record. An object in a format with no reader, or in no format at all,
still gets the strings-and-rust-crates pass and still comes back marked
`partial_analysis`, which is what keeps a wheel from looking clean merely because the
tool could not read it.

Unlike the three structural readers, this one cannot name its own format: it serves
whatever `binfmt.detect_format` returned, including a format that is recognised but
has no reader registered yet. `fmt` is therefore required, and passing the wrong one
mislabels the record, so it is the caller's business and never defaulted.
"""

from __future__ import annotations

from dataclasses import replace

from ..evidence import BinaryEvidence, ScanError
from ..ruleset import BinaryPatterns
from .rust import find_rust_crates
from .strings import extract_printable, match_string_groups


def read_strings_only(
    stream,
    path: str,
    patterns: BinaryPatterns,
    *,
    vendored: bool,
    fmt: str,
    max_strings_bytes: int,
) -> tuple[BinaryEvidence, tuple[ScanError, ...]]:
    """Read `stream` for printable strings and cargo paths, and nothing else.

    Returns no errors. Not being able to parse a format this tool never claimed to
    parse is not a failure worth recording; `partial_analysis` already says the object
    was not read in full.
    """
    stream.seek(0, 2)
    size = stream.tell()
    stream.seek(0)
    data = stream.read(min(size, max_strings_bytes))
    truncated = size > max_strings_bytes

    extracted = extract_printable(data, patterns.limits.min_string_length, max_strings_bytes)
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

    result = BinaryEvidence(
        path=path,
        format=fmt,
        vendored_path=vendored,
        matched_strings=matched_strings,
        rust_crates=rust_crates,
        strings_truncated=(
            truncated or extracted.truncated or string_match_truncated or rust_truncated
        ),
        partial_analysis=True,
    )
    return result, ()
