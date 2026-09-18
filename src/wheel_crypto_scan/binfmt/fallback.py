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

from ..evidence import BinaryEvidence, ScanError
from ..ruleset import BinaryPatterns
from .strings import scan_strings


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

    strings_found = scan_strings(data, patterns, max_strings_bytes)

    result = BinaryEvidence(
        path=path,
        format=fmt,
        vendored_path=vendored,
        matched_strings=strings_found.matched_strings,
        rust_crates=strings_found.rust_crates,
        strings_truncated=truncated or strings_found.truncated,
        partial_analysis=True,
    )
    return result, ()
