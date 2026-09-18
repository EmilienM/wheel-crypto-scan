"""Reads native objects inside a wheel and turns them into `BinaryEvidence`.

This is the layer that tells a wheel linking the system OpenSSL apart from one that
ships or statically links its own: everything else in the tool depends on the
`needed`/`soname` and `matched_symbols` binding this package produces. `read_binary`
is the single entry point; it sniffs the format and dispatches to the format-specific
reader, or to a strings-only fallback for anything it does not recognise, so a wheel
can never look clean merely because we cannot read it.

`max_strings_bytes` bounds how much of an object is pulled into memory. For ELF and
Mach-O that bounds the strings pass alone, because their structural reads go through
the stream. For PE it bounds the structural read too: that reader resolves every
directory inside the same buffer, so a directory lying past it is unread and is
reported as unread.
"""

from __future__ import annotations

from dataclasses import replace
from functools import partial
from typing import Protocol

from .. import evidence
from ..evidence import BinaryEvidence, ScanError
from ..ruleset import BinaryPatterns
from . import elf as _elf
from . import macho as _macho
from . import pe as _pe
from .detect import SNIFF_BYTES, detect_format
from .rust import find_rust_crates
from .strings import MAX_STRINGS_BYTES, extract_printable, match_string_groups

read_elf = _elf.read_elf
read_macho = _macho.read_macho
read_pe = _pe.read_pe


class Reader(Protocol):
    """The one signature every entry in `_READERS` answers to.

    Written down so the table can be a lookup rather than a chain: the branches this
    replaced each spelled the same argument list out by hand, which is exactly the
    kind of thing that drifts apart one reader at a time.
    """

    def __call__(
        self,
        stream,
        path: str,
        patterns: BinaryPatterns,
        *,
        vendored: bool,
        max_strings_bytes: int = MAX_STRINGS_BYTES,
    ) -> tuple[BinaryEvidence, tuple[ScanError, ...]]: ...


_READERS: dict[str, Reader] = {
    evidence.FORMAT_ELF: read_elf,
    evidence.FORMAT_MACHO: read_macho,
    evidence.FORMAT_PE: read_pe,
}


def read_binary(
    stream,
    path: str,
    patterns: BinaryPatterns,
    *,
    vendored: bool,
    max_strings_bytes: int = MAX_STRINGS_BYTES,
) -> tuple[BinaryEvidence, tuple[ScanError, ...]]:
    """Sniff `stream` and dispatch to the right reader.

    ELF, Mach-O and PE get full structural reads. Any format this tool does not
    recognise still gets a strings-and-rust-crates pass, so absence of a deep reader
    never looks the same as absence of evidence.
    """
    stream.seek(0)
    head = stream.read(SNIFF_BYTES)
    fmt = detect_format(head)
    stream.seek(0)

    # The fallback is bound to the format that was actually detected rather than
    # left to a default. `detect_format` may learn to name a format before this
    # package has a reader for it, and that object's record has to say what it is:
    # a table whose miss silently relabels the object `unknown` would take the one
    # line this refactor was meant to make safe and make it wrong instead.
    reader = _READERS.get(fmt) or partial(_read_strings_only, fmt=fmt)
    return reader(stream, path, patterns, vendored=vendored, max_strings_bytes=max_strings_bytes)


def _read_strings_only(
    stream,
    path: str,
    patterns: BinaryPatterns,
    *,
    vendored: bool,
    fmt: str,
    max_strings_bytes: int = MAX_STRINGS_BYTES,
) -> tuple[BinaryEvidence, tuple[ScanError, ...]]:
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


__all__ = ["Reader", "read_binary", "read_elf", "read_macho", "read_pe"]
