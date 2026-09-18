"""Reads native objects inside a wheel and turns them into `BinaryEvidence`.

This is the layer that tells a wheel linking the system OpenSSL apart from one that
ships or statically links its own: everything else in the tool depends on the
`needed`/`soname` and `matched_symbols` binding this package produces. `read_binary`
is the single entry point; it sniffs the format and dispatches to the format-specific
reader, or to a strings-only fallback for formats this tool does not parse in depth
(PE today), so a wheel can never look clean merely because we cannot read it.
"""

from __future__ import annotations

from dataclasses import replace

from .. import evidence
from ..evidence import BinaryEvidence, ScanError
from ..ruleset import BinaryPatterns
from . import elf as _elf
from . import macho as _macho
from .detect import SNIFF_BYTES, detect_format
from .rust import find_rust_crates
from .strings import extract_printable, match_string_groups

read_elf = _elf.read_elf
read_macho = _macho.read_macho


def read_binary(
    stream,
    path: str,
    patterns: BinaryPatterns,
    *,
    vendored: bool,
    max_strings_bytes: int = 64 * 1024 * 1024,
) -> tuple[BinaryEvidence, tuple[ScanError, ...]]:
    """Sniff `stream` and dispatch to the right reader.

    ELF and Mach-O get full structural reads. Everything else, including PE and any
    format this tool does not recognise, still gets a strings-and-rust-crates pass,
    so absence of a deep reader never looks the same as absence of evidence.
    """
    stream.seek(0)
    head = stream.read(SNIFF_BYTES)
    fmt = detect_format(head)
    stream.seek(0)

    if fmt == evidence.FORMAT_ELF:
        return read_elf(
            stream, path, patterns, vendored=vendored, max_strings_bytes=max_strings_bytes
        )
    if fmt == evidence.FORMAT_MACHO:
        return read_macho(
            stream, path, patterns, vendored=vendored, max_strings_bytes=max_strings_bytes
        )
    return _read_strings_only(
        stream, path, patterns, fmt, vendored=vendored, max_strings_bytes=max_strings_bytes
    )


def _read_strings_only(
    stream,
    path: str,
    patterns: BinaryPatterns,
    fmt: str,
    *,
    vendored: bool,
    max_strings_bytes: int,
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


__all__ = ["read_binary", "read_elf", "read_macho"]
