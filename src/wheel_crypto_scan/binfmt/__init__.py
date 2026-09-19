"""Reads native objects inside a wheel and turns them into `BinaryEvidence`.

This is the layer that tells a wheel linking the system OpenSSL apart from one that
ships or statically links its own: everything else in the tool depends on the
`needed`/`soname` and `matched_symbols` binding this package produces. `read_binary`
is the single entry point; it sniffs the format and dispatches to the reader
registered for it, or to `binfmt.fallback` when none is, so a wheel can never look
clean merely because we cannot read it.

Every reader here answers to one contract about failure: a structure that does not
parse costs that structure, never the evidence already gathered. A reader that cannot
read its own header still returns the strings, cargo paths and Go markers it found, and
still marks the object `partial_analysis`. Absence of evidence is not evidence of
absence, and the strings are often the only evidence there is. That is the outcome
required; how each reader reaches it is its own business, and `binfmt.pe` writes its
failure records out field by field where the other two call `binfmt.fallback`.

`max_strings_bytes` bounds how much of an object is pulled into memory, and reaching
that bound is itself recorded: a region nothing looked at is why an object can carry a
version banner and report none, so every reader names `strings_bytes_unread` when its
own cut bites. For ELF and Mach-O that bounds the strings pass alone, because their
structural reads go through the stream. For PE it bounds the structural read too: that
reader resolves every directory inside the same buffer, so a directory lying past it is
unread and is reported as unread.
"""

from __future__ import annotations

from functools import partial
from typing import Protocol

from .. import evidence
from ..evidence import BinaryEvidence, ScanError
from ..ruleset import BinaryPatterns
from . import elf as _elf
from . import macho as _macho
from . import pe as _pe
from .detect import SNIFF_BYTES, detect_format
from .fallback import read_strings_only
from .strings import MAX_STRINGS_BYTES

read_elf = _elf.read_elf
read_macho = _macho.read_macho
read_pe = _pe.read_pe


class _Reader(Protocol):
    """The one signature every entry in `_READERS` answers to.

    Written down so dispatch can be a lookup rather than a chain of branches that each
    spell the same argument list out by hand. Nothing type-checks this repo, so
    `test_binfmt_dispatch` asserts the table against it instead; a reader registered
    with a drifted signature would otherwise fail at scan time, where the binary
    layer's broad handler would quietly degrade it to one more unreadable object.

    `max_strings_bytes` carries a default because the three readers are public and the
    tests call them directly. Dispatch always passes it.
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


_READERS: dict[str, _Reader] = {
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
    """Sniff `stream` and dispatch to the reader registered for that format.

    Every format in `_READERS` gets a full structural read. Anything else, whether
    `detect_format` could name it or not, still gets a strings-and-rust-crates pass,
    so absence of a deep reader never looks the same as absence of evidence.
    """
    stream.seek(0)
    head = stream.read(SNIFF_BYTES)
    fmt = detect_format(head)
    stream.seek(0)

    reader = _READERS.get(fmt)
    if reader is None:
        # An object is recorded under the format it was sniffed as, even when nothing
        # here can read that format. `detect_format` may learn a name before a reader
        # exists for it, and relabelling such an object `unknown` would put the wrong
        # format into its record, into `engine`'s partial-read finding subject, and
        # into that finding's evidence line.
        reader = partial(read_strings_only, fmt=fmt, reason=evidence.PARTIAL_NO_STRUCTURAL_READER)
    return reader(stream, path, patterns, vendored=vendored, max_strings_bytes=max_strings_bytes)


__all__ = ["read_binary", "read_elf", "read_macho", "read_pe"]
