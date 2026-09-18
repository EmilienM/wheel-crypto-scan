"""Reading an object for strings alone, when nothing better is available.

It exists so that "we could not parse this" and "there was nothing to find" never
produce the same record. Whatever the strings pass finds is real evidence and does not
depend on any structure being readable: `cryptography` 42 and later compiles OpenSSL
straight into the extension, with no library file and no dependency to name, so on some
builds the only evidence of it is an `OpenSSL 3.2.1` banner in read-only data.

Two callers. `binfmt.read_binary` dispatches here for a format with no registered
reader. `binfmt.elf` and `binfmt.macho` call it when their own parse fails, which is the
reader contract stated in `binfmt`: a header that did not parse costs the header, never
the strings already in hand. `binfmt.pe` keeps that contract without coming through
here, writing its own failure records field by field for the reason its module says.
Either way the record comes back marked `partial_analysis`, so a wheel never looks clean
merely because the tool could not read it.

`fmt` is required and never defaulted. This reader cannot name its own format: it
serves whatever `binfmt.detect_format` returned, including a format that is recognised
but has no reader yet, and a structural reader passes its own. Passing the wrong one
mislabels the record.
"""

from __future__ import annotations

from ..evidence import BinaryEvidence, ScanError
from ..ruleset import BinaryPatterns
from .golang import build_go_info
from .strings import scan_strings


def read_strings_only(
    stream,
    path: str,
    patterns: BinaryPatterns,
    *,
    vendored: bool,
    fmt: str,
    max_strings_bytes: int,
    reason: str,
) -> tuple[BinaryEvidence, tuple[ScanError, ...]]:
    """Read `stream` for printable strings and cargo paths, and nothing else.

        Contributes no errors of its own. On the dispatch path there is nothing to
        record: not parsing a format this tool never claimed to parse is not a failure, and
        `partial_analysis` already says the object was not read in full. A structural reader
        calling in from its own failure path records that failure at the call site.

    `reason` is required for the same cause as `fmt`, and is the same kind of thing: a
        label this reader cannot derive. An ELF whose header would not parse is a different
        fact from a format nobody claimed to read, and only the record can tell a consumer
        which it was looking at. Defaulting it would be the quiet way to mislabel a record,
        which is what requiring `fmt` already refuses. Neither changes what is read.
    """
    # Deriving the size here rather than taking it from the caller costs a pass over
    # the object, and every caller already holds it. It stays anyway: through a
    # `wheelfile.SeekableZipMember` the seek to the end is what forces the reopen that
    # clears the retained window, and without it the following `seek(0)` is served from
    # a warm window whose short read returns a few dozen bytes. That failure is silent
    # -- an object scanned for no strings at all, with nothing raised -- so an optional
    # `size` has to come with a read loop or a `BufferedReader`, not on its own.
    stream.seek(0, 2)
    size = stream.tell()
    stream.seek(0)
    data = stream.read(min(size, max_strings_bytes))
    truncated = size > max_strings_bytes

    strings_found = scan_strings(data, patterns, max_strings_bytes)
    # `binfmt.pe` has always kept its Go markers across a header that would not parse.
    # Building them here is what makes that true of every format rather than one: the
    # markers are in the strings, and this reader never has `.go.buildinfo` bytes to
    # pass, so `None` is not a loss of anything.
    go = build_go_info(None, strings_found.text, patterns)

    result = BinaryEvidence(
        path=path,
        format=fmt,
        vendored_path=vendored,
        matched_strings=strings_found.matched_strings,
        rust_crates=strings_found.rust_crates,
        go=go,
        strings_truncated=truncated or strings_found.truncated,
        partial_analysis=True,
        partial_reasons=(reason,),
    )
    return result, ()
