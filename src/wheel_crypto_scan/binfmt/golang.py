"""Go toolchain provenance: the buildinfo blob and its BoringCrypto marker strings.

Go binaries have carried a `.go.buildinfo` section since 1.13, but its layout changed
in 1.18 to store the version inline as a length-prefixed string instead of a pointer
to one. We only parse the 1.18+ shape, on purpose: `binfmt` never sees the binary
mapped into memory, so a pointer-based version string (which points at an address,
not a file offset) cannot be resolved without guessing at the load layout. A wrong
guess would print a plausible-looking, wrong Go version, which is worse than none, so
older binaries fall back to the string-marker signals below.
"""

from __future__ import annotations

import re

from ..evidence import GoBuildInfo
from ..ruleset import BinaryPatterns

# The 14-byte magic every `.go.buildinfo` section starts with, regardless of version.
_BUILDINFO_MAGIC = b"\xff Go buildinf:"

# Byte 15 (the flags byte) of the header. Bit 0x2 marks the Go 1.18+ layout, where the
# version string is stored inline from offset 32 rather than behind a pointer.
_FLAG_INLINE_STRINGS = 0x2

_HEADER_SIZE = 32

# A Go release version, permissive enough to accept pre-release and devel suffixes
# ("go1.22.3", "go1.23rc1") without being permissive enough to accept arbitrary junk.
_VERSION_RE = re.compile(r"^go[0-9]+\.[0-9]+(?:\.[0-9]+)?[A-Za-z0-9.-]*$")


def _read_uvarint(data: bytes, offset: int) -> tuple[int, int] | None:
    """Decode a Go `encoding/binary` uvarint starting at `offset`.

    Returns (value, next_offset), or None when the data runs out or the varint is
    unreasonably long (which only happens for corrupt or hostile input; a real Go
    buildinfo string length never needs more than a few bytes).
    """
    result = 0
    shift = 0
    pos = offset
    while pos < len(data):
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            return None
    return None


def parse_go_buildinfo(data: bytes) -> str | None:
    """Extract the Go version string from a `.go.buildinfo` section, or None.

    Returns None for anything not confidently the Go 1.18+ inline-string layout: no
    magic, too short, the pre-1.18 pointer layout, or a length-prefixed string that
    does not look like a Go version. A missing version is a known gap; a wrong one
    would be silently misleading.
    """
    if not data.startswith(_BUILDINFO_MAGIC) or len(data) <= _HEADER_SIZE:
        return None
    flags = data[15]
    if not flags & _FLAG_INLINE_STRINGS:
        return None
    parsed = _read_uvarint(data, _HEADER_SIZE)
    if parsed is None:
        return None
    length, start = parsed
    end = start + length
    if length <= 0 or end > len(data):
        return None
    try:
        text = data[start:end].decode("ascii")
    except UnicodeDecodeError:
        return None
    if not _VERSION_RE.match(text):
        return None
    return text


def build_go_info(
    buildinfo: bytes | None, text: str, patterns: BinaryPatterns
) -> GoBuildInfo | None:
    """Assemble `GoBuildInfo` from a buildinfo section and/or extracted strings.

    Returns None when there is nothing at all to report: no buildinfo section and no
    Go marker strings in `text`. Callers that already know from other evidence (such
    as a `.note.go.buildid` section) that the object is a Go binary should still
    record that fact even when this returns None.
    """
    go_version = parse_go_buildinfo(buildinfo) if buildinfo is not None else None
    # The group names come from the ruleset, so renaming a group there cannot silently
    # flip `boring_crypto` while the matching rule still fires.
    # Every Go group the ruleset names, not only the ones a typed field is derived
    # from: `markers` is the structured summary a consumer reads instead of the
    # findings, and a group missing from it would make that summary contradict the
    # verdict built from the same strings -- a build against the Go FIPS 140-3 module
    # reporting `["go_stock_crypto"]` while its verdict said otherwise.
    wanted = {patterns.go_boring_group, patterns.go_stock_group, patterns.go_fips140_group}
    marker_groups = {group.name: group for group in patterns.string_groups if group.name in wanted}
    markers = tuple(
        sorted(name for name, group in marker_groups.items() if group.pattern.search(text))
    )
    if buildinfo is None and not markers:
        return None
    return GoBuildInfo(
        go_version=go_version,
        boring_crypto=patterns.go_boring_group in markers,
        markers=markers,
    )
