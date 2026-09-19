"""What a symbol table claims, checked against the string table it points into.

Every format here says how many symbols it has and leaves the names somewhere else:
`sh_size` over `.dynstr` in ELF, `nsyms` over `stroff` in Mach-O. Reading exactly what
the declaration says is not the same as reading every symbol the object carries, and the
difference is a way to look clean -- a table of five rows that declares one is read in
full by its own account while four names go unlooked-at.

Nothing structural says how many rows there really are. What sits between a symbol table
and its string table is another table's business in both formats, and assuming they are
adjacent is wrong for real layouts. The string table is the one place every name must
appear, though, so a name in it that a symbol group claims and that no entry we read
resolved to is a symbol the object carries and did not declare.

Shared because the check is the same in both readers and a security check that exists
twice is a security check that drifts. `DECISIONS.md` records what it does not cover.
"""

from __future__ import annotations

from collections.abc import Callable

from ..ruleset import BinaryPatterns
from .strings import sanitize


def holds_a_name_not_read(
    strings: bytes,
    patterns: BinaryPatterns,
    read: set[str],
    *,
    normalise: Callable[[str], str] | None = None,
) -> bool:
    """Does this string table hold a symbol-group name no entry we read resolved to?

    **The caller must have read this string table through.** A name index that pointed
    past its end, or into a run it never closes, means the caller did not resolve every
    row, and a name it could not resolve is one this function will find left over and
    blame the count for. Worse, the table may be short of names that are there. Both
    readers check that first and report it as its own cause: shrink `.dynstr` instead of
    `.dynsym` and every row, every count and every structural check survives while the
    names quietly stop being reachable.

    `read` is the crypto names the caller did read, which is all this needs: a name
    nothing claims never gets compared against it. `normalise` is whatever the caller
    applies to a raw name before matching it -- Mach-O's leading-underscore ABI prefix
    is the only one today -- so the name judged here is the one the reader would have
    judged, and the two cannot disagree about what a row would have been called.

    Two limits, both deliberate. It asks whether a *crypto* name went unread, not
    whether any name did, so padding and ordinary unreferenced strings do not make every
    object partial. `n_strx` may point at any byte, so every locator hit is treated as a
    candidate, from the hit offset to the next NUL, rather than only the run start.
    This closes the tail-of-string hole without needing to infer undeclared rows.

    `patterns.symbol_locator` does the scanning in C and this loop only visits the hits it
    lands on. Walking every run in Python instead put a 2 MiB string table of two-byte
    runs at nineteen seconds across a universal binary's slices, for an object a few
    megabytes long.
    """
    locator = patterns.symbol_locator
    if locator is None:
        return False
    position = 0
    while (hit := locator.search(strings, position)) is not None:
        stop = strings.find(b"\x00", hit.start())
        if stop == -1:
            stop = len(strings)
        raw = strings[hit.start() : stop].decode("utf-8", "replace")
        name = sanitize(normalise(raw) if normalise is not None else raw)
        if name and name not in read and patterns.symbol_groups_for(name):
            return True
        position = hit.start() + 1
    return False
