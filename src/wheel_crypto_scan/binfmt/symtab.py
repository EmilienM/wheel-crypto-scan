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

`BoundedNames` shares the same reasoning one level down, over the read that feeds this
check rather than the check itself: a name has no length bound of its own here either,
so nothing stopped many rows pointing at one enormous name, or many rows pointing at
many merely-long ones, from costing rows-times-bytes in `sanitize`, a per-character
Python pass. `binfmt.pe` solved the identical shape for PE's export and import tables
in #53; this ports the same two-part bound -- a per-name cap and a whole-table budget --
to the string table both `binfmt.elf` and `binfmt.macho` read symbol names out of. #61.
"""

from __future__ import annotations

from collections.abc import Callable

from ..ruleset import BinaryPatterns
from .strings import sanitize

# How far to look for one name's terminator, ported from `binfmt.pe`'s
# `_MAX_NAME_BYTES` (#53) at the same value: PE's own corpus measurement (30,835 export
# names across 383 real objects, the longest an MSVC-mangled 1027-byte C++ name) is the
# only real-world sample this reader has, and an Itanium-mangled C++ name or a legacy
# Rust symbol (a full module path plus a hash) grows unbounded the same way a
# MSVC-mangled one does, so nothing here argues for a different number without a
# corpus of our own. A name of exactly this many bytes still resolves; one byte longer
# does not -- past it the row is reported unresolved, the same as an index past the
# end of the table or into a run it never closes, never truncated into the record.
_MAX_NAME_BYTES = 8 * 1024

# One budget for the whole string table, mirroring `binfmt.pe`'s
# `_MAX_NAME_TOTAL_BYTES`, for the same reason: the per-name cap bounds one row, but
# nothing stops every row's index aiming at the same long name, or at many different
# long names, and either shape multiplies rows by bytes. What is expensive is
# `sanitize`, so it is the resolved bytes that have to be bounded, not the row count.
# Sized off the same PE corpus in the same proportion (roughly fifteen times its
# heaviest single object's resolved-name total) for lack of an ELF/Mach-O corpus of our
# own; revisit if a real wheel's honest symbol table is found against this budget.
_MAX_NAME_TOTAL_BYTES = 8 * 1024 * 1024

# How many distinct offsets `BoundedNames` will remember. The whole-table byte budget
# above does not bound this on its own: an offset that fails (past the table, or into
# a run it never closes) costs nothing from that budget, and neither does one that
# resolves to an empty or near-empty name, so a table built entirely of such offsets --
# one per row, all different -- could otherwise grow the cache by one entry per row
# regardless of `_MAX_NAME_TOTAL_BYTES`. That is exactly the cost `binfmt.elf` and
# `binfmt.macho` already avoid elsewhere by keeping only the crypto names read rather
# than every name (a half-million-symbol table costs 24 MiB remembered whole), so the
# cache that closes #61 cannot reopen it by a different door. Past this many distinct
# offsets, `resolve` keeps answering correctly, it simply stops remembering -- the same
# per-row cost an honest, mostly-unique table already paid before this cache existed,
# never worse. Sized like `binfmt.pe`'s `_MAX_THUNKS`: generous for a real object,
# nowhere near what #61's shape (many rows, few distinct offsets) needs to be closed.
_MAX_CACHE_ENTRIES = 65536


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
    object partial. And names are formed the way the table is laid out, from one NUL to
    the next: a name index may point at any byte, so a name that is the tail of a longer
    string is reachable and is not formed here. `DECISIONS.md` and #39 record why closing
    that costs more than it is worth -- every Rust or C++ symbol with a crypto name
    mangled inside it would read as an object hiding one.

    `patterns.symbol_locator` does the scanning in C and this loop only visits the runs
    it lands in, each of them once. Walking every run in Python instead put a 2 MiB
    string table of two-byte runs at nineteen seconds across a universal binary's
    slices, for an object a few megabytes long.
    """
    locator = patterns.symbol_locator
    if locator is None:
        return False
    start = 0
    stop = strings.find(b"\x00")
    if stop == -1:
        stop = len(strings)
    position = 0
    while (hit := locator.search(strings, position)) is not None:
        while hit.start() >= stop:
            start = stop + 1
            stop = strings.find(b"\x00", start)
            if stop == -1:
                stop = len(strings)
        raw = strings[start:stop].decode("utf-8", "replace")
        name = sanitize(normalise(raw) if normalise is not None else raw)
        if name and name not in read and patterns.symbol_groups_for(name):
            return True
        # This run has been judged; the next hit inside it would say nothing new.
        position = stop + 1
    return False


class BoundedNames:
    """Resolves NUL-terminated names out of one string table: capped, budgeted, cached.

    **One instance is scoped to exactly one string table, walked by exactly one
    caller's pass over it.** The cache is keyed by the raw byte offset into `strings`,
    which only means the same name when every lookup on this instance is asking about
    the same bytes. Sharing one instance -- or its cache -- across two different string
    tables (two symbol tables' string tables, or two slices of a fat Mach-O, each with
    its own `_read_symbols` call) would let one table's offset return a name read out
    of a completely different table: offset 8 meaning `EVP_DigestInit_ex` in one table
    and `md5_init` in another is exactly the collision a security-relevant cache cannot
    have. So a fresh instance is built for every table a reader walks -- `_iter_symbols`
    already gives each such pass its own local state; this only gives it a name -- and
    none is threaded in from outside or kept alive past that one pass.

    The cache also makes the per-name cap and the whole-table budget below sound
    against repetition: an offset resolved once is never re-decoded, so many rows
    pointing at the same offset cost the decode once, not once per row. An offset that
    failed once (past the cap, past the table, or past the budget) stays failed for
    every later row that shares it too -- correctly, since the budget only shrinks, so
    a later attempt at the same offset can never succeed where an earlier one did not.

    The cache is keyed by offset alone, not by offset and `normalise`, so every call
    against one instance that shares an offset must also agree on which `normalise` it
    passes to `resolve` -- two callers reading the same table but normalising its names
    differently would silently get whichever one resolved that offset first. Every
    caller today passes a fixed `normalise` per instance (Mach-O's `_strip_abi_prefix`
    for one pass, ELF's none for another), so this holds in practice; a caller mixing
    normalisers within one instance's lifetime would need its own cache.

    The cache itself is capped at `_MAX_CACHE_ENTRIES` distinct offsets, because the
    byte budget above only bounds the names it *spends on*: an offset that fails, or
    resolves to an empty name, costs the budget nothing, so a table of many rows each
    naming its own such offset would otherwise grow this cache by one entry per row
    regardless of the budget. Past the cap, `resolve` still answers every row
    correctly; it just stops remembering, which only costs the repeat-lookup speedup
    this cache exists to provide, never correctness.
    """

    def __init__(self, strings: bytes) -> None:
        self._strings = strings
        self._cache: dict[int, tuple[str, bool]] = {}
        self._budget = _MAX_NAME_TOTAL_BYTES

    def resolve(
        self, offset: int, *, normalise: Callable[[str], str] | None = None
    ) -> tuple[str, bool]:
        """(name, resolved) for the name at `offset`, sanitized.

        `resolved` is `False` for an offset past the table, a run the table never
        closes, a name past the per-name cap, or a table whose whole-table budget is
        already spent by names read earlier -- the caller reads all four the same way
        it already reads the first two: the name is not in hand, not a name shorter
        than the object carries. `normalise` is applied to the raw name before
        `sanitize`, the same knob `holds_a_name_not_read` takes, for the one caller
        that needs it (Mach-O's leading-underscore ABI prefix).

        The terminator is searched for in place over `strings`, bounded on both sides
        by the cap and by the budget still available, rather than sliced into a copy
        first and checked after: copying first costs the bound's width whatever the
        name turns out to be, which is how PE's own bound ended up cheap to search and
        expensive to copy. Cheapest place is the find call.
        """
        cached = self._cache.get(offset)
        if cached is not None:
            return cached
        result = self._resolve_uncached(offset, normalise)
        if len(self._cache) < _MAX_CACHE_ENTRIES:
            self._cache[offset] = result
        return result

    def _resolve_uncached(
        self, offset: int, normalise: Callable[[str], str] | None
    ) -> tuple[str, bool]:
        strings = self._strings
        if offset >= len(strings):
            return "", False
        # The most name content this call may read is the smaller of the per-name cap
        # and what remains of the whole-table budget; `+ 1` turns that into a search
        # span, because a name of exactly that many content bytes has its terminator
        # one byte past them, and such a name is meant to still resolve -- the bound
        # limits how much name content is read, not how many bytes are scanned.
        # `self._budget` alone, without this `+ 1`, searches one byte short: a name
        # exactly as long as the budget remaining would need its terminator at
        # `offset + self._budget`, outside a window sized to `self._budget` itself.
        max_len = min(_MAX_NAME_BYTES, self._budget)
        window = min(max_len + 1, len(strings) - offset)
        stop = strings.find(b"\x00", offset, offset + window) if window > 0 else -1
        if stop == -1:
            return "", False
        self._budget -= stop - offset
        raw = strings[offset:stop].decode("utf-8", "replace")
        return sanitize(normalise(raw) if normalise is not None else raw), True
