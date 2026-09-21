"""Behaviour of `binfmt.symtab.BoundedNames`: the cap/budget/cache shared by ELF and
Mach-O symbol-name resolution.

`test_binfmt_elf.py` and `test_binfmt_macho.py` exercise the per-name cap, the
whole-table budget and the memoization this class provides, through their own
readers, at a scale a real object could plausibly carry. This file holds the one
property neither of those exercises: the cache itself cannot grow without bound just
because a table has many distinct offsets, none of which repeat.
"""

from __future__ import annotations

from wheel_crypto_scan.binfmt.symtab import _MAX_CACHE_ENTRIES, _MAX_NAME_BYTES, BoundedNames


def test_the_cache_does_not_grow_past_its_own_cap() -> None:
    """Many distinct, cheap-to-resolve offsets must not be remembered one each forever.

    Each name here costs the whole-table byte budget almost nothing, so a table shaped
    like this one -- many rows, each its own tiny, valid, never-repeated name -- would
    exhaust neither the per-name cap nor the byte budget before running the cache's own
    entry count well past it. `binfmt.elf` and `binfmt.macho` already avoid remembering
    every name in a huge table for exactly this reason elsewhere (a half-million-symbol
    table costs 24 MiB remembered whole), so the name cache cannot reopen that door
    through a table shaped to dodge the byte budget instead of the per-name cap.

    Every offset still has to resolve correctly regardless: the cap only stops this
    class remembering an answer, never stops it giving one.
    """
    count = _MAX_CACHE_ENTRIES * 2
    strings = bytearray(b"\x00")
    entries: list[tuple[int, str]] = []
    for index in range(count):
        offset = len(strings)
        name = f"n{index}"
        strings.extend(name.encode("ascii") + b"\x00")
        entries.append((offset, name))

    resolver = BoundedNames(bytes(strings))
    for offset, expected in entries:
        name, resolved = resolver.resolve(offset)
        assert resolved is True
        assert name == expected

    assert len(resolver._cache) <= _MAX_CACHE_ENTRIES


def test_a_small_table_is_cached_in_full() -> None:
    """The cap is generous, not the default state: an ordinary table is not degraded."""
    strings = b"\x00EVP_DigestInit_ex\x00SSL_new\x00"
    resolver = BoundedNames(strings)
    resolver.resolve(1)
    resolver.resolve(19)
    resolver.resolve(1)  # repeated, must not add a second entry
    assert len(resolver._cache) == 2


def test_a_name_exactly_as_long_as_the_remaining_budget_still_resolves() -> None:
    """A name costing exactly what is left of the budget is affordable, not one over.

    `window` as plain `min(cap + 1, available, budget)` would be wrong: with `budget`
    down to exactly `_MAX_NAME_BYTES`, that clamps the search span to `_MAX_NAME_BYTES`
    itself, one byte short of where a name of exactly that length terminates -- the
    budget limits how much content may be *spent*, not how far the search may look, and
    a search span equal to the spend limit is one byte too narrow to confirm a name
    spends exactly that much rather than more.
    """
    name = "A" * _MAX_NAME_BYTES
    strings = b"\x00" + name.encode("ascii") + b"\x00"
    resolver = BoundedNames(strings)
    resolver._budget = _MAX_NAME_BYTES  # as if this much, and no more, remained
    resolved_name, resolved = resolver.resolve(1)
    assert resolved is True
    assert resolved_name == name
