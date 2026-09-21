"""A cap bounds the record's size. It must not also choose which evidence survives.

Every per-binary limit exists so one object cannot produce an unbounded JSON line. None
exists to pick winners, and each of them did, because they sorted and cut and the sort
key has nothing to do with what a match is worth. Three reproductions are pinned here
end to end, because the unit test for the helper passes just as well against a reader
that never calls it.
"""

from __future__ import annotations

import io

import pytest

from helpers.binfmt import (
    DynSym,
    ElfBuilder,
    MachOBuilder,
    MachOSym,
    PEBuilder,
    PEExport,
    PEImport,
)
from wheel_crypto_scan.binfmt import read_binary
from wheel_crypto_scan.caps import cap
from wheel_crypto_scan.engine import apply_rules
from wheel_crypto_scan.evidence import (
    ArtifactInventory,
    BinaryEvidence,
    Evidence,
    RustCrate,
    ScanError,
    StringMatch,
    SymbolMatch,
)
from wheel_crypto_scan.linkage import resolve_linkage
from wheel_crypto_scan.record import _SkippedEntry, _SymlinkEntry
from wheel_crypto_scan.ruleset_loader import load_ruleset

RULESET = load_ruleset()
PATTERNS = RULESET.compile_patterns().binary
BANNER = b"OpenSSL 3.0.14 4 Jun 2024\x00"


def _cargo(name: str, version: str) -> bytes:
    root = "/root/.cargo/registry/src/index.crates.io-6f17d22bba15001f"
    return f"{root}/{name}-{version}/src/lib.rs\x00".encode()


def _evidence(data: bytes, path: str = "x") -> tuple[BinaryEvidence, Evidence]:
    """Read `data` and wrap it in the one-binary wheel `Evidence` every helper here needs."""
    ev, errors = read_binary(io.BytesIO(data), path, PATTERNS, vendored=False)
    wheel = Evidence(
        filename="demo-1.0-py3-none-any.whl",
        sha256="0" * 64,
        size_bytes=1,
        artifacts=ArtifactInventory(),
        binaries=(ev,),
        errors=errors,
    )
    return ev, wheel


def _scan(**builder):
    ev, linkage, wheel = _read(ElfBuilder(**builder).build(), path="x.so")
    return ev, linkage, {finding.rule_id for finding in apply_rules(RULESET, wheel, linkage)}


# --- the three shapes that lost evidence ------------------------------------


def test_a_named_crate_survives_a_flood_of_earlier_names() -> None:
    """The worst of the three: the record read clean, with nothing recorded at all.

    `find_rust_crates` sorted by name and cut at 128, and every crypto crate the
    ruleset names sits in the o-to-s range, so a Rust wheel carrying three hundred
    crates dropped `ring` behind a hundred and twenty-eight `anyhow`-class names that
    fire nothing.
    """
    limit = PATTERNS.limits.max_rust_crates_per_binary
    flood = b"".join(_cargo(f"aaa{n:04d}", "1.0.0") for n in range(limit + 2))

    _, _, alone = _scan(rodata=_cargo("ring", "0.17.8"))
    ev, _, crowded = _scan(rodata=flood + _cargo("ring", "0.17.8"))

    assert "ring" in {crate.name for crate in ev.rust_crates}
    assert len(ev.rust_crates) == limit, "the cap must still bound the record"
    assert crowded == alone


def test_a_string_group_survives_a_flood_of_an_earlier_group() -> None:
    """`openssl_banner` is tenth of thirteen group names, and the cap read the alphabet."""
    limit = PATTERNS.limits.max_strings_per_binary
    flood = b"".join(b"mbedtls_ssl_setup_%04d\x00" % n for n in range(limit + 6))

    _, alone, _ = _scan(rodata=BANNER)
    ev, crowded, _ = _scan(rodata=flood + BANNER)

    assert alone["openssl"] == "static"
    assert crowded["openssl"] == "static", "the banner was crowded out of its own posture"
    assert "openssl_banner" in {match.group for match in ev.matched_strings}
    assert len(ev.matched_strings) == limit


def test_a_symbol_group_survives_a_flood_of_an_earlier_group() -> None:
    """`libsodium` sorts before `openssl`, which is the shape of PyNaCl's extension."""
    limit = PATTERNS.limits.max_symbols_per_binary
    flood = tuple(DynSym(f"crypto_box_seal_{n:04d}", defined=True) for n in range(limit + 6))
    openssl = DynSym("EVP_DigestInit_ex", defined=True)

    _, alone, _ = _scan(dynsyms=(openssl,))
    ev, crowded, _ = _scan(dynsyms=flood + (openssl,))

    assert alone["openssl"] == "static"
    assert crowded["openssl"] == "static"
    assert "openssl" in {match.group for match in ev.matched_symbols}
    assert len(ev.matched_symbols) == limit


def _read(data: bytes, path: str = "x"):
    ev, wheel = _evidence(data, path)
    return ev, resolve_linkage(RULESET, wheel), wheel


def _flooded(reader: str, n: int) -> bytes:
    """One object per reader: `n` defined libsodium names plus one defined OpenSSL one."""
    names = [f"crypto_box_seal_{i:04d}" for i in range(n)] + ["EVP_DigestInit_ex"]
    if reader == "elf":
        return ElfBuilder(dynsyms=tuple(DynSym(x, defined=True) for x in names)).build()
    if reader == "macho":
        return MachOBuilder(
            id_dylib="libfoo.dylib",
            symbols=tuple(MachOSym(f"_{x}", defined=True) for x in names),
        ).build()
    return PEBuilder(
        dll_name="_ext.pyd",
        imports=(PEImport("python311.dll", names=("Py_Initialize",)),),
        exports=tuple(PEExport(x) for x in names),
    ).build()


@pytest.mark.parametrize("reader", ["elf", "macho", "pe"])
def test_every_reader_caps_symbols_a_group_at_a_time(reader) -> None:
    """Three readers cap symbols and each one is its own chance to cut blind.

    Written against all three because the ELF-only version of this left Mach-O and PE
    free to go back to a plain slice with the suite staying green.
    """
    limit = PATTERNS.limits.max_symbols_per_binary
    ev, linkage, _ = _read(_flooded(reader, limit + 6))
    assert "openssl" in {match.group for match in ev.matched_symbols}, reader
    assert linkage["openssl"] == "static", reader
    assert len(ev.matched_symbols) <= limit, reader
    assert ev.symbols_truncated is True, reader


def _one_defined_behind_many_imported(reader: str, n: int) -> bytes:
    """`n` imported `EVP_aaa_*` names plus one defined `EVP_zzz_*`, per reader."""
    imported = [f"EVP_aaa_{i:04d}" for i in range(n)]
    defined = "EVP_zzz_defined"
    if reader == "elf":
        return ElfBuilder(
            dynsyms=tuple(DynSym(x, defined=False) for x in imported)
            + (DynSym(defined, defined=True),)
        ).build()
    if reader == "macho":
        return MachOBuilder(
            id_dylib="libfoo.dylib",
            symbols=tuple(MachOSym(f"_{x}", defined=False) for x in imported)
            + (MachOSym(f"_{defined}", defined=True),),
        ).build()
    return PEBuilder(
        dll_name="_ext.pyd",
        imports=(PEImport("libcrypto-x.dll", names=tuple(imported)),),
        exports=(PEExport(defined),),
    ).build()


@pytest.mark.parametrize("reader", ["elf", "macho", "pe"])
def test_the_binding_is_part_of_the_key_not_just_the_group(reader) -> None:
    """`linkage` asks for a *defined* symbol, so one imported one does not answer it.

    Keying on the group alone keeps whichever `EVP_*` sorts first, and when that is an
    imported one the defined one goes -- `unknown` where the object is `static`, a
    quieter version of the same bug. Parametrised for the same reason its neighbour is:
    the ELF-only version left Mach-O and PE free to go back to a group-only key with
    the suite staying green.
    """
    limit = PATTERNS.limits.max_symbols_per_binary
    ev, linkage, _ = _read(_one_defined_behind_many_imported(reader, limit + 6))

    bindings = {match.binding for match in ev.matched_symbols if match.group == "openssl"}
    assert bindings == {"imported", "defined"}, reader
    assert linkage["openssl"] == "static", reader


# --- the helper itself ------------------------------------------------------


def _match(group: str, name: str) -> SymbolMatch:
    return SymbolMatch(name=name, group=group, binding="imported")


@pytest.mark.parametrize(
    ("factory", "fields"),
    [
        (lambda **kw: StringMatch(**{"group": "g", "value": "v", **kw}), ("group", "value")),
        (
            lambda **kw: SymbolMatch(**{"name": "n", "group": "g", "binding": "imported", **kw}),
            ("name", "group", "binding"),
        ),
        (lambda **kw: RustCrate(**{"name": "n", "version": "1.0", **kw}), ("name", "version")),
        (
            lambda **kw: ScanError(**{"stage": "binary", "kind": "k", "message": "m", **kw}),
            ("stage", "path", "kind", "message"),
        ),
        (
            lambda **kw: _SkippedEntry(**{"path": "p", "reason": "r", **kw}),
            ("path", "reason"),
        ),
        (
            lambda **kw: _SymlinkEntry(**{"path": "p", "target": "t", **kw}),
            ("path", "target"),
        ),
    ],
)
def test_a_sort_key_separates_any_two_records_that_differ(factory, fields) -> None:
    """What the whole cap rests on, and it is not obvious from reading `caps.py`.

    `sorted` is stable, so two items whose `sort_key` ties keep the order they arrived
    in -- and they arrive out of a `set`, whose order is not stable across runs. A
    `sort_key` that skipped a field would therefore make the record depend on the hash
    seed, which is the determinism this tool promises. `SbomComponent` already carries
    this reasoning in a comment; these six carry it in a test.
    """
    base = factory()
    for field in fields:
        other = factory(**{field: "zzz"})
        assert other != base, field
        assert other.sort_key() != base.sort_key(), field


def test_the_cap_still_bounds_and_still_reports_truncation() -> None:
    kept, truncated = cap([_match("a", f"n{i:04d}") for i in range(200)], 64)
    assert len(kept) == 64 and truncated is True


def test_nothing_is_dropped_when_everything_fits() -> None:
    items = [_match("a", "one"), _match("b", "two")]
    kept, truncated = cap(items, 64)
    assert set(kept) == set(items) and truncated is False


def test_the_result_is_sorted_however_the_input_arrived() -> None:
    """Determinism is the point: a record must not depend on extractor scan order."""
    items = [_match("z", "n"), _match("a", "n"), _match("m", "n")]
    forwards, _ = cap(items, 2)
    backwards, _ = cap(items[::-1], 2)
    assert forwards == backwards
    assert [m.group for m in forwards] == ["a", "m"]


def test_more_keys_than_room_keeps_the_lowest_sorting_ones() -> None:
    """Arbitrary, but no more so than the cut it replaces, and at least it is stable."""
    items = [_match(chr(ord("a") + n), "n") for n in range(10)]
    kept, truncated = cap(items, 3)
    assert [m.group for m in kept] == ["a", "b", "c"] and truncated is True


@pytest.mark.parametrize("limit", [0, 1])
def test_a_tiny_limit_is_honoured_rather_than_overrun(limit) -> None:
    """The representatives pass must not push past the limit it is filling."""
    items = [_match("a", "x"), _match("b", "y"), _match("c", "z")]
    kept, truncated = cap(items, limit)
    assert len(kept) == limit and truncated is True


def test_a_pinned_item_is_kept_ahead_of_an_unpinned_one() -> None:
    """The crate case: an inventory entry must not take the room a claimed one needs."""
    claimed = RustCrate(name="ring", version="0.17.8")
    noise = [RustCrate(name=f"aaa{n:04d}", version="1.0.0") for n in range(200)]
    kept, truncated = cap(noise + [claimed], 64, pin=lambda c: c.name == "ring")
    assert claimed in kept and len(kept) == 64 and truncated is True


def test_one_pinned_name_cannot_eat_the_budget_with_its_versions() -> None:
    """The finding both reviews made: the pinned pass is keyed, not a plain prefix."""
    many = [RustCrate(name="openssl", version=f"3.0.{n}") for n in range(200)]
    ring = RustCrate(name="ring", version="0.17.8")
    claimed = {"openssl", "ring"}
    kept, _ = cap(many + [ring], 64, pin=lambda c: c.name in claimed)
    assert ring in kept
    assert {c.name for c in kept} >= claimed


def test_a_pinned_leftover_fills_the_last_slot_before_an_unpinned_one() -> None:
    """The fill-phase half of pin priority, not just the representative-pass half:
    once every group has its one representative, whatever pinned items are still
    left over must still be offered the remaining room before an unpinned leftover
    is. A version of `cap` that scanned pinned and unpinned leftovers in the wrong
    order passes every other test in this file but fails this one -- confirmed by
    swapping the fill passes' order and watching this assertion, and only this one,
    flip."""
    claimed = RustCrate(name="ring", version="0.17.8")
    ring_extra = RustCrate(name="ring", version="0.17.9")
    other_rep = RustCrate(name="other", version="1.0.0")
    other_extra = RustCrate(name="other", version="1.0.1")
    kept, truncated = cap(
        [claimed, ring_extra, other_rep, other_extra], 3, pin=lambda c: c.name == "ring"
    )
    assert truncated is True
    assert set(kept) == {claimed, ring_extra, other_rep}
