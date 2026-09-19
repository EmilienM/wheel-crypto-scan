"""Behaviour of `binfmt.macho.read_macho`.

Mach-O is read for its load commands and its `LC_SYMTAB`, which is what gives a Mach-O
object the same imported-versus-defined split ELF gets. These tests hold it to that,
and to the two cases where `partial_analysis` has to survive: a symbol table that could
not be read in full, and a slice of a fat binary that could not be read.
"""

from __future__ import annotations

import dataclasses
import io
import struct

import pytest
from helpers.binfmt import MachOBuilder, MachOSym, build_fat
from wheel_crypto_scan import evidence
from wheel_crypto_scan.binfmt.macho import read_macho
from wheel_crypto_scan.errors import MACHO_PARSE_ERROR
from wheel_crypto_scan.ruleset import load_ruleset

PATTERNS = load_ruleset().compile_patterns().binary

# Darwin's C ABI spells every C symbol with a leading underscore, so a fixture that
# writes the bare name is not a fixture of anything real.
IMPORTED_OPENSSL = MachOSym("_EVP_DigestInit_ex", defined=False)
DEFINED_OPENSSL = MachOSym("_EVP_DigestInit_ex", defined=True)


def _read(data: bytes, path: str = "libfoo.dylib", *, vendored: bool = False):
    return read_macho(io.BytesIO(data), path, PATTERNS, vendored=vendored)


class _SeekLog(io.BytesIO):
    """A stream that remembers where it was asked to seek backwards from, and to.

    Backwards is the direction that costs: `wheelfile.SeekableZipMember` serves a short
    one from its retained window and pays a whole fresh decompression pass for a long
    one. A test can only see that as a seek, so this is what it watches.
    """

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.backwards: list[tuple[int, int]] = []

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET and offset < self.tell():
            self.backwards.append((self.tell(), offset))
        return super().seek(offset, whence)


def _symbol(name: str, binding: str, group: str = "openssl") -> evidence.SymbolMatch:
    return evidence.SymbolMatch(name=name, group=group, binding=binding)


def test_id_dylib_and_load_dylib_round_trip() -> None:
    data = MachOBuilder(
        id_dylib="@rpath/libfoo.dylib",
        load_dylibs=("/usr/lib/libcrypto.3.dylib", "/usr/lib/libSystem.B.dylib"),
    ).build()
    ev, errors = _read(data)
    assert errors == ()
    assert ev.soname == "@rpath/libfoo.dylib"
    assert ev.needed == ("/usr/lib/libSystem.B.dylib", "/usr/lib/libcrypto.3.dylib")
    assert ev.format == evidence.FORMAT_MACHO


def test_lc_rpath_is_read() -> None:
    data = MachOBuilder(id_dylib="libfoo.dylib", rpaths=("@loader_path/../lib",)).build()
    ev, errors = _read(data)
    assert errors == ()
    assert ev.rpath == ("@loader_path/../lib",)


def test_64_bit_little_endian() -> None:
    data = MachOBuilder(is64=True, big_endian=False, id_dylib="libfoo.dylib").build()
    ev, errors = _read(data)
    assert errors == ()
    assert ev.bits == 64
    assert ev.endian == "little"
    assert ev.machine == "CPU_TYPE_X86_64"


def test_32_bit_big_endian() -> None:
    data = MachOBuilder(is64=False, big_endian=True, id_dylib="libbar.dylib").build()
    ev, errors = _read(data)
    assert errors == ()
    assert ev.bits == 32
    assert ev.endian == "big"
    assert ev.soname == "libbar.dylib"


def test_fat_binary_takes_its_architecture_fields_from_the_first_slice() -> None:
    """`machine`, `bits` and `endian` describe one architecture and cannot describe two."""
    slice_a = MachOBuilder(id_dylib="libfoo.dylib").build()
    slice_b = MachOBuilder(is64=False, big_endian=True, id_dylib="libbar.dylib").build()
    fat = build_fat([slice_a, slice_b])
    ev, errors = _read(fat, path="fat.dylib")
    assert errors == ()
    assert ev.soname == "libfoo.dylib"
    assert ev.bits == 64
    assert ev.endian == "little"
    assert ev.machine == "CPU_TYPE_X86_64"


def test_always_extracts_strings() -> None:
    banner = b"OpenSSL 3.0.14 4 Jun 2024"
    data = MachOBuilder(id_dylib="libfoo.dylib").build() + banner
    ev, errors = _read(data)
    assert errors == ()
    assert ev.matched_strings == (
        evidence.StringMatch(group="openssl_banner", value=banner.decode("ascii")),
    )


def test_vendored_flag_passes_through() -> None:
    data = MachOBuilder(id_dylib="libfoo.dylib").build()
    ev, _ = _read(data, vendored=True)
    assert ev.vendored_path is True


def test_truncated_object_does_not_raise() -> None:
    data = MachOBuilder(id_dylib="libfoo.dylib").build()
    ev, errors = _read(data[:10], path="trunc.dylib")
    assert ev.format == evidence.FORMAT_MACHO
    assert ev.partial_analysis is True
    assert len(errors) == 1
    assert errors[0].kind == MACHO_PARSE_ERROR
    assert errors[0].path == "trunc.dylib"


def test_garbage_input_does_not_raise() -> None:
    ev, errors = _read(b"garbage bytes, not a mach-o object at all" * 2, path="garbage.dylib")
    assert ev.format == evidence.FORMAT_MACHO
    assert len(errors) == 1
    assert errors[0].kind == MACHO_PARSE_ERROR


def test_empty_input_does_not_raise() -> None:
    ev, errors = _read(b"")
    assert ev.matched_strings == ()
    assert len(errors) == 1
    assert errors[0].kind == MACHO_PARSE_ERROR


def test_reading_the_same_bytes_twice_is_equal() -> None:
    data = MachOBuilder(
        id_dylib="libfoo.dylib",
        load_dylibs=("/usr/lib/libcrypto.3.dylib",),
        rpaths=("@loader_path/../lib",),
        symbols=(IMPORTED_OPENSSL, MachOSym("_blake2b_init", defined=True)),
    ).build()
    first, first_errors = _read(data)
    second, second_errors = _read(data)
    assert first == second
    assert first_errors == second_errors


# --- the imported/defined split ----------------------------------------------


def test_an_imported_symbol_is_told_apart_from_a_defined_one() -> None:
    """The distinction the whole tool turns on, now drawable on macOS."""
    calls_out = MachOBuilder(id_dylib="libfoo.dylib", symbols=(IMPORTED_OPENSSL,)).build()
    carries_it = MachOBuilder(id_dylib="libfoo.dylib", symbols=(DEFINED_OPENSSL,)).build()

    imported, errors = _read(calls_out)
    assert errors == ()
    assert imported.matched_symbols == (_symbol("EVP_DigestInit_ex", evidence.BINDING_IMPORTED),)
    assert imported.symtab_count == 1
    assert imported.partial_analysis is False

    defined, errors = _read(carries_it)
    assert errors == ()
    assert defined.matched_symbols == (_symbol("EVP_DigestInit_ex", evidence.BINDING_DEFINED),)


def test_darwins_leading_underscore_is_stripped() -> None:
    """Otherwise a ruleset written against `EVP_` matches nothing on macOS at all."""
    data = MachOBuilder(id_dylib="libfoo.dylib", symbols=(IMPORTED_OPENSSL,)).build()
    ev, _ = _read(data)
    assert [match.name for match in ev.matched_symbols] == ["EVP_DigestInit_ex"]


def test_symbols_are_read_in_both_widths_and_byte_orders() -> None:
    for is64 in (True, False):
        for big_endian in (True, False):
            data = MachOBuilder(
                is64=is64,
                big_endian=big_endian,
                id_dylib="libfoo.dylib",
                symbols=(IMPORTED_OPENSSL, MachOSym("_blake2b_init", defined=True)),
            ).build()
            ev, errors = _read(data)
            assert errors == (), (is64, big_endian)
            assert ev.matched_symbols == (
                _symbol("blake2b_init", evidence.BINDING_DEFINED, group="blake"),
                _symbol("EVP_DigestInit_ex", evidence.BINDING_IMPORTED),
            ), (is64, big_endian)
            assert ev.partial_analysis is False, (is64, big_endian)


def test_debug_entries_are_not_read_as_definitions() -> None:
    """An N_STAB entry is a source file or a line number, not a symbol.

    Its N_TYPE bits are unrelated to a section index, so reading one anyway would say
    this object defines the code it names.
    """
    data = MachOBuilder(
        id_dylib="libfoo.dylib",
        symbols=(MachOSym("_EVP_DigestInit_ex", defined=True, stab=True),),
    ).build()
    ev, errors = _read(data)
    assert ev.matched_symbols == ()
    assert ev.symtab_count == 1  # it was read, and then skipped on purpose
    # And a crypto-sounding debug name is still not a symbol this object declares, so
    # the table has declared nothing. Asserted on *this* fixture because its name is one
    # the ruleset matches: a guard that only fires on a name nobody would choose is not
    # a guard.
    #
    # It reports as an undeclared name rather than an empty table, which is the more
    # accurate of the two: the name is in the string table and no entry claimed it.
    assert ev.partial_analysis is True
    assert [e.message for e in errors] == [
        "mach-o symbol table declares fewer entries than it has names"
    ]


def test_a_table_of_nothing_but_debug_records_has_declared_nothing() -> None:
    """The fourth cheap way to look clean, alongside the three `complete` already names.

    A debug record's name is readable, so it used to count toward "we read every name
    here". But it is not a symbol the object declares, so a table holding nothing else
    has declared nothing and we have checked nothing. One crafted entry was the whole
    difference between `OPAQUE` and a clean verdict on an object that told us nothing.
    """
    stabs_only = MachOBuilder(
        id_dylib="libfoo.dylib",
        symbols=(MachOSym("/src/foo.c", defined=True, stab=True),),
    ).build()
    ev, errors = _read(stabs_only)
    assert ev.partial_analysis is True
    assert list(ev.partial_reasons) == ["macho_symtab_incomplete"]
    assert [e.message for e in errors] == [
        "mach-o symbol table declares entries but names no symbol"
    ]
    # `symtab_count` still counts the row: `SCHEMA.md` defines it as `LC_SYMTAB`
    # entries, and a debug record is one. `is_opaque` therefore still reads false, and
    # that is fine -- what closes the hole is the partial flag above, which fires a rule
    # whose verdict is `OPAQUE` regardless.
    assert ev.symtab_count == 1
    assert ev.is_opaque is False


def test_a_debug_record_beside_real_symbols_changes_nothing() -> None:
    """The common case: an unstripped dylib carries a debug map and its symbols."""
    data = MachOBuilder(
        id_dylib="libfoo.dylib",
        symbols=(
            MachOSym("/src/foo.c", defined=True, stab=True),
            MachOSym("_PyInit__ext", defined=True),
        ),
    ).build()
    ev, errors = _read(data)
    assert errors == ()
    assert ev.partial_analysis is False
    assert ev.symtab_count == 2
    assert ev.is_opaque is False


def test_only_symbols_the_ruleset_claims_are_recorded() -> None:
    data = MachOBuilder(
        id_dylib="libfoo.dylib",
        symbols=(IMPORTED_OPENSSL, MachOSym("_ordinary_helper", defined=True)),
    ).build()
    ev, _ = _read(data)
    assert ev.matched_symbols == (_symbol("EVP_DigestInit_ex", evidence.BINDING_IMPORTED),)
    assert ev.symtab_count == 2


def test_a_symbol_name_that_is_not_ascii_is_sanitised() -> None:
    """The record is ASCII-only, so a corrupt string table cannot smuggle bytes into it."""
    data = MachOBuilder(
        id_dylib="libfoo.dylib",
        symbols=(MachOSym("_EVP_Test\udc80Name", defined=True),),
    ).build()
    ev, errors = _read(data)
    assert errors == ()
    assert ev.matched_symbols == (_symbol("EVP_TestName", evidence.BINDING_DEFINED),)


def test_the_symbol_limit_is_applied_and_flagged() -> None:
    limit = PATTERNS.limits.max_symbols_per_binary
    symbols = tuple(MachOSym(f"_EVP_Sym{index:03d}", defined=False) for index in range(limit + 6))
    data = MachOBuilder(id_dylib="libfoo.dylib", symbols=symbols).build()
    ev, errors = _read(data)
    assert errors == ()
    assert ev.symbols_truncated is True
    assert len(ev.matched_symbols) == limit
    # Capped after sorting, so which ones survive is the same on every run.
    assert [match.name for match in ev.matched_symbols] == [
        f"EVP_Sym{index:03d}" for index in range(limit)
    ]


# --- fat binaries -------------------------------------------------------------


def test_fat_symbol_offsets_are_relative_to_the_slice() -> None:
    """`symoff` counts from the start of the slice, not the start of the file.

    Dropping the slice offset reads 48 bytes short of the table and comes back with
    nothing, which is why this asserts the symbols rather than merely the count.
    """
    thin = MachOBuilder(
        id_dylib="libfoo.dylib",
        load_dylibs=("/usr/lib/libcrypto.3.dylib",),
        symbols=(IMPORTED_OPENSSL, MachOSym("_EVP_EncryptInit_ex", defined=False)),
    ).build()
    fat = build_fat([thin, MachOBuilder(is64=False, big_endian=True, id_dylib="b.dylib").build()])

    from_thin, _ = _read(thin)
    from_fat, errors = _read(fat, path="fat.dylib")
    assert errors == ()
    assert from_fat.matched_symbols == (
        _symbol("EVP_DigestInit_ex", evidence.BINDING_IMPORTED),
        _symbol("EVP_EncryptInit_ex", evidence.BINDING_IMPORTED),
    )
    assert from_fat.matched_symbols == from_thin.matched_symbols
    assert from_fat.symtab_count == 2


def test_a_fat_binary_whose_every_slice_read_cleanly_is_not_partial() -> None:
    """Most macOS wheels are universal2, so this is the common case, not the exotic one.

    While only the first slice was read, every fat object stayed partial, and a
    universal2 wheel with no crypto in it came out `OPAQUE` rather than
    `NO_CRYPTO_DETECTED`. That put every crypto-free universal2 wheel in the index on
    the README's `OPAQUE` triage list.
    """
    slice_a = MachOBuilder(id_dylib="libfoo.dylib", symbols=(IMPORTED_OPENSSL,)).build()
    slice_b = MachOBuilder(
        is64=False, big_endian=True, id_dylib="libfoo.dylib", symbols=(IMPORTED_OPENSSL,)
    ).build()
    ev, errors = _read(build_fat([slice_a, slice_b]), path="fat.dylib")
    assert errors == ()
    assert ev.partial_analysis is False


def test_a_symbol_defined_only_in_the_second_slice_is_still_found() -> None:
    """The whole point of walking every slice: arm64 evidence an x86_64 read misses."""
    slice_a = MachOBuilder(id_dylib="libfoo.dylib", symbols=(IMPORTED_OPENSSL,)).build()
    slice_b = MachOBuilder(
        is64=False,
        big_endian=True,
        id_dylib="libfoo.dylib",
        symbols=(MachOSym("_EVP_EncryptInit_ex", defined=True),),
    ).build()
    ev, errors = _read(build_fat([slice_a, slice_b]), path="fat.dylib")
    assert errors == ()
    assert [(m.name, m.binding) for m in ev.matched_symbols] == [
        ("EVP_DigestInit_ex", "imported"),
        ("EVP_EncryptInit_ex", "defined"),
    ]
    # Summed over the slices, not taken from whichever one was read first.
    assert ev.symtab_count == 2


def test_an_unparseable_slice_keeps_the_object_partial() -> None:
    """An architecture we could not read is unknown, not absent."""
    slice_a = MachOBuilder(id_dylib="libfoo.dylib", symbols=(IMPORTED_OPENSSL,)).build()
    ev, errors = _read(build_fat([slice_a, b"\x00" * 64]), path="fat.dylib")
    # The reason survives per slice rather than collapsing into one generic message.
    assert [e.message for e in errors] == ["not a recognisable Mach-O object"]
    assert ev.partial_analysis is True
    # What the readable slice said still survives.
    assert [m.name for m in ev.matched_symbols] == ["EVP_DigestInit_ex"]


def test_load_dylibs_merge_across_slices() -> None:
    """A dependency named by one architecture is a dependency of the object."""
    slice_a = MachOBuilder(
        id_dylib="libfoo.dylib", load_dylibs=("libcrypto.3.dylib",), symbols=(IMPORTED_OPENSSL,)
    ).build()
    slice_b = MachOBuilder(
        is64=False,
        big_endian=True,
        id_dylib="libfoo.dylib",
        load_dylibs=("libssl.3.dylib",),
        rpaths=("@loader_path/../lib",),
        symbols=(IMPORTED_OPENSSL,),
    ).build()
    ev, errors = _read(build_fat([slice_a, slice_b]), path="fat.dylib")
    assert errors == ()
    assert ev.needed == ("libcrypto.3.dylib", "libssl.3.dylib")
    assert ev.rpath == ("@loader_path/../lib",)


# --- when the symbol table is missing or lying --------------------------------


def test_an_object_without_a_symbol_table_stays_partial() -> None:
    data = MachOBuilder(id_dylib="libfoo.dylib").build()
    ev, errors = _read(data)
    assert errors == ()  # an absent LC_SYMTAB is not a failure, only a limit
    assert ev.matched_symbols == ()
    assert ev.symtab_count == 0
    assert ev.partial_analysis is True


def test_an_empty_symbol_table_has_declared_nothing() -> None:
    """`nsyms = 0` used to be exempt from `complete`, and that was the hole.

    A table declaring nothing tells us exactly what an absent `LC_SYMTAB` tells us, and
    an absent one has always been incomplete. The exemption let an object carry rows
    full of crypto imports, declare none of them, and read clean.

    No error, though: like an absent table, declaring nothing is what `strip` leaves
    behind rather than something that went wrong.
    """
    data = MachOBuilder(id_dylib="libfoo.dylib", with_symtab=True).build()
    ev, errors = _read(data)
    assert errors == ()
    assert ev.symtab_count == 0
    assert ev.partial_analysis is True
    assert list(ev.partial_reasons) == ["macho_symtab_incomplete"]


def test_an_object_with_no_symbol_names_to_offer_is_recorded_as_stripped() -> None:
    """`stripped` is "no symbol table worth the name", which Mach-O can say two ways.

    It is read off the table rather than off `nsyms`, which is the point of the two
    cases below it: a count of zero over rows holding crypto names is a table we could
    not use, and "we could not use it" is not "this object has no symbols". `stripped`
    is recorded rather than treated as a finding, so a cause must not be able to set it.
    """
    no_command = MachOBuilder(id_dylib="libfoo.dylib").build()
    no_entries = MachOBuilder(id_dylib="libfoo.dylib", with_symtab=True).build()
    carries_symbols = MachOBuilder(id_dylib="libfoo.dylib", symbols=(IMPORTED_OPENSSL,)).build()
    only_debug = MachOBuilder(
        id_dylib="libfoo.dylib", symbols=(MachOSym("/src/foo.c", defined=True, stab=True),)
    ).build()
    undeclared = MachOBuilder(
        id_dylib="libfoo.dylib", symbols=(IMPORTED_OPENSSL,), declared_nsyms=0
    ).build()

    assert _read(no_command)[0].stripped is True
    assert _read(no_entries)[0].stripped is True
    assert _read(carries_symbols)[0].stripped is False
    # Both of these declare a table we could not take at its word.
    assert _read(only_debug)[0].stripped is False
    assert _read(undeclared)[0].stripped is False


def test_a_symbol_table_that_claims_more_than_exists_is_an_error() -> None:
    """A 32-bit nsyms can promise 64 GiB of symbols out of a few hundred bytes."""
    data = MachOBuilder(
        id_dylib="libfoo.dylib",
        load_dylibs=("/usr/lib/libcrypto.3.dylib",),
        symbols=(IMPORTED_OPENSSL,),
        declared_nsyms=0xFFFFFFFF,
    ).build()
    ev, errors = _read(data, path="liar.dylib")
    assert [error.kind for error in errors] == [MACHO_PARSE_ERROR]
    assert errors[0].path == "liar.dylib"
    # The evidence that was readable survives the entry that was not.
    assert ev.needed == ("/usr/lib/libcrypto.3.dylib",)
    assert ev.matched_symbols == (_symbol("EVP_DigestInit_ex", evidence.BINDING_IMPORTED),)
    assert ev.partial_analysis is True


def test_a_string_table_that_claims_more_than_exists_is_an_error() -> None:
    data = MachOBuilder(
        id_dylib="libfoo.dylib", symbols=(IMPORTED_OPENSSL,), declared_strsize=1 << 30
    ).build()
    ev, errors = _read(data)
    assert [error.kind for error in errors] == [MACHO_PARSE_ERROR]
    assert ev.partial_analysis is True


def test_a_symbol_table_pointed_outside_the_object_yields_nothing() -> None:
    data = MachOBuilder(
        id_dylib="libfoo.dylib", symbols=(IMPORTED_OPENSSL,), declared_symoff=1 << 30
    ).build()
    ev, errors = _read(data)
    assert [error.kind for error in errors] == [MACHO_PARSE_ERROR]
    assert ev.matched_symbols == ()
    assert ev.symtab_count == 0
    assert ev.partial_analysis is True


def _hiding_names() -> list[tuple[str, MachOBuilder]]:
    """Every shape of "the entries are there, but no name can be resolved from them".

    All six carry two real nlist entries naming OpenSSL. If any of them comes back as a
    complete read, the record says "we read every name and none of them was crypto"
    about an object whose names we never read, which is the one thing this reader must
    never say. Each case is a one-field edit to an object that reads perfectly.
    """
    honest = MachOBuilder(
        id_dylib="libfoo.dylib",
        symbols=(IMPORTED_OPENSSL, MachOSym("_EVP_EncryptInit_ex", defined=False)),
    )
    symoff, _stroff = honest.table_offsets()
    hidden_index = 1 << 20  # past the end of any string table this object could hold
    return [
        ("strsize = 0", dataclasses.replace(honest, declared_strsize=0)),
        ("strsize = 1", dataclasses.replace(honest, declared_strsize=1)),
        (
            "every n_strx = 0",
            dataclasses.replace(
                honest,
                symbols=tuple(dataclasses.replace(sym, strx=0) for sym in honest.symbols),
            ),
        ),
        (
            "every n_strx past the table",
            dataclasses.replace(
                honest,
                symbols=tuple(
                    dataclasses.replace(sym, strx=hidden_index) for sym in honest.symbols
                ),
            ),
        ),
        ("stroff inside the nlist table", dataclasses.replace(honest, declared_stroff=symoff)),
        ("symoff = 0, nsyms = 5", dataclasses.replace(honest, declared_symoff=0, declared_nsyms=5)),
    ]


_HIDING_NAMES = _hiding_names()


@pytest.mark.parametrize(
    ("label", "builder"), _HIDING_NAMES, ids=[label for label, _ in _HIDING_NAMES]
)
def test_an_object_whose_names_cannot_be_read_is_never_a_complete_read(
    label: str, builder: MachOBuilder
) -> None:
    ev, errors = _read(builder.build(), path="hidden.dylib")
    assert ev.matched_symbols == (), label
    assert ev.partial_analysis is True, label
    assert [error.kind for error in errors] == [MACHO_PARSE_ERROR], label


def test_the_same_object_without_the_edit_is_a_complete_read() -> None:
    """The control for the six cases above: nothing about the shape is inherently partial."""
    honest = MachOBuilder(
        id_dylib="libfoo.dylib",
        symbols=(IMPORTED_OPENSSL, MachOSym("_EVP_EncryptInit_ex", defined=False)),
    )
    ev, errors = _read(honest.build())
    assert errors == ()
    assert ev.partial_analysis is False
    assert [match.name for match in ev.matched_symbols] == [
        "EVP_DigestInit_ex",
        "EVP_EncryptInit_ex",
    ]


def test_a_string_table_pointed_outside_the_object_is_an_error() -> None:
    data = MachOBuilder(
        id_dylib="libfoo.dylib", symbols=(IMPORTED_OPENSSL,), declared_stroff=1 << 30
    ).build()
    ev, errors = _read(data)
    assert [error.kind for error in errors] == [MACHO_PARSE_ERROR]
    assert ev.matched_symbols == ()
    assert ev.partial_analysis is True


def test_a_string_table_running_off_the_end_of_the_object_does_not_raise() -> None:
    """The tables are written nlist first, so the last six bytes are the string table's.

    What survives is a name cut short, and a name cut short is not a name this object
    carries. Recording `EVP_DigestIn` used to look like the safe direction -- noisy,
    but unable to hide anything -- and it is not safe: the record then asserts a symbol
    that does not exist, in the field the whole tool turns on, and asserts it as read.
    A run the table never closes is a name we could not resolve, which is what the flag
    and the error below say instead.
    """
    data = MachOBuilder(id_dylib="libfoo.dylib", symbols=(IMPORTED_OPENSSL,)).build()
    ev, errors = _read(data[:-6], path="short.dylib")
    assert [error.kind for error in errors] == [MACHO_PARSE_ERROR]
    assert ev.matched_symbols == ()
    assert ev.partial_analysis is True


# --- reading the tables without seeking backwards -----------------------------


def test_a_table_straddling_the_end_of_the_string_read_is_not_re_read_from_the_start() -> None:
    """The prefix already in hand is used, and the rest is read forward from where it ends.

    Seeking back to the start of the table instead would re-read the part we are already
    holding, and through a zip member every backwards seek past the retained window costs
    a fresh decompression of everything before it. That is the cost this reader exists to
    avoid, so it is pinned rather than left to the next refactor.
    """
    builder = MachOBuilder(
        id_dylib="libfoo.dylib",
        symbols=(IMPORTED_OPENSSL, MachOSym("_EVP_EncryptInit_ex", defined=False)),
    )
    symoff, _stroff = builder.table_offsets()
    stream = _SeekLog(builder.build())
    # Stop the string-extraction read inside the first nlist entry, so the symbol table
    # is half held in memory and half still in the stream.
    ev, errors = read_macho(
        stream, "straddle.dylib", PATTERNS, vendored=False, max_strings_bytes=symoff + 8
    )

    assert errors == ()
    assert ev.partial_analysis is False
    assert ev.matched_symbols == (
        _symbol("EVP_DigestInit_ex", evidence.BINDING_IMPORTED),
        _symbol("EVP_EncryptInit_ex", evidence.BINDING_IMPORTED),
    )
    # Seeking back over the header to sniff it is free; seeking back into the tables is
    # the regression.
    assert [seek for seek in stream.backwards if seek[1] >= symoff] == []


def test_an_escaped_symbol_name_keeps_its_underscore() -> None:
    """`_strip_abi_prefix` runs before `sanitize`, and the order is load-bearing.

    A leading `\\x01` means "the linker added no ABI prefix". Sanitising first would
    drop the escape and invite the underscore that follows to be stripped as one,
    turning a symbol that is not `EVP_DigestInit_ex` into a *defined* match for it:
    "this wheel carries its own OpenSSL", out of nothing.
    """
    data = MachOBuilder(
        id_dylib="libfoo.dylib",
        symbols=(MachOSym("\x01_EVP_DigestInit_ex", defined=True),),
    ).build()
    ev, _ = _read(data, path="odd.dylib")
    assert ev.matched_symbols == ()


def test_a_callers_max_strings_bytes_is_reported_as_truncation() -> None:
    banner = b"OpenSSL 3.0.14 4 Jun 2024"
    stream = io.BytesIO(MachOBuilder(id_dylib="libfoo.dylib").build() + banner)
    ev, _ = read_macho(stream, "libfoo.dylib", PATTERNS, vendored=False, max_strings_bytes=8)
    assert ev.strings_truncated is True


# --- a header that does not parse costs the header, not the strings ----------

BANNER = b"OpenSSL 3.0.14 4 Jun 2024"
CARGO = b"/root/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ring-0.17.8/src/lib.rs"


def test_unreadable_fat_header_keeps_the_strings_it_already_found() -> None:
    """A fat header too short to walk still leaves the object's banner readable."""
    data = b"\xca\xfe\xba\xbe" + BANNER + b"\x00" + CARGO + b"\x00"
    ev, errors = _read(data, path="fat.dylib")
    assert [e.kind for e in errors] == [MACHO_PARSE_ERROR]
    assert ev.format == evidence.FORMAT_MACHO
    assert ev.partial_analysis is True
    assert [m.value for m in ev.matched_strings] == [BANNER.decode()]
    assert [(c.name, c.version) for c in ev.rust_crates] == [("ring", "0.17.8")]


def test_unrecognisable_magic_keeps_the_strings_it_already_found() -> None:
    data = b"\xfe\xed\x00\x00" + BANNER + b"\x00"
    ev, errors = _read(data, path="odd.dylib")
    assert [e.kind for e in errors] == [MACHO_PARSE_ERROR]
    assert ev.partial_analysis is True
    assert [m.value for m in ev.matched_strings] == [BANNER.decode()]


def test_a_fat_binary_with_no_readable_slice_keeps_its_strings() -> None:
    """Every architecture placed outside the object, and the banner still survives."""
    header = struct.pack(">II", 0xCAFEBABE, 1) + struct.pack(">iiIII", 7, 0, 1 << 30, 16, 0)
    ev, errors = _read(header + BANNER + b"\x00", path="fat.dylib")
    assert [e.message for e in errors] == ["no readable slice in fat binary"]
    assert ev.partial_analysis is True
    assert [m.value for m in ev.matched_strings] == [BANNER.decode()]


def test_the_failure_path_still_honours_max_strings_bytes() -> None:
    """The fallback is bounded by the caller's limit, not by the object's size."""
    stream = io.BytesIO(b"\xca\xfe\xba\xbe" + BANNER + b"\x00")
    ev, _ = read_macho(stream, "fat.dylib", PATTERNS, vendored=False, max_strings_bytes=8)
    assert ev.partial_analysis is True
    assert ev.strings_truncated is True
    assert ev.matched_strings == ()


def test_go_markers_survive_a_header_that_would_not_parse() -> None:
    """`binfmt.pe` always kept these; the contract says every format does."""
    marker = b"GOEXPERIMENT=boringcrypto\x00_Cfunc__goboringcrypto_DLEAY_version\x00"
    ev, _ = _read(b"\xca\xfe\xba\xbe" + marker, path="fat.dylib")
    assert ev.go is not None
    assert ev.go.boring_crypto is True


def test_truncated_load_commands_keep_the_strings_it_already_found() -> None:
    """Load commands that run off the end cost the load commands, nothing more."""
    full = MachOBuilder(id_dylib="libfoo.dylib", load_dylibs=("libcrypto.3.dylib",)).build()
    # mach_header_64 is magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, ...
    (sizeofcmds,) = struct.unpack_from("<I", full, 20)
    # Keep the header, drop the load commands, and leave the banner where the reader
    # will still find it: the object now promises more commands than it carries.
    data = full[:32] + BANNER + b"\x00"
    assert len(data) - 32 < sizeofcmds
    ev, errors = _read(data, path="chopped.dylib")
    assert [e.kind for e in errors] == [MACHO_PARSE_ERROR]
    assert ev.partial_analysis is True
    assert [m.value for m in ev.matched_strings] == [BANNER.decode()]


def test_unparsed_macho_reports_no_structural_evidence() -> None:
    """Strings survive; nothing else is invented to go with them."""
    ev, _ = _read(b"\xca\xfe\xba\xbe" + BANNER, path="fat.dylib")
    assert ev.needed == ()
    assert ev.soname is None
    assert ev.matched_symbols == ()
    assert ev.machine is None
    assert ev.symtab_count == 0


def test_one_slice_keeping_its_symbols_makes_the_object_not_stripped() -> None:
    """`stripped` is `all(slices)`: an architecture with symbols is symbols the object has."""
    bare = MachOBuilder(is64=False, big_endian=True, id_dylib="libfoo.dylib").build()
    with_syms = MachOBuilder(id_dylib="libfoo.dylib", symbols=(IMPORTED_OPENSSL,)).build()
    ev, _ = _read(build_fat([with_syms, bare]), path="fat.dylib")
    assert ev.stripped is False
    ev, _ = _read(build_fat([bare, bare]), path="fat.dylib")
    assert ev.stripped is True


def test_the_symbol_cap_is_applied_after_the_slices_merge() -> None:
    """Capping per slice would let which symbols survive depend on which slice they were in."""
    limit = PATTERNS.limits.max_symbols_per_binary
    first = tuple(MachOSym(f"_EVP_Digest{i:04d}", defined=False) for i in range(limit))
    second = tuple(MachOSym(f"_EVP_Encrypt{i:04d}", defined=False) for i in range(limit))
    a = MachOBuilder(id_dylib="libfoo.dylib", symbols=first).build()
    b = MachOBuilder(is64=False, big_endian=True, id_dylib="libfoo.dylib", symbols=second).build()

    forward, _ = _read(build_fat([a, b]), path="fat.dylib")
    reverse, _ = _read(build_fat([b, a]), path="fat.dylib")
    assert len(forward.matched_symbols) == limit
    assert forward.symbols_truncated is True
    # Which ones survive is a property of the merged set, not of slice order.
    assert [m.name for m in forward.matched_symbols] == [m.name for m in reverse.matched_symbols]


def test_two_entries_naming_one_slice_describe_one_slice() -> None:
    """A duplicated offset must not count the same symbol table twice."""
    thin = MachOBuilder(id_dylib="libfoo.dylib", symbols=(IMPORTED_OPENSSL,)).build()
    body_at = 8 + 2 * 20
    entry = struct.pack(">iiIII", 7, 0, body_at, len(thin), 0)
    data = struct.pack(">II", 0xCAFEBABE, 2) + entry + entry + thin
    ev, errors = _read(data, path="fat.dylib")
    assert errors == ()
    single, _ = _read(thin, path="thin.dylib")
    assert ev.symtab_count == single.symtab_count
    assert ev.partial_analysis is False


def test_an_over_declared_arch_count_is_reported_rather_than_believed() -> None:
    thin = MachOBuilder(id_dylib="libfoo.dylib", symbols=(IMPORTED_OPENSSL,)).build()
    body_at = 8 + 40 * 20
    entries = b"".join(struct.pack(">iiIII", 7, i, body_at, len(thin), 0) for i in range(40))
    data = struct.pack(">II", 0xCAFEBABE, 40) + entries + thin
    ev, errors = _read(data, path="fat.dylib")
    assert [e.message for e in errors] == [
        "fat header declares more architectures than this reader walks"
    ]
    assert ev.partial_analysis is True


def test_every_unreadable_slice_says_why_it_was_unreadable() -> None:
    """When nothing parses, no reason is dropped for being second."""
    truncated = MachOBuilder(id_dylib="libfoo.dylib").build()[:32]
    ev, errors = _read(build_fat([b"\x00" * 64, truncated]), path="fat.dylib")
    assert [e.message for e in errors] == [
        "mach-o header is truncated",
        "not a recognisable Mach-O object",
    ]
    assert ev.partial_analysis is True


# --- 64-bit universal binaries ------------------------------------------------


def test_a_64_bit_fat_binary_reads_the_same_as_a_32_bit_one() -> None:
    """`FAT_MAGIC_64` changes the arch table and nothing else.

    The magic is one bit from the 32-bit one, which is how an object of this shape gets
    missed: it used to sniff as `unknown` and fall to the strings-only reader, so its
    install name, its dependencies and its imported OpenSSL symbol were all lost.
    """
    slice_a = MachOBuilder(id_dylib="libfoo.dylib", symbols=(IMPORTED_OPENSSL,)).build()
    slice_b = MachOBuilder(
        is64=False,
        big_endian=True,
        id_dylib="libfoo.dylib",
        symbols=(MachOSym("_EVP_EncryptInit_ex", defined=True),),
    ).build()
    narrow, narrow_errors = _read(build_fat([slice_a, slice_b]), path="fat.dylib")
    wide, wide_errors = _read(build_fat([slice_a, slice_b], wide=True), path="fat.dylib")

    assert narrow_errors == () and wide_errors == ()
    assert dataclasses.asdict(wide) == dataclasses.asdict(narrow)
    assert wide.partial_analysis is False
    assert [m.name for m in wide.matched_symbols] == [
        "EVP_DigestInit_ex",
        "EVP_EncryptInit_ex",
    ]


def test_a_64_bit_fat_slice_that_could_not_be_read_stays_partial() -> None:
    slice_a = MachOBuilder(id_dylib="libfoo.dylib", symbols=(IMPORTED_OPENSSL,)).build()
    ev, errors = _read(build_fat([slice_a, b"\x00" * 64], wide=True), path="fat.dylib")
    assert [e.message for e in errors] == ["not a recognisable Mach-O object"]
    assert ev.partial_analysis is True
    assert [m.name for m in ev.matched_symbols] == ["EVP_DigestInit_ex"]


def test_a_64_bit_fat_header_uses_the_wider_arch_entry() -> None:
    """Reading a `fat_arch_64` table at 20 bytes an entry would desynchronise it."""
    thin = MachOBuilder(id_dylib="libfoo.dylib", symbols=(IMPORTED_OPENSSL,)).build()
    wide = build_fat([thin, thin], wide=True)
    narrow = build_fat([thin, thin])
    # 8 bytes of header, then 32 bytes an entry rather than 20.
    assert len(wide) - len(narrow) == 2 * (32 - 20)
    ev, errors = _read(wide, path="fat.dylib")
    assert errors == ()
    assert ev.partial_analysis is False


def test_a_byte_swapped_fat_header_is_defensive_not_supported() -> None:
    """Both `CIGAM` magics sniff as Mach-O and then fail the same way.

    Fat headers are big-endian on disk, so a byte-swapped one is not a thing a real
    toolchain emits. The magics are carried so such an object is recognised and read
    for strings rather than silently classified as some other format, and this pins
    that the 64-bit spelling behaves exactly like the 32-bit one rather than being
    mistaken for a well-formed wide table.
    """
    banner = b"OpenSSL 3.0.14 4 Jun 2024"
    records = []
    for magic in (b"\xbe\xba\xfe\xca", b"\xbf\xba\xfe\xca"):
        ev, errors = _read(magic + b"\x00" * 64 + banner + b"\x00", path="swapped.dylib")
        assert ev.format == evidence.FORMAT_MACHO
        assert ev.partial_analysis is True
        assert [m.value for m in ev.matched_strings] == [banner.decode()]
        records.append((list(ev.partial_reasons), [e.message for e in errors]))
    assert records[0] == records[1]


def test_one_hidden_index_beside_a_readable_symbol_is_still_incomplete() -> None:
    """`not unresolved` in `complete`, which nothing exercised on its own.

    Every other fixture hides *every* name, so `named` being zero already cleared the
    flag and this clause never had to. One entry pointing past the string table is
    enough: the object named something we could not read.
    """
    data = MachOBuilder(
        id_dylib="libfoo.dylib",
        symbols=(
            MachOSym("_PyInit__ext", defined=True),
            MachOSym("_EVP_DigestInit_ex", defined=False, strx=0xFFFF),
        ),
    ).build()
    ev, errors = _read(data)
    assert ev.partial_analysis is True
    assert list(ev.partial_reasons) == ["macho_symtab_incomplete"]
    assert [e.message for e in errors] == ["mach-o symbol table names strings it does not hold"]


# --- the declaration itself can lie ------------------------------------------

_HIDDEN = (
    MachOSym("_EVP_DigestInit_ex", defined=False),
    MachOSym("_SSL_new", defined=False),
)


def test_a_count_of_zero_over_rows_full_of_symbols_is_not_a_clean_read() -> None:
    """Reading what the object declares is not reading what the object carries.

    The rows are there, the string table is there, and `nsyms` says none of it counts.
    Every name is found in the string table and none was looked at, which is the
    difference between "we checked and found nothing" and "we were told not to check".
    """
    data = MachOBuilder(id_dylib="libfoo.dylib", symbols=_HIDDEN, declared_nsyms=0).build()
    ev, errors = _read(data)
    assert ev.partial_analysis is True
    # Both: the format's own cause, and the one a consumer can filter an index on
    # without caring which format told the lie.
    assert list(ev.partial_reasons) == ["macho_symtab_incomplete", "symtab_understates_rows"]
    assert [e.message for e in errors] == [
        "mach-o symbol table declares fewer entries than it has names"
    ]
    assert ev.matched_symbols == ()


def test_a_count_that_stops_short_of_the_rows_is_not_a_clean_read() -> None:
    """The sharper one: it does not use the zero short-circuit.

    Declare one entry over three, put something harmless first, and the two crypto
    imports behind it are never read. `named` is one, nothing is unresolvable, both
    lengths match -- every structural check passes.
    """
    data = MachOBuilder(
        id_dylib="libfoo.dylib",
        symbols=(MachOSym("_PyInit__ext", defined=True),) + _HIDDEN,
        declared_nsyms=1,
    ).build()
    ev, errors = _read(data)
    assert ev.partial_analysis is True
    assert [e.message for e in errors] == [
        "mach-o symbol table declares fewer entries than it has names"
    ]


def test_an_honest_table_costs_nothing_and_stays_complete() -> None:
    """The cross-check must not fire on an object that declared what it carries."""
    data = MachOBuilder(id_dylib="libfoo.dylib", symbols=_HIDDEN).build()
    ev, errors = _read(data)
    assert errors == ()
    assert ev.partial_analysis is False
    assert [m.name for m in ev.matched_symbols] == ["EVP_DigestInit_ex", "SSL_new"]


def test_the_walk_does_not_stop_at_the_first_name_it_recognises() -> None:
    """A declared crypto symbol is a name the locator lands on and nothing is wrong with.

    The walk has to carry on past it. Stopping there reads the whole check as "is the
    first recognisable name accounted for", and any object that honestly declares one
    crypto import can hide as many more as it likes behind it.
    """
    data = MachOBuilder(
        id_dylib="libfoo.dylib",
        symbols=(
            MachOSym("_PyInit__ext", defined=True),
            MachOSym("_EVP_DigestInit_ex", defined=False),
            MachOSym("_SSL_new", defined=False),
        ),
        declared_nsyms=2,
    ).build()
    ev, errors = _read(data)
    assert ev.partial_analysis is True
    assert [e.message for e in errors] == [
        "mach-o symbol table declares fewer entries than it has names"
    ]
    # The one it did declare is still evidence.
    assert [m.name for m in ev.matched_symbols] == ["EVP_DigestInit_ex"]


def test_a_hidden_name_claimed_only_by_an_exact_rule_is_still_found() -> None:
    """The locator has to carry both arms of the matcher, not just the prefix one.

    `SSL_new` is claimed by a group's exact set; no prefix reaches it. Paired with
    `EVP_DigestInit_ex` it proves nothing, because the walk stops at the first hidden
    name and the prefix arm gets there first.
    """
    data = MachOBuilder(
        id_dylib="libfoo.dylib",
        symbols=(MachOSym("_PyInit__ext", defined=True), MachOSym("_SSL_new", defined=False)),
        declared_nsyms=1,
    ).build()
    ev, errors = _read(data)
    assert ev.partial_analysis is True
    assert [e.message for e in errors] == [
        "mach-o symbol table declares fewer entries than it has names"
    ]


def test_a_control_byte_cannot_hide_a_name_from_its_own_matcher() -> None:
    """`sanitize` strips the byte, so the name the matcher is shown is the crypto one.

    A locator reading raw bytes would look straight past `_EV\x81P_DigestInit_ex`, and
    an object would hide a symbol from the check by writing a name this reader itself
    resolves to `EVP_DigestInit_ex`. One stripped byte is the whole cost.
    """
    data = MachOBuilder(
        id_dylib="libfoo.dylib",
        symbols=(
            MachOSym("_PyInit__ext", defined=True),
            MachOSym("_EV\udc81P_DigestInit_ex", defined=False),
        ),
        declared_nsyms=1,
    ).build()
    ev, errors = _read(data)
    assert ev.partial_analysis is True
    assert [e.message for e in errors] == [
        "mach-o symbol table declares fewer entries than it has names"
    ]


def test_a_name_the_ruleset_does_not_claim_is_not_a_hidden_symbol() -> None:
    """The check asks whether a *crypto* name went unread, not whether any name did.

    A string table holding padding, or names of things the ruleset says nothing about,
    is the ordinary case and must not make every object partial.
    """
    data = MachOBuilder(
        id_dylib="libfoo.dylib",
        symbols=(MachOSym("_PyInit__ext", defined=True), MachOSym("_helper", defined=True)),
        declared_nsyms=1,
    ).build()
    ev, errors = _read(data)
    assert errors == ()
    assert ev.partial_analysis is False


def test_a_debug_row_cannot_launder_a_hidden_symbol() -> None:
    """Counting a debug record as read was a way to hide a real one.

    Put the crypto name on a stabs row inside the declared window and the real undefined
    row outside it: the name then looks accounted for, and the cross-check finds nothing
    left over. It is not accounted for -- a debug record's name never reaches the group
    matching -- so it is recorded as read by nothing.
    """
    data = MachOBuilder(
        id_dylib="libfoo.dylib",
        load_dylibs=("/usr/lib/libSystem.B.dylib",),
        symbols=(
            MachOSym("_PyInit__ext", defined=True),
            MachOSym("_EVP_DigestInit_ex", defined=True, stab=True),
            MachOSym("_EVP_DigestInit_ex", defined=False),
        ),
        declared_nsyms=2,
    ).build()
    ev, errors = _read(data)
    assert ev.partial_analysis is True
    assert [e.message for e in errors] == [
        "mach-o symbol table declares fewer entries than it has names"
    ]
    assert ev.matched_symbols == ()


def test_an_alias_target_is_read_rather_than_merely_accounted_for() -> None:
    """`N_INDR` names its target through `n_value`, not through any entry's `n_strx`.

    Without reading it the target is a string nothing appears to reference, and an
    honest object with a renamed or vendored crypto symbol would read as one hiding it.

    Reading it has to mean matching it. The evidence below is the half that proves the
    name went through the matcher rather than into the set of names to stop asking
    about, which is the distinction the next test turns on.
    """
    data = MachOBuilder(
        id_dylib="libfoo.dylib",
        symbols=(MachOSym("_local_alias", defined=True, indirect_to="_EVP_DigestInit_ex"),),
    ).build()
    ev, errors = _read(data)
    assert errors == ()
    assert ev.partial_analysis is False
    # `imported`: an alias resolves to code this object does not carry under that name.
    assert ev.matched_symbols == (_symbol("EVP_DigestInit_ex", evidence.BINDING_IMPORTED),)


def test_an_alias_row_cannot_launder_a_hidden_symbol() -> None:
    """The `N_INDR` spelling of the debug-row trick, and one row is the whole cost.

    Alias a name inside the declared window to the crypto symbol hidden outside it. If
    the target were merely remembered as read, the cross-check would find nothing left
    over in the string table and the object would read clean. It goes through the
    matcher instead, so either the name is evidence or it is unaccounted for -- here it
    is both, because the hidden row is what the alias points at.
    """
    data = MachOBuilder(
        id_dylib="libfoo.dylib",
        load_dylibs=("/usr/lib/libSystem.B.dylib",),
        symbols=(
            MachOSym("_local_alias", defined=True, indirect_to="_EVP_DigestInit_ex"),
            MachOSym("_EVP_DigestInit_ex", defined=False),
        ),
        declared_nsyms=1,
    ).build()
    ev, errors = _read(data)
    assert errors == ()
    assert ev.matched_symbols == (_symbol("EVP_DigestInit_ex", evidence.BINDING_IMPORTED),)
