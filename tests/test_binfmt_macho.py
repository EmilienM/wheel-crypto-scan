"""Behaviour of `binfmt.macho.read_macho`.

Mach-O is read for its load commands and its `LC_SYMTAB`, which is what gives a Mach-O
object the same imported-versus-defined split ELF gets. These tests hold it to that,
and to the two cases where `partial_analysis` has to survive: a symbol table that could
not be read in full, and a fat binary, where only one slice is examined.
"""

from __future__ import annotations

import dataclasses
import io

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


def test_fat_binary_reads_first_parseable_slice() -> None:
    slice_a = MachOBuilder(id_dylib="libfoo.dylib").build()
    slice_b = MachOBuilder(is64=False, big_endian=True, id_dylib="libbar.dylib").build()
    fat = build_fat([slice_a, slice_b])
    ev, errors = _read(fat, path="fat.dylib")
    assert errors == ()
    assert ev.soname == "libfoo.dylib"
    assert ev.bits == 64


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
    assert errors == ()
    assert ev.matched_symbols == ()
    assert ev.symtab_count == 1  # it was read, and then skipped on purpose


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


def test_a_fat_binary_stays_partial_because_only_one_slice_is_read() -> None:
    """The other architectures were never looked at, so they are unknown, not clean."""
    thin = MachOBuilder(id_dylib="libfoo.dylib", symbols=(IMPORTED_OPENSSL,)).build()
    fat = build_fat([thin, MachOBuilder(is64=False, big_endian=True, id_dylib="b.dylib").build()])
    ev, errors = _read(fat, path="fat.dylib")
    assert errors == ()
    assert ev.matched_symbols != ()
    assert ev.partial_analysis is True


# --- when the symbol table is missing or lying --------------------------------


def test_an_object_without_a_symbol_table_stays_partial() -> None:
    data = MachOBuilder(id_dylib="libfoo.dylib").build()
    ev, errors = _read(data)
    assert errors == ()  # an absent LC_SYMTAB is not a failure, only a limit
    assert ev.matched_symbols == ()
    assert ev.symtab_count == 0
    assert ev.partial_analysis is True


def test_an_empty_symbol_table_is_still_a_complete_read() -> None:
    data = MachOBuilder(id_dylib="libfoo.dylib", with_symtab=True).build()
    ev, errors = _read(data)
    assert errors == ()
    assert ev.symtab_count == 0
    assert ev.partial_analysis is False


def test_an_object_with_no_symbol_names_to_offer_is_recorded_as_stripped() -> None:
    """`stripped` is "no symbol table worth the name", which Mach-O can say two ways."""
    no_command = MachOBuilder(id_dylib="libfoo.dylib").build()
    no_entries = MachOBuilder(id_dylib="libfoo.dylib", with_symtab=True).build()
    carries_symbols = MachOBuilder(id_dylib="libfoo.dylib", symbols=(IMPORTED_OPENSSL,)).build()

    assert _read(no_command)[0].stripped is True
    assert _read(no_entries)[0].stripped is True
    assert _read(carries_symbols)[0].stripped is False


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

    What survives is a name cut short. Recording `EVP_DigestIn` as an imported symbol is
    noisy in the direction that cannot hide anything, the same way the ELF reader is, and
    the object is flagged partial either way.
    """
    data = MachOBuilder(id_dylib="libfoo.dylib", symbols=(IMPORTED_OPENSSL,)).build()
    ev, errors = _read(data[:-6], path="short.dylib")
    assert [error.kind for error in errors] == [MACHO_PARSE_ERROR]
    assert ev.matched_symbols == (_symbol("EVP_DigestIn", evidence.BINDING_IMPORTED),)
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
