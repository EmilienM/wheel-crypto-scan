"""Behaviour of `binfmt.pe.read_pe`.

A Windows extension used to be read for printable strings alone, so it had no `needed`,
no `soname` and no imported-versus-defined split. These tests hold the reader to
recovering all three, to translating addresses through the section table rather than
around it, and to keeping `partial_analysis` set for everything it did not read: a
truncated section table, an absent import directory, a directory it could not walk,
anything named by ordinal alone, and a delay-load directory it does not parse.
"""

from __future__ import annotations

import dataclasses
import io

import pytest
from helpers.binfmt import IMAGE_FILE_MACHINE_I386, PEBuilder, PEExport, PEImport
from wheel_crypto_scan import evidence
from wheel_crypto_scan.binfmt.pe import read_pe
from wheel_crypto_scan.errors import PE_PARSE_ERROR
from wheel_crypto_scan.ruleset import load_ruleset

PATTERNS = load_ruleset().compile_patterns().binary

OPENSSL_DLL = "libcrypto-3-x64.dll"


def _read(data: bytes, path: str = "demo/_ext.pyd", *, vendored: bool = False):
    return read_pe(io.BytesIO(data), path, PATTERNS, vendored=vendored)


def _symbol(name: str, binding: str, group: str = "openssl") -> evidence.SymbolMatch:
    return evidence.SymbolMatch(name=name, group=group, binding=binding)


def _extension(**overrides) -> PEBuilder:
    """A `.pyd` shaped like one setuptools would produce: it calls OpenSSL, exports its
    module entry point, and names itself."""
    builder = PEBuilder(
        imports=(
            PEImport(OPENSSL_DLL, names=("EVP_DigestInit_ex", "EVP_EncryptInit_ex")),
            PEImport("python312.dll", names=("PyModule_Create2",)),
        ),
        exports=(PEExport("PyInit__ext"),),
        dll_name="_ext.pyd",
    )
    return dataclasses.replace(builder, **overrides)


# --- what the issue asked for -------------------------------------------------


def test_the_import_directory_names_every_dll_the_object_depends_on() -> None:
    """The `DT_NEEDED` equivalent, and the reason this reader exists."""
    ev, errors = _read(_extension().build())
    assert errors == ()
    assert ev.needed == (OPENSSL_DLL, "python312.dll")
    assert ev.format == evidence.FORMAT_PE
    assert ev.partial_analysis is False


def test_the_export_directory_names_the_object_itself() -> None:
    ev, errors = _read(_extension().build())
    assert errors == ()
    assert ev.soname == "_ext.pyd"


def test_an_imported_symbol_is_told_apart_from_a_defined_one() -> None:
    """The distinction the whole tool turns on, now drawable on Windows."""
    calls_out = _extension(exports=(PEExport("PyInit__ext"),))
    carries_it = _extension(
        imports=(PEImport("python312.dll", names=("PyModule_Create2",)),),
        exports=(PEExport("PyInit__ext"), PEExport("EVP_DigestInit_ex")),
    )

    imported, errors = _read(calls_out.build())
    assert errors == ()
    assert imported.matched_symbols == (
        _symbol("EVP_DigestInit_ex", evidence.BINDING_IMPORTED),
        _symbol("EVP_EncryptInit_ex", evidence.BINDING_IMPORTED),
    )

    defined, errors = _read(carries_it.build())
    assert errors == ()
    assert defined.matched_symbols == (_symbol("EVP_DigestInit_ex", evidence.BINDING_DEFINED),)


@pytest.mark.parametrize(
    ("is64", "machine", "bits", "name"),
    [
        (True, None, 64, "IMAGE_FILE_MACHINE_AMD64"),
        (False, IMAGE_FILE_MACHINE_I386, 32, "IMAGE_FILE_MACHINE_I386"),
    ],
    ids=["pe32+", "pe32"],
)
def test_both_optional_header_layouts_read_the_same_object(
    is64: bool, machine: int | None, bits: int, name: str
) -> None:
    """PE32 and PE32+ differ in field widths and in where the directories start."""
    overrides = {"is64": is64} if machine is None else {"is64": is64, "machine": machine}
    ev, errors = _read(_extension(**overrides).build())
    assert errors == ()
    assert ev.bits == bits
    assert ev.machine == name
    assert ev.endian == "little"
    assert ev.needed == (OPENSSL_DLL, "python312.dll")
    assert ev.matched_symbols == (
        _symbol("EVP_DigestInit_ex", evidence.BINDING_IMPORTED),
        _symbol("EVP_EncryptInit_ex", evidence.BINDING_IMPORTED),
    )
    assert ev.partial_analysis is False


def test_only_symbols_the_ruleset_claims_are_recorded() -> None:
    ev, _ = _read(_extension().build())
    assert [match.name for match in ev.matched_symbols] == [
        "EVP_DigestInit_ex",
        "EVP_EncryptInit_ex",
    ]
    # Everything read is still counted: three imports and one export.
    assert ev.symtab_count == 4
    assert ev.stripped is False


def test_a_name_that_is_not_ascii_is_sanitised() -> None:
    """The record is ASCII-only, so a corrupt name table cannot smuggle bytes into it."""
    builder = _extension(
        imports=(PEImport("libcrypto\udc80-3.dll", names=("EVP_Test\udc80Name",)),)
    )
    ev, errors = _read(builder.build())
    assert errors == ()
    assert ev.needed == ("libcrypto-3.dll",)
    assert ev.matched_symbols == (_symbol("EVP_TestName", evidence.BINDING_IMPORTED),)


def test_the_symbol_limit_is_applied_and_flagged() -> None:
    limit = PATTERNS.limits.max_symbols_per_binary
    names = tuple(f"EVP_Sym{index:03d}" for index in range(limit + 6))
    ev, errors = _read(_extension(imports=(PEImport(OPENSSL_DLL, names=names),)).build())
    assert errors == ()
    assert ev.symbols_truncated is True
    assert len(ev.matched_symbols) == limit
    # Capped after sorting, so which ones survive is the same on every run.
    assert [match.name for match in ev.matched_symbols] == [
        f"EVP_Sym{index:03d}" for index in range(limit)
    ]


def test_reading_the_same_bytes_twice_is_equal() -> None:
    data = _extension().build()
    first, first_errors = _read(data)
    second, second_errors = _read(data)
    assert first == second
    assert first_errors == second_errors


def test_always_extracts_strings() -> None:
    banner = b"OpenSSL 3.0.14 4 Jun 2024"
    ev, errors = _read(_extension(trailing=banner).build())
    assert errors == ()
    assert ev.matched_strings == (
        evidence.StringMatch(group="openssl_banner", value=banner.decode("ascii")),
    )


def test_vendored_flag_passes_through() -> None:
    ev, _ = _read(_extension().build(), vendored=True)
    assert ev.vendored_path is True


# --- address translation ------------------------------------------------------


def test_addresses_are_translated_through_the_section_table() -> None:
    """The same content at a different address and a different file offset reads the same.

    Two extra sections ahead of the import data move both, and by different amounts: the
    section alignment is 0x1000 and the file alignment 0x200, so no single delta maps
    one object onto the other.
    """
    plain = _extension()
    shifted = _extension(filler_sections=2)
    assert plain.section_addresses()[".rdata"] != shifted.section_addresses()[".rdata"]
    assert plain.section_offsets()[".rdata"] != shifted.section_offsets()[".rdata"]

    first, first_errors = _read(plain.build())
    second, second_errors = _read(shifted.build())
    assert (first_errors, second_errors) == ((), ())
    assert second.needed == first.needed
    assert second.matched_symbols == first.matched_symbols
    assert second.soname == first.soname
    assert second.partial_analysis is False


def test_a_section_that_lies_about_where_its_bytes_are_reads_no_real_names() -> None:
    """The control for the test above: break the mapping and the names must go.

    `PointerToRawData` is moved one file-alignment unit on, which lands the import
    directory on the export section's bytes. A reader that translated addresses any
    other way would come back with names that are not in this object's import table.
    """
    honest = _extension()
    misplaced = _extension(declared_rdata_raw_offset=honest.section_offsets()[".rdata"] + 0x200)
    ev, errors = _read(misplaced.build())
    assert [error.kind for error in errors] == [PE_PARSE_ERROR]
    assert OPENSSL_DLL not in ev.needed
    assert ev.matched_symbols == ()
    assert ev.partial_analysis is True


def test_bytes_past_size_of_raw_data_are_not_in_the_object() -> None:
    """Past `SizeOfRawData` the loader zero-fills, so the file carries nothing there.

    The bytes are physically present in this fixture; only the header says they are not.
    A reader that clamped to the section's virtual size instead would read them anyway.
    """
    clamped = _extension(declared_rdata_raw_size=20)
    ev, errors = _read(clamped.build())
    assert [error.kind for error in errors] == [PE_PARSE_ERROR]
    assert ev.needed == ()
    assert ev.partial_analysis is True


def test_a_section_with_no_virtual_size_is_as_big_as_its_raw_data() -> None:
    """Zero there is how an object file spells "as big as what the file carries".

    Believing the zero would give the section an empty span, and every address inside
    it would resolve nowhere.
    """
    ev, errors = _read(_extension(declared_rdata_virtual_size=0).build())
    assert errors == ()
    assert ev.needed == (OPENSSL_DLL, "python312.dll")
    assert ev.partial_analysis is False


def test_a_section_pointed_past_the_end_of_the_object_yields_nothing() -> None:
    ev, errors = _read(_extension(declared_rdata_raw_offset=1 << 30).build())
    assert [error.kind for error in errors] == [PE_PARSE_ERROR]
    assert ev.matched_symbols == ()
    assert ev.partial_analysis is True


# --- imports that cannot be believed -----------------------------------------


def test_an_object_with_no_import_directory_stays_partial() -> None:
    """It declared no dependency at all, which is what its record said before this reader."""
    ev, errors = _read(_extension(imports=()).build())
    assert errors == ()  # an absent directory is not a failure, only a limit
    assert ev.needed == ()
    assert ev.soname == "_ext.pyd"
    assert ev.partial_analysis is True


def test_an_import_array_with_no_terminator_is_an_error() -> None:
    ev, errors = _read(_extension(unterminated_imports=True).build())
    assert [error.kind for error in errors] == [PE_PARSE_ERROR]
    assert errors[0].path == "demo/_ext.pyd"
    # Whatever was readable before the array ran off the end is still evidence.
    assert OPENSSL_DLL in ev.needed
    assert ev.partial_analysis is True


def test_an_import_array_that_loops_back_is_read_once() -> None:
    """Two sections can map one file offset, so walking by address can revisit bytes.

    The alias sits at the address the array's terminator would occupy and maps the first
    descriptor, so a reader that did not notice would keep reading the same DLLs.
    """
    looping = _extension(
        imports=(PEImport("a.dll", names=("EVP_A",)), PEImport("b.dll", names=("EVP_B",))),
        aliased_rdata_section=True,
    )
    ev, errors = _read(looping.build())
    assert [error.kind for error in errors] == [PE_PARSE_ERROR]
    assert ev.needed == ("a.dll", "b.dll")
    # Two imports and one export. `needed` is a set, so the count is the only thing
    # that shows the revisited descriptor was refused rather than read a second time.
    assert ev.symtab_count == 3
    assert ev.partial_analysis is True

    honest, honest_errors = _read(dataclasses.replace(looping, aliased_rdata_section=False).build())
    assert honest_errors == ()
    assert honest.needed == ("a.dll", "b.dll")
    assert honest.partial_analysis is False


def test_an_import_array_longer_than_any_real_object_stops() -> None:
    """The cap is the last guard under an array that simply never ends."""
    many = _extension(imports=tuple(PEImport(f"d{index:04d}.dll") for index in range(4200)))
    ev, errors = _read(many.build())
    assert [error.kind for error in errors] == [PE_PARSE_ERROR]
    assert len(ev.needed) < 4200
    assert ev.partial_analysis is True


def test_one_thunk_array_shared_by_every_descriptor_is_walked_once_over() -> None:
    """The two caps are not independent: nothing stops every descriptor sharing a table.

    A per-DLL thunk cap would multiply with the descriptor cap rather than bound
    anything, so the budget is carried across the whole object. Walking it out is an
    incomplete read like any other.
    """
    shared = _extension(
        imports=tuple(PEImport(f"d{index:03d}.dll") for index in range(200)),
        shared_thunk_entries=4096,
    )
    ev, errors = _read(shared.build())
    assert [error.kind for error in errors] == [PE_PARSE_ERROR]
    # 819,200 entries were reachable through those descriptors. What was read is the
    # whole-object budget of 65,536, plus the one export.
    assert ev.symtab_count == 65536 + 1
    # The DLL names are cheap and are the evidence worth having, so the walk goes on
    # collecting them after the budget for their contents is gone.
    assert len(ev.needed) == 200
    assert ev.partial_analysis is True


def test_a_dll_name_pointer_outside_every_section_is_an_error() -> None:
    ev, errors = _read(_extension(declared_dll_name_rva=0x900000).build())
    assert [error.kind for error in errors] == [PE_PARSE_ERROR]
    assert ev.needed == ()
    assert ev.partial_analysis is True


def test_a_hint_name_pointer_outside_every_section_is_an_error() -> None:
    ev, errors = _read(_extension(declared_hint_name_rva=0x900000).build())
    assert [error.kind for error in errors] == [PE_PARSE_ERROR]
    # The library it depends on was still named; the functions it takes were not.
    assert OPENSSL_DLL in ev.needed
    assert ev.matched_symbols == ()
    assert ev.partial_analysis is True


def test_a_bound_image_is_read_from_its_address_table() -> None:
    """A bound image zeroes the lookup table and keeps the entries in the address one.

    The lookup table is the authority, but when it is absent the address table is the
    only place these names exist. Reading only the lookup table would report an object
    that plainly depends on OpenSSL as depending on nothing readable.
    """
    honest, _ = _read(_extension().build())
    bound, errors = _read(_extension(bound_imports=True).build())
    assert errors == ()
    assert bound.needed == honest.needed
    assert bound.matched_symbols == honest.matched_symbols
    assert bound.partial_analysis is False


def test_an_import_directory_pointed_outside_every_section_is_an_error() -> None:
    ev, errors = _read(_extension(declared_import_rva=0x900000).build())
    assert [error.kind for error in errors] == [PE_PARSE_ERROR]
    assert ev.needed == ()
    assert ev.partial_analysis is True


def test_a_name_whose_terminator_is_outside_its_section_is_not_read() -> None:
    """Reporting the bytes up to the boundary would invent a name out of what follows.

    `.rdata` is clipped by one byte, which takes the NUL off the end of the last DLL
    name and nothing else. A reader that returned the truncated window would report a
    dependency on OpenSSL that this object does not, as far as it can be read, declare.
    """
    builder = _extension(imports=(PEImport(OPENSSL_DLL, names=("EVP_DigestInit_ex",)),))
    clipped = dataclasses.replace(
        builder, declared_rdata_raw_size=builder.section_sizes()[".rdata"] - 1
    )
    ev, errors = _read(clipped.build())
    assert [error.kind for error in errors] == [PE_PARSE_ERROR]
    assert ev.needed == ()
    assert ev.partial_analysis is True


def test_an_ordinal_only_import_is_counted_and_leaves_the_object_partial() -> None:
    """An ordinal names its function by number, so there is no name anywhere to read.

    Dropping it silently would leave a record saying "we read every name and none of
    them was crypto" about an object whose names we did not all read.
    """
    by_ordinal = _extension(
        imports=(PEImport(OPENSSL_DLL, names=("EVP_DigestInit_ex",), ordinals=(17, 42)),)
    )
    ev, errors = _read(by_ordinal.build())
    assert errors == ()  # well-formed: unreadable evidence, not a broken object
    assert ev.needed == (OPENSSL_DLL,)
    assert ev.matched_symbols == (_symbol("EVP_DigestInit_ex", evidence.BINDING_IMPORTED),)
    assert ev.symtab_count == 4  # one named import, two ordinals, one export
    assert ev.partial_analysis is True


@pytest.mark.parametrize("size", [32, 0], ids=["sized", "size-zero"])
def test_a_delay_load_import_directory_leaves_the_object_partial(size: int) -> None:
    """It names libraries loaded on first call, and this reader does not parse it.

    The directory is keyed on its address alone, like the import and export
    directories. Its `Size` is informational: the descriptor array is NUL-terminated
    and the loader drives it from the descriptors, so a zero there is the cheapest
    possible way to hide a delay-loaded OpenSSL behind a complete-looking read.
    """
    builder = _extension(delay_import_directory=True, declared_delay_import_size=size)
    ev, errors = _read(builder.build())
    assert errors == ()
    assert ev.needed == (OPENSSL_DLL, "python312.dll")
    assert ev.partial_analysis is True


# --- exports that cannot be believed -----------------------------------------


def test_a_forwarded_export_is_recorded_as_imported() -> None:
    """A forwarder's address is a string naming another DLL, so the code is not here."""
    forwarding = _extension(
        imports=(PEImport("python312.dll", names=("PyModule_Create2",)),),
        exports=(PEExport("EVP_DigestInit_ex", forwarder="libcrypto.EVP_DigestInit_ex"),),
    )
    ev, errors = _read(forwarding.build())
    assert errors == ()
    assert ev.matched_symbols == (_symbol("EVP_DigestInit_ex", evidence.BINDING_IMPORTED),)
    assert ev.partial_analysis is False


def test_a_forwarder_at_the_export_directory_s_first_byte_is_still_a_forwarder() -> None:
    """The range that tells a forwarder from a definition includes its own first byte.

    An address equal to the directory's own is inside the directory, so the "code" it
    names is a string. An exclusive lower bound would record this as a definition:
    OpenSSL compiled into the wheel rather than resolved from another DLL.
    """
    forwarding = _extension(
        imports=(PEImport("python312.dll", names=("PyModule_Create2",)),),
        exports=(PEExport("EVP_DigestInit_ex", forwarder="libcrypto.EVP_DigestInit_ex"),),
        forwarder_at_directory_start=True,
    )
    ev, errors = _read(forwarding.build())
    assert errors == ()
    assert ev.matched_symbols == (_symbol("EVP_DigestInit_ex", evidence.BINDING_IMPORTED),)


def test_exports_the_name_table_never_points_at_leave_the_object_partial() -> None:
    """Definitions with no name are the cheap way to hide what an object carries."""
    ev, errors = _read(_extension(unnamed_exports=3).build())
    assert errors == ()
    assert ev.symtab_count == 7  # three imports, one named export, three unnamed
    assert ev.partial_analysis is True


def test_a_name_count_larger_than_the_tables_is_an_error() -> None:
    """`NumberOfNames` and `NumberOfFunctions` are independent, and nothing makes them agree."""
    ev, errors = _read(_extension(declared_name_count=4096).build())
    assert [error.kind for error in errors] == [PE_PARSE_ERROR]
    assert ev.partial_analysis is True


def test_a_name_pointer_table_outside_every_section_is_an_error() -> None:
    ev, errors = _read(_extension(declared_name_pointer_rva=0x900000).build())
    assert [error.kind for error in errors] == [PE_PARSE_ERROR]
    assert ev.soname == "_ext.pyd"
    assert ev.partial_analysis is True


def test_an_export_directory_pointed_outside_every_section_is_an_error() -> None:
    ev, errors = _read(_extension(declared_export_rva=0x900000).build())
    assert [error.kind for error in errors] == [PE_PARSE_ERROR]
    assert ev.soname is None
    assert ev.partial_analysis is True


def test_an_object_that_exports_nothing_is_still_a_complete_read() -> None:
    """Nothing can link against it, so reading no exports from it is the whole truth."""
    ev, errors = _read(_extension(exports=(), dll_name=None).build())
    assert errors == ()
    assert ev.soname is None
    assert ev.partial_analysis is False


def test_an_object_that_names_nothing_is_not_recorded_as_stripped() -> None:
    """`stripped` is an ELF and Mach-O observation and PE has nothing to observe.

    Its own symbol table is COFF debug information every linker drops, so there is no
    absence here that could mean what `stripped` means. Deriving it from the count
    would also let a failed read of the export table assert that the object named
    nothing, which is the opposite of what that failure knows. The count says it.
    """
    ev, _ = _read(_extension(imports=(), exports=(), dll_name=None).build())
    assert ev.stripped is False
    assert ev.symtab_count == 0


def test_an_unreadable_export_table_never_claims_the_object_named_nothing() -> None:
    """The failure that hid the exports must not also assert there were none."""
    ev, errors = _read(_extension(imports=(), declared_name_count=4096).build())
    assert [error.kind for error in errors] == [PE_PARSE_ERROR]
    assert ev.stripped is False
    assert ev.partial_analysis is True


# --- headers that cannot be believed -----------------------------------------


@pytest.mark.parametrize(
    ("cut", "message"),
    [
        (0x30, "object is too short to hold a dos header"),
        (0x50, "pe header offset is outside the object"),
        (0x60, "pe optional header is truncated"),
        (0x150, "pe section table is truncated"),
    ],
    ids=["dos", "coff", "optional", "sections"],
)
def test_a_truncated_object_does_not_raise(cut: int, message: str) -> None:
    ev, errors = _read(_extension(truncate_to=cut).build(), path="trunc.pyd")
    # A cut that takes the section table also takes both directories with it, so what
    # is pinned is the first thing that went wrong, not how many symptoms it had.
    assert {error.kind for error in errors} == {PE_PARSE_ERROR}
    assert message in {error.message for error in errors}
    assert {error.path for error in errors} == {"trunc.pyd"}
    assert ev.format == evidence.FORMAT_PE
    assert ev.partial_analysis is True


@pytest.mark.parametrize("value", [0, 1 << 30, 0xFFFFFFF0], ids=["zero", "past-eof", "negative"])
def test_an_e_lfanew_that_points_nowhere_is_an_error(value: int) -> None:
    """It is a signed LONG on disk, so a negative one arrives as a very large offset."""
    ev, errors = _read(_extension(declared_e_lfanew=value).build())
    assert [error.kind for error in errors] == [PE_PARSE_ERROR]
    assert errors[0].message == "pe header offset is outside the object"
    assert ev.partial_analysis is True


def test_a_missing_pe_signature_is_an_error() -> None:
    ev, errors = _read(_extension(signature=b"NE\x00\x00").build())
    assert [error.kind for error in errors] == [PE_PARSE_ERROR]
    assert errors[0].message == "pe signature is missing"
    assert ev.partial_analysis is True


def test_an_unrecognised_optional_header_magic_is_an_error() -> None:
    ev, errors = _read(_extension(declared_optional_magic=0x107).build())
    assert [error.kind for error in errors] == [PE_PARSE_ERROR]
    assert errors[0].message == "unrecognised pe optional header magic"
    assert ev.partial_analysis is True


def test_a_section_count_of_65535_does_not_allocate() -> None:
    """A 16-bit self-declared count out of an object a few kilobytes long."""
    ev, errors = _read(_extension(declared_section_count=0xFFFF).build())
    assert PE_PARSE_ERROR in {error.kind for error in errors}
    assert ev.partial_analysis is True


def test_a_dos_stub_with_no_pe_header_keeps_its_strings() -> None:
    """Plenty of things start with MZ. Losing their strings would be the worst outcome."""
    data = b"MZ" + b"\x00" * 60 + b"OpenSSL 3.0.14 4 Jun 2024\x00"
    ev, errors = _read(data, path="stub.pyd")
    assert [error.kind for error in errors] == [PE_PARSE_ERROR]
    assert ev.matched_strings != ()
    assert ev.partial_analysis is True


def test_an_empty_input_does_not_raise() -> None:
    ev, errors = _read(b"")
    assert [error.kind for error in errors] == [PE_PARSE_ERROR]
    assert ev.matched_strings == ()
    assert ev.partial_analysis is True
