"""Behaviour of `binfmt.elf.read_elf`, built entirely on synthetic fixtures.

The system/vendored/static distinction this module exists to draw is exercised as
three explicit fixtures (see the `test_*_linked` tests below), because that
distinction is the entire point of this layer: an imported crypto symbol next to a
plain `DT_NEEDED` means the wheel can pick up the host's FIPS provider; the same
symbol defined, or a mangled SONAME, means it brought its own copy instead.
"""

from __future__ import annotations

import dataclasses
import io
import os

import pytest

from helpers.binfmt import (
    E_SHNUM_OFFSET,
    EM_S390,
    EM_X86_64,
    DynSym,
    ElfBuilder,
    patch_u16,
)
from wheel_crypto_scan import evidence
from wheel_crypto_scan.binfmt.elf import read_elf
from wheel_crypto_scan.errors import BINARY_TRUNCATED, BINARY_UNKNOWN_FORMAT, ELF_PARSE_ERROR
from wheel_crypto_scan.ruleset import load_ruleset

PATTERNS = load_ruleset().compile_patterns().binary


def _read(data: bytes, path: str = "mod.so", *, vendored: bool = False):
    return read_elf(io.BytesIO(data), path, PATTERNS, vendored=vendored)


# --- binding: imported vs defined --------------------------------------------


def test_undefined_symbol_is_reported_as_imported() -> None:
    data = ElfBuilder(dynsyms=(DynSym("EVP_DigestInit_ex", defined=False),)).build()
    ev, errors = _read(data)
    assert errors == ()
    assert ev.matched_symbols == (
        evidence.SymbolMatch(name="EVP_DigestInit_ex", group="openssl", binding="imported"),
    )


def test_defined_symbol_is_reported_as_defined() -> None:
    data = ElfBuilder(dynsyms=(DynSym("EVP_DigestInit_ex", defined=True),)).build()
    ev, errors = _read(data)
    assert errors == ()
    assert ev.matched_symbols == (
        evidence.SymbolMatch(name="EVP_DigestInit_ex", group="openssl", binding="defined"),
    )


# --- DT_NEEDED / DT_SONAME / DT_RUNPATH read back exactly --------------------


def test_needed_soname_and_runpath_round_trip() -> None:
    data = ElfBuilder(
        needed=("libcrypto.so.3", "libpthread.so.0"),
        soname="libfoo.so.1",
        runpath=("/opt/app/lib",),
    ).build()
    ev, errors = _read(data)
    assert errors == ()
    assert ev.needed == ("libcrypto.so.3", "libpthread.so.0")
    assert ev.soname == "libfoo.so.1"
    assert ev.runpath == ("/opt/app/lib",)


# --- the three cases this whole tool exists to separate ----------------------


def test_system_linked_openssl() -> None:
    """DT_NEEDED names libcrypto, EVP_* is imported, no OpenSSL banner anywhere."""
    data = ElfBuilder(
        needed=("libcrypto.so.3",),
        dynsyms=(DynSym("EVP_DigestInit_ex", defined=False),),
    ).build()
    ev, errors = _read(data)
    assert errors == ()
    assert ev.needed == ("libcrypto.so.3",)
    assert ev.matched_symbols[0].binding == evidence.BINDING_IMPORTED
    assert ev.matched_strings == ()


def test_vendored_openssl() -> None:
    """A mangled, auditwheel-style SONAME; EVP_* defined; the banner is compiled in."""
    data = ElfBuilder(
        soname="libcrypto-3a1f2b4c.so.3",
        dynsyms=(DynSym("EVP_DigestInit_ex", defined=True),),
        rodata=b"OpenSSL 3.0.14 4 Jun 2024",
    ).build()
    ev, errors = _read(data, vendored=True)
    assert errors == ()
    assert ev.soname == "libcrypto-3a1f2b4c.so.3"
    assert ev.vendored_path is True
    assert ev.matched_symbols[0].binding == evidence.BINDING_DEFINED
    assert ev.matched_strings == (
        evidence.StringMatch(group="openssl_banner", value="OpenSSL 3.0.14 4 Jun 2024"),
    )


def test_statically_linked_openssl() -> None:
    """No OpenSSL anywhere in DT_NEEDED; EVP_* defined; banner still shows up."""
    data = ElfBuilder(
        needed=("libz.so.1",),
        dynsyms=(DynSym("EVP_DigestInit_ex", defined=True),),
        rodata=b"OpenSSL 3.0.14 4 Jun 2024",
    ).build()
    ev, errors = _read(data)
    assert errors == ()
    assert "libcrypto.so.3" not in ev.needed
    assert not any("crypto" in name for name in ev.needed)
    assert ev.matched_symbols[0].binding == evidence.BINDING_DEFINED
    assert ev.matched_strings[0].value == "OpenSSL 3.0.14 4 Jun 2024"


# --- stripped ------------------------------------------------------------------


def test_stripped_object_still_reports_dynamic_symbols() -> None:
    data = ElfBuilder(
        dynsyms=(DynSym("EVP_DigestInit_ex", defined=False),), with_symtab=False
    ).build()
    ev, errors = _read(data)
    assert errors == ()
    assert ev.stripped is True
    # dynsym_count includes the mandatory null symbol at index 0.
    assert ev.dynsym_count == 2
    assert ev.matched_symbols != ()


def test_unstripped_object_reports_stripped_false() -> None:
    data = ElfBuilder(
        dynsyms=(DynSym("EVP_DigestInit_ex", defined=False),), with_symtab=True
    ).build()
    ev, errors = _read(data)
    assert errors == ()
    assert ev.stripped is False
    assert ev.symtab_count > 0


# --- yields nothing -------------------------------------------------------------


def test_object_with_nothing_reports_empty_tuples_not_an_exception() -> None:
    data = ElfBuilder(include_dynamic=False).build()
    ev, errors = _read(data)
    assert errors == ()
    assert ev.needed == ()
    assert ev.soname is None
    assert ev.matched_symbols == ()
    assert ev.matched_strings == ()
    assert ev.rust_crates == ()
    assert ev.go is None


# --- rust crate extraction -------------------------------------------------------


def test_rust_crate_extraction_from_rodata() -> None:
    path = "/root/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ring-0.17.8/src/lib.rs"
    data = ElfBuilder(rodata=path.encode("ascii")).build()
    ev, errors = _read(data)
    assert errors == ()
    assert ev.rust_crates == (evidence.RustCrate(name="ring", version="0.17.8"),)


def test_rust_crate_extraction_deduplicates_and_sorts() -> None:
    base = "cargo/registry/src/index.crates.io-x/{}-1.0.0/src/lib.rs"
    rodata = "\n".join([base.format("zeroize"), base.format("ring"), base.format("ring")]).encode(
        "ascii"
    )
    data = ElfBuilder(rodata=rodata).build()
    ev, errors = _read(data)
    assert errors == ()
    assert [c.name for c in ev.rust_crates] == ["ring", "zeroize"]


# --- determinism -----------------------------------------------------------------


def test_reading_the_same_bytes_twice_is_equal() -> None:
    data = ElfBuilder(
        needed=("libcrypto.so.3", "libz.so.1"),
        dynsyms=(DynSym("EVP_DigestInit_ex", defined=False), DynSym("RAND_bytes", defined=True)),
        rodata=b"OpenSSL 3.0.14 4 Jun 2024",
    ).build()
    first, first_errors = _read(data)
    second, second_errors = _read(data)
    assert first == second
    assert first_errors == second_errors


def test_differently_ordered_equivalent_inputs_compare_equal() -> None:
    syms_a = (DynSym("EVP_DigestInit_ex", defined=False), DynSym("RAND_bytes", defined=True))
    syms_b = (DynSym("RAND_bytes", defined=True), DynSym("EVP_DigestInit_ex", defined=False))
    data_a = ElfBuilder(needed=("libcrypto.so.3", "libz.so.1"), dynsyms=syms_a).build()
    data_b = ElfBuilder(needed=("libz.so.1", "libcrypto.so.3"), dynsyms=syms_b).build()
    ev_a, _ = _read(data_a, path="same/path.so")
    ev_b, _ = _read(data_b, path="same/path.so")
    assert ev_a == ev_b


# --- robustness: truncated and garbage input ---------------------------------


def test_truncated_object_reports_binary_truncated() -> None:
    full = ElfBuilder(
        needed=("libcrypto.so.3",), dynsyms=(DynSym("EVP_DigestInit_ex", defined=False),)
    ).build()
    truncated = full[: len(full) // 2]
    ev, errors = _read(truncated, path="trunc.so")
    assert ev.path == "trunc.so"
    assert ev.format == evidence.FORMAT_ELF
    assert len(errors) == 1
    assert errors[0].kind == BINARY_TRUNCATED
    assert errors[0].path == "trunc.so"
    assert "trunc.so" not in errors[0].message  # message never repeats a filesystem path


def test_garbage_input_reports_binary_unknown_format() -> None:
    ev, errors = _read(b"this is not an elf file, just filler bytes" * 3, path="garbage.so")
    assert ev.format == evidence.FORMAT_ELF
    assert len(errors) == 1
    assert errors[0].kind == BINARY_UNKNOWN_FORMAT


def test_empty_input_does_not_raise() -> None:
    ev, errors = _read(b"")
    assert ev.matched_symbols == ()
    assert len(errors) == 1
    assert errors[0].kind == BINARY_UNKNOWN_FORMAT


# --- robustness: corrupt section table, no .dynstr, no .dynsym ---------------


def test_corrupt_section_table_does_not_raise() -> None:
    full = ElfBuilder(
        needed=("libcrypto.so.3",),
        dynsyms=(DynSym("EVP_DigestInit_ex", defined=False),),
        rodata=b"hello",
    ).build()
    corrupt = patch_u16(full, E_SHNUM_OFFSET[64], 0xFFFF, big_endian=False)
    ev, errors = _read(corrupt, path="corrupt.so")
    assert ev.format == evidence.FORMAT_ELF
    assert len(errors) == 1
    assert errors[0].kind in (BINARY_TRUNCATED, ELF_PARSE_ERROR)


def test_dynamic_section_with_unresolvable_string_table_does_not_raise() -> None:
    data = ElfBuilder(
        needed=("libcrypto.so.3",),
        dynsyms=(DynSym("EVP_DigestInit_ex", defined=False),),
        rodata=b"hello",
        dynamic_strtab_broken=True,
    ).build()
    ev, errors = _read(data)
    # The dynamic tags could not be resolved, so needed/soname fall back to empty...
    assert ev.needed == ()
    assert ev.soname is None
    # ...but .dynsym and .rodata, which do not depend on .dynamic, still come through.
    assert ev.matched_symbols == (
        evidence.SymbolMatch(name="EVP_DigestInit_ex", group="openssl", binding="imported"),
    )
    assert ev.matched_strings == ()  # no banner was given to this fixture
    assert any(err.kind == ELF_PARSE_ERROR for err in errors)


def test_no_dynsym_at_all_does_not_raise() -> None:
    data = ElfBuilder(needed=("libcrypto.so.3",), dynsyms=()).build()
    ev, errors = _read(data)
    assert errors == ()
    assert ev.dynsym_count == 0
    assert ev.matched_symbols == ()
    assert ev.needed == ("libcrypto.so.3",)


# --- 32-bit and big-endian ----------------------------------------------------


def test_32_bit_object_parses() -> None:
    data = ElfBuilder(
        elfclass=32,
        needed=("libcrypto.so.1",),
        dynsyms=(DynSym("EVP_DigestInit_ex", defined=True),),
    ).build()
    ev, errors = _read(data)
    assert errors == ()
    assert ev.bits == 32
    assert ev.needed == ("libcrypto.so.1",)
    assert ev.matched_symbols[0].binding == evidence.BINDING_DEFINED


def test_big_endian_object_parses() -> None:
    data = ElfBuilder(
        big_endian=True,
        machine=EM_S390,
        needed=("libcrypto.so.3",),
        dynsyms=(DynSym("EVP_DigestInit_ex", defined=False),),
    ).build()
    ev, errors = _read(data)
    assert errors == ()
    assert ev.endian == "big"
    assert ev.machine == "EM_S390"
    assert ev.matched_symbols[0].binding == evidence.BINDING_IMPORTED


def test_32_bit_big_endian_combination_parses() -> None:
    data = ElfBuilder(
        elfclass=32,
        big_endian=True,
        machine=EM_S390,
        needed=("libc.so.6",),
        dynsyms=(DynSym("RAND_bytes", defined=True),),
    ).build()
    ev, errors = _read(data)
    assert errors == ()
    assert ev.bits == 32
    assert ev.endian == "big"
    assert ev.needed == ("libc.so.6",)


# --- caps and truncation flags -------------------------------------------------


def test_symbol_cap_is_applied_after_sorting_and_flagged() -> None:
    limit = PATTERNS.limits.max_symbols_per_binary
    syms = tuple(DynSym(f"EVP_sym{i:03d}", defined=False) for i in range(limit + 5))
    data = ElfBuilder(dynsyms=syms).build()
    ev, errors = _read(data)
    assert errors == ()
    assert len(ev.matched_symbols) == limit
    assert ev.symbols_truncated is True
    names = [m.name for m in ev.matched_symbols]
    assert names == sorted(names)


def test_evidence_chars_cap_trims_string_match_value() -> None:
    limit = PATTERNS.limits.max_evidence_chars
    banner = "OpenSSL 3." + "x" * (limit + 50)
    data = ElfBuilder(rodata=banner.encode("ascii")).build()
    ev, errors = _read(data)
    assert errors == ()
    assert len(ev.matched_strings[0].value) == limit


# --- machine metadata ------------------------------------------------------------


def test_machine_bits_endian_and_elf_type_are_populated() -> None:
    data = ElfBuilder(machine=EM_X86_64).build()
    ev, errors = _read(data)
    assert errors == ()
    assert ev.machine == "EM_X86_64"
    assert ev.bits == 64
    assert ev.endian == "little"
    assert ev.elf_type == "ET_DYN"
    assert ev.partial_analysis is False
    assert ev.format == evidence.FORMAT_ELF


# --- vendored flag pass-through --------------------------------------------------


def test_vendored_flag_is_passed_through_unchanged() -> None:
    data = ElfBuilder().build()
    for flag in (True, False):
        ev, _ = _read(data, vendored=flag)
        assert ev.vendored_path is flag


# --- real system binary ------------------------------------------------------


@pytest.mark.hostbin
def test_hostbin_libcrypto_soname_and_evp_digestinit_ex_defined() -> None:
    path = "/usr/lib64/libcrypto.so.3"
    if not os.path.exists(path):
        pytest.skip("no system libcrypto.so.3 on this host")
    with open(path, "rb") as handle:
        data = handle.read()
    # The real library carries far more than max_symbols_per_binary matching symbols;
    # widen the cap so the specific symbol this test cares about is not truncated
    # away before we get to look at it. Truncation itself is exercised separately,
    # with synthetic fixtures, in test_symbol_cap_is_applied_after_sorting_and_flagged.
    wide_limits = dataclasses.replace(PATTERNS.limits, max_symbols_per_binary=100_000)
    wide_patterns = dataclasses.replace(PATTERNS, limits=wide_limits)
    ev, errors = read_elf(io.BytesIO(data), path, wide_patterns, vendored=False)
    assert errors == ()
    assert ev.soname == "libcrypto.so.3"
    digest = [m for m in ev.matched_symbols if m.name == "EVP_DigestInit_ex"]
    assert len(digest) == 1
    assert digest[0].binding == evidence.BINDING_DEFINED


# --- reading symbol tables without seeking per symbol ------------------------


def test_fast_symbol_reader_agrees_with_pyelftools() -> None:
    """The hand-rolled parser must produce exactly what pyelftools would.

    It exists because pyelftools seeks per symbol, which is catastrophic on a
    streamed member, but it is only safe if it reads the same bytes the same way.
    """
    import io

    from elftools.elf.elffile import ELFFile

    from wheel_crypto_scan.binfmt.elf import _iter_symbols

    for elfclass, big_endian in ((64, False), (32, False), (64, True), (32, True)):
        symbols = tuple(DynSym(f"sym_{i:03d}", defined=(i % 3 == 0)) for i in range(60)) + (
            DynSym("EVP_DigestInit_ex", defined=False),
            DynSym("sodium_init", defined=True),
        )
        blob = ElfBuilder(
            elfclass=elfclass, big_endian=big_endian, dynsyms=symbols, needed=("libc.so.6",)
        ).build()

        elf = ELFFile(io.BytesIO(blob))
        section = elf.get_section_by_name(".dynsym")
        expected = [
            (s.name, s["st_shndx"] == "SHN_UNDEF") for s in section.iter_symbols() if s.name
        ]
        actual = list(_iter_symbols(elf, section))
        assert actual == expected, f"mismatch for elfclass={elfclass} big_endian={big_endian}"


def test_a_large_symbol_table_does_not_thrash_a_streamed_member(tmp_path) -> None:
    """One wheel must not be able to hang an index scan.

    pandoc ships a 400 MiB object with ~497,000 dynamic symbols. Read through a
    streamed zip member with a per-symbol seek, that never finished.
    """
    import io
    import zipfile

    from wheel_crypto_scan.binfmt.elf import read_elf
    from wheel_crypto_scan.ruleset import load_ruleset
    from wheel_crypto_scan.wheelfile import SeekableZipMember

    symbols = tuple(DynSym(f"filler_symbol_{i:06d}", defined=True) for i in range(20000))
    symbols += (DynSym("EVP_DigestInit_ex", defined=False),)
    blob = ElfBuilder(dynsyms=symbols, needed=("libcrypto.so.3",), rodata=b"x" * 400000).build()

    archive_path = tmp_path / "big.zip"
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(zipfile.ZipInfo("lib/big.so", date_time=(1980, 1, 1, 0, 0, 0)), blob)

    patterns = load_ruleset().compile_patterns().binary
    with zipfile.ZipFile(archive_path) as archive:
        # window_bytes=0 is the worst case: no read-back at all.
        member = SeekableZipMember(archive, "lib/big.so", len(blob), 0)
        stream = io.BufferedReader(member)
        found, errors = read_elf(stream, "lib/big.so", patterns, vendored=False)
        stream.close()

    assert errors == ()
    assert found.dynsym_count == len(symbols) + 1
    assert any(s.name == "EVP_DigestInit_ex" for s in found.matched_symbols)
    # The cost must scale with the number of sections, not the number of symbols.
    # Before the fix this was one full decompression per symbol.
    assert member.reopens < 50, f"re-decompressed {member.reopens} times"


# --- the shared strings pass keeps feeding the reader's own inputs ------------


def _go_buildinfo(version: str) -> bytes:
    """A `.go.buildinfo` section, the shape `binfmt.golang` parses."""
    header = b"\xff Go buildinf:" + bytes([8, 0x2]) + b"\x00" * 16
    assert len(header) == 32
    return header + bytes([len(version)]) + version.encode("ascii")


def test_go_buildinfo_section_bytes_reach_the_go_reader() -> None:
    """`read_elf` passes the section it read, not just the strings pass text.

    Mach-O and PE have no such section and pass `None`. Losing ELF's first argument
    leaves `go` populated from the build id alone, with `go_version` quietly `None`,
    which is why this asserts the version rather than that `go` exists.
    """
    data = ElfBuilder(go_buildinfo=_go_buildinfo("go1.22.3")).build()
    ev, errors = _read(data, path="go.so")
    assert errors == ()
    assert ev.go is not None
    assert ev.go.go_version == "go1.22.3"


def test_a_callers_max_strings_bytes_is_reported_as_truncation() -> None:
    stream = io.BytesIO(ElfBuilder(rodata=b"OpenSSL 3.0.14 4 Jun 2024\x00").build())
    ev, _ = read_elf(stream, "mod.so", PATTERNS, vendored=False, max_strings_bytes=8)
    assert ev.strings_truncated is True


# --- a header that does not parse costs the header, not the strings ----------

BANNER = b"OpenSSL 3.0.14 4 Jun 2024"
CARGO = b"/root/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ring-0.17.8/src/lib.rs"


def test_unparseable_header_keeps_the_strings_it_already_found() -> None:
    """The headline case: `cryptography` 42+ compiles OpenSSL into the extension.

    There is no library file and no `DT_NEEDED` to find, so on some builds the banner
    in read-only data is the only evidence the object carries. Throwing it away because
    `ELFFile()` raised is how a wheel ends up looking clean.
    """
    data = b"\x7fELF" + b"\x00" * 12 + BANNER + b"\x00" + CARGO + b"\x00"
    ev, errors = _read(data, path="broken.so")
    assert [e.kind for e in errors] == [BINARY_UNKNOWN_FORMAT]
    assert ev.format == evidence.FORMAT_ELF
    assert [m.value for m in ev.matched_strings] == [BANNER.decode()]
    assert [(c.name, c.version) for c in ev.rust_crates] == [("ring", "0.17.8")]


def test_unparseable_header_marks_the_object_partial() -> None:
    """An object we could not read at all has to say so.

    This was the more serious half: `partial_analysis` stayed `False`, so nothing
    raised `BIN_PARTIAL_FORMAT` and the record never flagged itself incomplete.
    """
    ev, _ = _read(b"\x7fELF" + b"\x00" * 12 + BANNER, path="broken.so")
    assert ev.partial_analysis is True


def test_truncated_section_header_table_keeps_strings_and_marks_partial() -> None:
    full = ElfBuilder(rodata=BANNER + b"\x00").build()
    corrupt = patch_u16(full, E_SHNUM_OFFSET[64], 0xFFFF, big_endian=False)
    ev, errors = _read(corrupt, path="trunc.so")
    assert [e.kind for e in errors] == [BINARY_TRUNCATED]
    assert ev.partial_analysis is True
    assert [m.value for m in ev.matched_strings] == [BANNER.decode()]


def test_unparseable_header_still_reports_no_structural_evidence() -> None:
    """Strings survive; nothing else is invented to go with them."""
    ev, _ = _read(b"\x7fELF" + b"\x00" * 12 + BANNER, path="broken.so")
    assert ev.needed == ()
    assert ev.soname is None
    assert ev.matched_symbols == ()
    assert ev.machine is None
    assert ev.dynsym_count == 0


def test_a_truncated_section_table_keeps_the_header_fields_it_did_parse() -> None:
    """The ELF header parsed; only what it pointed at did not, so those four survive.

    Same contract as the strings: a structure that does not parse costs that structure,
    never what was already read. A truncated object still saying it is 64-bit x86-64
    has told us something.
    """
    full = ElfBuilder(rodata=BANNER + b"\x00").build()
    corrupt = patch_u16(full, E_SHNUM_OFFSET[64], 0xFFFF, big_endian=False)
    ev, errors = _read(corrupt, path="trunc.so")
    assert [e.kind for e in errors] == [BINARY_TRUNCATED]
    assert (ev.machine, ev.bits, ev.endian, ev.elf_type) == ("EM_X86_64", 64, "little", "ET_DYN")
    # Nothing the section headers would have supplied is invented to go with them.
    assert ev.needed == ()
    assert ev.matched_symbols == ()


def test_an_unparseable_elf_header_leaves_the_header_fields_empty() -> None:
    """Nothing parsed, so nothing is claimed."""
    ev, _ = _read(b"\x7fELF" + b"\x00" * 12 + BANNER, path="broken.so")
    assert (ev.machine, ev.bits, ev.endian, ev.elf_type) == (None, None, None, None)


def test_go_markers_survive_a_header_that_would_not_parse() -> None:
    """`binfmt.pe` always kept these; the contract says every format does."""
    marker = b"GOEXPERIMENT=boringcrypto\x00_Cfunc__goboringcrypto_DLEAY_version\x00"
    ev, _ = _read(b"\x7fELF" + b"\x00" * 12 + marker, path="broken.so")
    assert ev.go is not None
    assert ev.go.boring_crypto is True


def test_the_fallback_reports_a_string_not_a_section_it_cannot_know() -> None:
    """The whole-file fallback can match a name out of `.dynstr`, not just a banner.

    An object that merely *imports* mbedTLS matches the `mbedtls` string group this way.
    The record is honest about it because `engine` labels the evidence `string=` rather
    than naming a section the reader never identified, and the object stays partial.
    """
    full = ElfBuilder(
        needed=("libmbedtls.so.14",), dynsyms=(DynSym("mbedtls_ssl_init", defined=False),)
    ).build()
    corrupt = patch_u16(full, E_SHNUM_OFFSET[64], 0xFFFF, big_endian=False)
    ev, _ = _read(corrupt, path="trunc.so")
    assert [m.group for m in ev.matched_strings] == ["mbedtls"]
    assert ev.partial_analysis is True
