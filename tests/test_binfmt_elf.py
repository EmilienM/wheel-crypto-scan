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
import struct
import zlib

import pytest

from helpers.binfmt import (
    E_SHNUM_OFFSET,
    EM_S390,
    EM_X86_64,
    ET_REL,
    SHF_COMPRESSED,
    SHT_DYNAMIC,
    SHT_DYNSYM,
    SHT_PROGBITS,
    SHT_SYMTAB,
    STB_GLOBAL,
    DynSym,
    ElfBuilder,
    append_duplicate_dynsym_section,
    append_strtab_decoy,
    insert_bogus_section_before,
    patch_header_field,
    patch_section_header,
    patch_u16,
)
from wheel_crypto_scan import evidence
from wheel_crypto_scan.binfmt import symtab
from wheel_crypto_scan.binfmt.elf import read_elf
from wheel_crypto_scan.engine import apply_rules
from wheel_crypto_scan.errors import BINARY_TRUNCATED, BINARY_UNKNOWN_FORMAT, ELF_PARSE_ERROR
from wheel_crypto_scan.linkage import resolve_linkage
from wheel_crypto_scan.ruleset_loader import load_ruleset
from wheel_crypto_scan.verdict import NO_CRYPTO_DETECTED, classify

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
    """`.dynamic` failing to read costs `.dynsym`'s symbols too, and that is correct.

    `.dynsym`'s own `sh_link` is only trusted when it corroborates `.dynamic`'s own
    `DT_STRTAB` tag (#56 round 4): a decoy `SHT_STRTAB` section is otherwise
    indistinguishable from the real `.dynstr`. When `.dynamic` itself could not be
    read at all, there is no `DT_STRTAB` to corroborate against, so `.dynsym`'s
    string table is untrusted too -- fail closed, not "structurally unrelated, so
    unaffected". This was a deliberate behaviour change, not a regression: the
    alternative is exactly the hole that let a decoy string table erase real crypto
    symbols with nothing in the record to say so.
    """
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
    # ...and .dynsym's names are now also untrusted, with nothing to corroborate its
    # string table against; the record says so rather than reading them as absent.
    assert ev.matched_symbols == ()
    assert ev.partial_analysis is True
    assert set(ev.partial_reasons) == {
        evidence.PARTIAL_ELF_SECTIONS_UNREAD,
        evidence.PARTIAL_ELF_DYNSYM_UNREAD,
    }
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


@pytest.mark.hostbin
def test_hostbin_libcrypto_carries_its_build_string_beside_its_banner() -> None:
    """A real compiled-in copy of OpenSSL keeps `openssl_build_info` beside its own
    `openssl_banner`: `OpenSSL_version()` returns both from the same switch. This
    pins the claim `linkage._banner_is_header_text`'s gate rests on against a real
    library, not only hand-built evidence."""
    path = "/usr/lib64/libcrypto.so.3"
    if not os.path.exists(path):
        pytest.skip("no system libcrypto.so.3 on this host")
    with open(path, "rb") as handle:
        data = handle.read()
    ev, errors = read_elf(io.BytesIO(data), path, PATTERNS, vendored=False)
    assert errors == ()
    groups = {match.group for match in ev.matched_strings}
    assert "openssl_banner" in groups
    assert "openssl_build_info" in groups


# --- reading symbol tables without seeking per symbol ------------------------


def test_fast_symbol_reader_agrees_with_pyelftools() -> None:
    """The hand-rolled parser must produce exactly what pyelftools would.

    It exists because pyelftools seeks per symbol, which is catastrophic on a
    streamed member, but it is only safe if it reads the same bytes the same way.
    """
    import io

    from elftools.elf.elffile import ELFFile

    from wheel_crypto_scan.binfmt.elf import _iter_symbols, _symbol_bytes, _validated_strtab
    from wheel_crypto_scan.binfmt.strings import MAX_STRINGS_BYTES

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
        # `ElfBuilder` always writes DT_STRTAB and every section's sh_addr as 0, so 0
        # is the value that corroborates `.dynstr` here -- this test is about the fast
        # reader agreeing with pyelftools, not about the sh_link/DT_STRTAB check.
        dynstr_section = _validated_strtab(elf, section["sh_link"], 0)
        table, dynstr, _unread = _symbol_bytes(elf, section, dynstr_section, MAX_STRINGS_BYTES)
        read = _iter_symbols(elf, table, dynstr)
        actual = [
            (name, undefined) for name, undefined, resolved, _symtype in read if resolved and name
        ]
        assert actual == expected, f"mismatch for elfclass={elfclass} big_endian={big_endian}"


def test_a_large_symbol_table_does_not_thrash_a_streamed_member(tmp_path) -> None:
    """One wheel must not be able to hang an index scan.

    pandoc ships a 400 MiB object with ~497,000 dynamic symbols. Read through a
    streamed zip member with a per-symbol seek, that never finished.
    """
    import io
    import zipfile

    from wheel_crypto_scan.binfmt.elf import read_elf
    from wheel_crypto_scan.ruleset_loader import load_ruleset
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


def test_the_symbol_tables_are_read_in_the_order_they_sit_in_the_file(tmp_path) -> None:
    """Whichever of `.dynsym` and `.dynstr` comes first is read first.

    Reading the later one first is a backwards seek, and through a zip member past its
    retained window that is one more full decompression of everything before it. The
    linker usually puts `.dynsym` first; this suite's own builder does not, and neither
    do some `objcopy` reorderings, so the reader sorts rather than assuming.

    The count below is exact on purpose. Taking the sections in a fixed order instead
    costs exactly one more, and a bound loose enough not to notice that is a bound that
    would not have caught it.
    """
    import io
    import zipfile

    from wheel_crypto_scan.binfmt.elf import read_elf
    from wheel_crypto_scan.ruleset_loader import load_ruleset
    from wheel_crypto_scan.wheelfile import SeekableZipMember

    symbols = tuple(DynSym(f"filler_{i:05d}", defined=True) for i in range(4000))
    symbols += (DynSym("EVP_DigestInit_ex", defined=False),)
    blob = ElfBuilder(dynsyms=symbols, needed=("libcrypto.so.3",), rodata=b"x" * 200000).build()

    archive_path = tmp_path / "ordered.zip"
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(zipfile.ZipInfo("lib/o.so", date_time=(1980, 1, 1, 0, 0, 0)), blob)

    patterns = load_ruleset().compile_patterns().binary
    with zipfile.ZipFile(archive_path) as archive:
        member = SeekableZipMember(archive, "lib/o.so", len(blob), 0)
        stream = io.BufferedReader(member)
        found, errors = read_elf(stream, "lib/o.so", patterns, vendored=False)
        stream.close()

    assert errors == ()
    assert any(s.name == "EVP_DigestInit_ex" for s in found.matched_symbols)
    assert member.reopens == 10, f"re-decompressed {member.reopens} times, expected 10"


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


# --- #62: a SHF_COMPRESSED section's declared size is checked before it is inflated --
#
# `Section.data()` decompresses `Chdr.ch_size` bytes -- the logical, decompressed size,
# an attacker-controlled 64-bit field -- before this reader ever gets to apply its own
# byte budget. A 255 KiB object can declare and produce a 256 MiB buffer this way. The
# fix reads `ch_size` (`section.data_size`, which pyelftools itself already parses
# eagerly, cheaply, in `Section.__init__`) and refuses to call `.data()` at all once
# that alone is over budget.


def _compressed_chdr(ch_size: int, *, addralign: int = 1) -> bytes:
    """A `SHF_COMPRESSED` section's `Elf64_Chdr`: `ELFCOMPRESS_ZLIB`, declaring `ch_size`."""
    return struct.pack("<IIQQ", 1, 0, ch_size, addralign)


def _compressed_section(payload: bytes) -> bytes:
    """A real, honestly-declared `SHF_COMPRESSED` section body for `payload`."""
    return _compressed_chdr(len(payload)) + zlib.compress(payload, 9)


def test_a_compressed_rodata_declaring_more_than_the_budget_is_refused_not_inflated() -> None:
    """Refused by the declared size alone, before the (here, real and honest) payload
    is ever decompressed.

    The payload genuinely does decompress to its declared 8 KiB -- this is not a
    section whose bytes cannot be trusted, the way "elf section data unreadable" in
    `tests/test_partial_reasons.py` is. Unfixed, `.data()` succeeds here and the
    banner at the front of the buffer survives truncation to 4 KiB, so the object
    reads as `strings_bytes_unread` rather than `elf_section_data_unread`: correct in
    the sense the issue itself describes ("the record afterwards is correct... this
    is cost, not evidence"), but only after the 8 KiB (a stand-in for the issue's own
    512 MiB) was fully inflated to get there. Fixed, the declared size alone is over
    budget and `.data()` is never called, so nothing is ever read from this section --
    and `strings_truncated` stays `False`: the section was never read, so nothing
    here can say how many of its bytes, if any, were genuine strings versus more of
    whatever `ch_size` this large represents (see DECISIONS.md's note on this).
    """
    payload = BANNER + b"\x00" + b"\x00" * (8192 - len(BANNER) - 1)
    body = _compressed_section(payload)
    data = patch_section_header(
        ElfBuilder(rodata=body).build(), ".rodata", "sh_flags", SHF_COMPRESSED, bitwise_or=True
    )
    ev, errs = read_elf(
        io.BytesIO(data), "mod.so", PATTERNS, vendored=False, max_strings_bytes=4096
    )
    assert ev.partial_analysis is True
    assert evidence.PARTIAL_ELF_SECTION_DATA_UNREAD in ev.partial_reasons
    assert evidence.PARTIAL_STRINGS_BYTES_UNREAD not in ev.partial_reasons
    assert ev.strings_truncated is False
    assert any(e.kind == ELF_PARSE_ERROR for e in errs)
    assert ev.matched_strings == ()


def test_a_compressed_rodata_declaring_exactly_the_remaining_budget_still_reads() -> None:
    """Exactly `remaining`, not more than it, so the section is refused nothing."""
    payload = BANNER + b"\x00"
    body = _compressed_section(payload)
    data = patch_section_header(
        ElfBuilder(rodata=body).build(), ".rodata", "sh_flags", SHF_COMPRESSED, bitwise_or=True
    )
    ev, errs = read_elf(
        io.BytesIO(data), "mod.so", PATTERNS, vendored=False, max_strings_bytes=len(payload)
    )
    assert errs == ()
    assert ev.partial_analysis is False
    assert ev.strings_truncated is False
    assert [m.value for m in ev.matched_strings] == [BANNER.decode()]


def test_a_compressed_rodata_under_the_budget_reads_normally() -> None:
    """Regression guard: an honestly small compressed section still decompresses."""
    payload = BANNER + b"\x00"
    body = _compressed_section(payload)
    data = patch_section_header(
        ElfBuilder(rodata=body).build(), ".rodata", "sh_flags", SHF_COMPRESSED, bitwise_or=True
    )
    ev, errs = read_elf(
        io.BytesIO(data), "mod.so", PATTERNS, vendored=False, max_strings_bytes=len(payload) * 4
    )
    assert errs == ()
    assert ev.partial_analysis is False
    assert [m.value for m in ev.matched_strings] == [BANNER.decode()]


# `.dynsym`'s associated string table goes through the identical `.data()` call, via
# `_bounded_section_data` shared with `.rodata` above -- a decoy `SHT_STRTAB`,
# corroborated against `.dynamic`'s own `DT_STRTAB` the way #56 already requires, is
# how a test can control what bytes `.dynsym` resolves names through without the
# builder needing a raw-bytes hook for `.dynstr` itself. `sh_addr=0` is what
# corroborates: `ElfBuilder` always writes `DT_STRTAB`'s own `d_ptr`, and every
# section's `sh_addr`, as 0.

# 46 bytes, chosen (#95) so `_DYNSTR_PAYLOAD` below lands at exactly 48 bytes -- the
# same 48 bytes `.dynsym` itself declares for one real `DynSym` here: index 0 is always
# the reserved null entry, so one real symbol is two `Elf64_Sym` rows, 24 bytes each.
# `_bounded_section_data` now checks `.dynsym`'s own declared size unconditionally too,
# not only `.dynstr`'s, so an "exactly at the budget" test below has to sit at a
# boundary both sections actually share, not just the string table's.
_DYNSTR_NAME = "EVP_" + "x" * 42
_DYNSTR_PAYLOAD = b"\x00" + _DYNSTR_NAME.encode("ascii") + b"\x00"


def _compressed_dynstr_decoy(honest: bytes, body: bytes) -> bytes:
    with_decoy, decoy_index = append_strtab_decoy(honest, body, sh_addr=0)
    with_decoy = patch_section_header(
        with_decoy, "", "sh_flags", SHF_COMPRESSED, bitwise_or=True, occurrence=2
    )
    return patch_section_header(with_decoy, ".dynsym", "sh_link", decoy_index)


def test_a_compressed_dynstr_declaring_more_than_the_budget_is_refused_not_inflated() -> None:
    """As above, one level over: `.dynsym` has no truncate-and-continue of its own, so
    unfixed this genuinely decompressing 8 KiB `.dynstr` is read in full regardless of
    `max_strings_bytes` and the symbol resolves -- the exposure here is that nothing
    ever refuses it, at any size. Fixed, `ch_size` alone over budget refuses it before
    `.data()` runs, and the entry that named it comes back unresolved instead.
    """
    honest = ElfBuilder(dynsyms=(DynSym(_DYNSTR_NAME, defined=False),)).build()
    payload = _DYNSTR_PAYLOAD + b"\x00" * (8192 - len(_DYNSTR_PAYLOAD))
    body = _compressed_section(payload)
    repointed = _compressed_dynstr_decoy(honest, body)
    ev, errs = read_elf(
        io.BytesIO(repointed), "mod.so", PATTERNS, vendored=False, max_strings_bytes=4096
    )
    assert ev.partial_analysis is True
    assert evidence.PARTIAL_ELF_DYNSYM_UNREAD in ev.partial_reasons
    assert ev.matched_symbols == ()
    assert any(e.kind == ELF_PARSE_ERROR for e in errs)


def test_a_compressed_dynstr_declaring_exactly_the_budget_still_resolves() -> None:
    honest = ElfBuilder(dynsyms=(DynSym(_DYNSTR_NAME, defined=False),)).build()
    body = _compressed_section(_DYNSTR_PAYLOAD)
    repointed = _compressed_dynstr_decoy(honest, body)
    ev, errs = read_elf(
        io.BytesIO(repointed),
        "mod.so",
        PATTERNS,
        vendored=False,
        max_strings_bytes=len(_DYNSTR_PAYLOAD),
    )
    assert errs == ()
    assert ev.partial_analysis is False
    assert {m.name for m in ev.matched_symbols} == {_DYNSTR_NAME}


def test_a_compressed_dynstr_under_the_budget_resolves_normally() -> None:
    honest = ElfBuilder(dynsyms=(DynSym(_DYNSTR_NAME, defined=False),)).build()
    body = _compressed_section(_DYNSTR_PAYLOAD)
    repointed = _compressed_dynstr_decoy(honest, body)
    ev, errs = read_elf(
        io.BytesIO(repointed),
        "mod.so",
        PATTERNS,
        vendored=False,
        max_strings_bytes=len(_DYNSTR_PAYLOAD) * 4,
    )
    assert errs == ()
    assert ev.partial_analysis is False
    assert {m.name for m in ev.matched_symbols} == {_DYNSTR_NAME}


# --- #95: an ordinary, uncompressed section is checked against the budget too -------
#
# `_bounded_section_data` only refused before `.data()` ran when the section was
# `compressed` or `SHT_NOBITS` -- the two shapes #62 measured. An ordinary, honest,
# uncompressed section (or `.dynsym`/`.dynstr` from a real symbol table) fell through
# that `and` entirely and reached `.data()` unconditionally, so a large honest `.rodata`
# or symbol table was read in full regardless of `max_strings_bytes`, with only the
# *accumulated* buffer cut afterwards. `section.data_size` is `sh_size` itself for an
# ordinary section (pyelftools sets `_decompressed_size = header['sh_size']` whenever
# `compressed` is false), so the same check #62 already applies, without the narrowing,
# closes this the same way -- for `.rodata`/`.comment`/`.go.buildinfo`, with the real,
# honest prefix up to the budget kept (`keep_prefix=True`) rather than thrown away:
# unlike a compressed section, reading `min(sh_size, max_bytes)` bytes of an ordinary
# one costs nothing extra, an honest banner well inside the budget is real evidence
# a refusal should not cost, and this is exactly what `_collect_string_bytes` already
# did before this widened check started refusing the whole section outright. The
# result reads as `strings_bytes_unread` -- the reader's own budget ran out before the
# object did, not that the section could not be read -- the same token an oversized
# object already gets when several smaller sections exhaust the budget between them.


def test_an_ordinary_rodata_over_the_budget_keeps_its_in_budget_prefix() -> None:
    """The uncompressed counterpart of the compressed `.rodata` test above: the section
    is honest and file-backed, so its first `max_strings_bytes` are real content --
    including the banner here, which sits at the very front -- and are kept rather
    than discarded, even though the section as a whole is refused past that point.
    """
    payload = BANNER + b"\x00" + b"\x00" * (8192 - len(BANNER) - 1)
    data = ElfBuilder(rodata=payload).build()
    ev, errs = read_elf(
        io.BytesIO(data), "mod.so", PATTERNS, vendored=False, max_strings_bytes=4096
    )
    assert errs == ()
    assert ev.partial_analysis is True
    assert ev.partial_reasons == (evidence.PARTIAL_STRINGS_BYTES_UNREAD,)
    assert ev.strings_truncated is True
    assert [m.value for m in ev.matched_strings] == [BANNER.decode()]


def test_an_ordinary_rodata_over_the_budget_with_nothing_in_the_prefix_still_partial() -> None:
    """Regression guard the other way: when the recoverable prefix holds nothing a
    consumer cares about, the object is still correctly `partial_analysis` -- keeping
    a prefix is not the same claim as the object being fully read.
    """
    payload = b"\x00" * 8192
    data = ElfBuilder(rodata=payload).build()
    ev, errs = read_elf(
        io.BytesIO(data), "mod.so", PATTERNS, vendored=False, max_strings_bytes=4096
    )
    assert errs == ()
    assert ev.partial_analysis is True
    assert ev.partial_reasons == (evidence.PARTIAL_STRINGS_BYTES_UNREAD,)
    assert ev.matched_strings == ()


def test_a_short_read_past_the_budget_is_not_reported_as_truncated() -> None:
    """`truncated` says what was actually dropped, not what `sh_size` declared.

    A `sh_size` patched far past the object's real end (a malformed header, not an
    honestly large section) makes `keep_prefix`'s bounded read come back shorter than
    the budget with nothing left unread -- the recovered bytes are everything from
    `sh_offset` to EOF. Reporting `strings_bytes_unread` here would be the same false
    claim `AGENTS.md` and this function's own docstring rule out for the "declared vs.
    actually dropped" distinction elsewhere in this reader.
    """
    payload = BANNER + b"\x00" + b"\x00" * 64
    data = ElfBuilder(rodata=payload).build()
    data = patch_section_header(data, ".rodata", "sh_size", 1024**3)  # 1 GiB, past EOF
    ev, errs = read_elf(
        io.BytesIO(data), "mod.so", PATTERNS, vendored=False, max_strings_bytes=4096
    )
    assert errs == ()
    assert ev.partial_analysis is False
    assert ev.partial_reasons == ()
    assert ev.strings_truncated is False
    assert [m.value for m in ev.matched_strings] == [BANNER.decode()]


def test_an_ordinary_rodata_declaring_exactly_the_remaining_budget_still_reads() -> None:
    """Exactly `remaining`, not more than it, so the section is refused nothing -- the
    same "more than, not at least" boundary #62's own tests draw for the compressed case.
    """
    payload = BANNER + b"\x00"
    data = ElfBuilder(rodata=payload).build()
    ev, errs = read_elf(
        io.BytesIO(data), "mod.so", PATTERNS, vendored=False, max_strings_bytes=len(payload)
    )
    assert errs == ()
    assert ev.partial_analysis is False
    assert ev.strings_truncated is False
    assert [m.value for m in ev.matched_strings] == [BANNER.decode()]


def test_an_ordinary_rodata_under_the_budget_reads_normally() -> None:
    """Regression guard: a section comfortably under budget is unaffected by widening
    the check to the uncompressed case.
    """
    payload = BANNER + b"\x00"
    data = ElfBuilder(rodata=payload).build()
    ev, errs = read_elf(
        io.BytesIO(data), "mod.so", PATTERNS, vendored=False, max_strings_bytes=len(payload) * 4
    )
    assert errs == ()
    assert ev.partial_analysis is False
    assert [m.value for m in ev.matched_strings] == [BANNER.decode()]


def _ordinary_dynstr_decoy(honest: bytes, body: bytes) -> bytes:
    """As `_compressed_dynstr_decoy` above, minus the compression: `body` is the
    decoy `.dynstr`'s raw, uncompressed content.
    """
    with_decoy, decoy_index = append_strtab_decoy(honest, body, sh_addr=0)
    return patch_section_header(with_decoy, ".dynsym", "sh_link", decoy_index)


def test_an_ordinary_dynstr_declaring_more_than_the_budget_is_refused_not_inflated() -> None:
    """As the compressed `.dynstr` test above, minus the compression: unfixed, this
    honest, uncompressed 8 KiB `.dynstr` is read in full at any size and the symbol
    resolves. Fixed, `sh_size` alone over budget refuses it before `.data()` runs, and
    the entry that named it comes back unresolved instead -- the record has to say so
    rather than read as a clean, complete table.
    """
    honest = ElfBuilder(dynsyms=(DynSym(_DYNSTR_NAME, defined=False),)).build()
    payload = _DYNSTR_PAYLOAD + b"\x00" * (8192 - len(_DYNSTR_PAYLOAD))
    repointed = _ordinary_dynstr_decoy(honest, payload)
    ev, errs = read_elf(
        io.BytesIO(repointed), "mod.so", PATTERNS, vendored=False, max_strings_bytes=4096
    )
    assert ev.partial_analysis is True
    assert evidence.PARTIAL_ELF_DYNSYM_UNREAD in ev.partial_reasons
    assert ev.matched_symbols == ()
    assert any(e.kind == ELF_PARSE_ERROR for e in errs)


def test_an_ordinary_dynstr_declaring_exactly_the_budget_still_resolves() -> None:
    """Boundary: exactly at the budget still resolves, one byte over does not."""
    honest = ElfBuilder(dynsyms=(DynSym(_DYNSTR_NAME, defined=False),)).build()
    repointed = _ordinary_dynstr_decoy(honest, _DYNSTR_PAYLOAD)
    ev, errs = read_elf(
        io.BytesIO(repointed),
        "mod.so",
        PATTERNS,
        vendored=False,
        max_strings_bytes=len(_DYNSTR_PAYLOAD),
    )
    assert errs == ()
    assert ev.partial_analysis is False
    assert {m.name for m in ev.matched_symbols} == {_DYNSTR_NAME}


def test_an_ordinary_dynstr_under_the_budget_resolves_normally() -> None:
    """Regression guard: an honest, comfortably-under-budget `.dynstr` is unaffected."""
    honest = ElfBuilder(dynsyms=(DynSym(_DYNSTR_NAME, defined=False),)).build()
    repointed = _ordinary_dynstr_decoy(honest, _DYNSTR_PAYLOAD)
    ev, errs = read_elf(
        io.BytesIO(repointed),
        "mod.so",
        PATTERNS,
        vendored=False,
        max_strings_bytes=len(_DYNSTR_PAYLOAD) * 4,
    )
    assert errs == ()
    assert ev.partial_analysis is False
    assert {m.name for m in ev.matched_symbols} == {_DYNSTR_NAME}


# --- a refused .dynsym/.dynstr never reaches the understated/unresolved cross-check --
#
# `symtab_bytes_unread` (#95's own widened refusal) has to be checked BEFORE
# `unresolved`/`holds_a_name_not_read`, the same ordering `binfmt.macho`'s own
# `truncated` check already has ahead of its `unresolved`/understated pair. Without
# that ordering, a `.dynsym` refused for budget (empty `table`, zero rows, `unresolved
# == 0`) with an honest, in-budget `.dynstr` reaches `holds_a_name_not_read` and
# fabricates `symtab_understates_rows` -- a specific, checkable claim that is false
# here: the object's row count was never wrong, `.dynsym` was simply never read.


def test_a_refused_dynsym_with_an_honest_dynstr_does_not_fabricate_understated_rows() -> None:
    """`.dynsym` alone is over budget (many short-named padding entries); `.dynstr`,
    built from the same short names, comfortably fits. Unfixed, `table` is empty so
    `unresolved` stays 0, and `holds_a_name_not_read` finds `SSL_new` in `.dynstr`
    unclaimed by any read row -- a real crypto name reported as an understated symbol
    count, when the true fact is the table was refused, not that it lied.
    """
    padding = tuple(DynSym(f"n{i:03d}", defined=False) for i in range(100))
    syms = (DynSym("SSL_new", defined=False),) + padding
    data = ElfBuilder(dynsyms=syms).build()

    ev, errs = read_elf(io.BytesIO(data), "mod.so", PATTERNS, vendored=False, max_strings_bytes=600)

    assert ev.partial_analysis is True
    assert ev.partial_reasons == (evidence.PARTIAL_ELF_DYNSYM_UNREAD,)
    assert evidence.PARTIAL_SYMTAB_UNDERSTATES_ROWS not in ev.partial_reasons
    assert [e.message for e in errs] == [
        ".dynsym or its string table declares more bytes than the budget allows"
    ]
    assert ev.matched_symbols == ()


def test_a_refused_dynstr_with_an_honest_dynsym_does_not_fabricate_a_second_error() -> None:
    """The companion, lower-severity shape: `.dynstr` alone is over budget (a large
    uncompressed decoy), `.dynsym` is a single honest, in-budget entry. Unfixed, every
    row in `table` fails to resolve against the empty `dynstr`, so `unresolved > 0` and
    the first branch fires a second, redundant error on top of the correct budget one
    -- `.dynstr` was never shown to lie about its own contents, only left unread.
    """
    honest = ElfBuilder(dynsyms=(DynSym("SSL_new", defined=False),)).build()
    payload = b"\x00SSL_new\x00" + b"\x00" * (8192 - 10)
    repointed = _ordinary_dynstr_decoy(honest, payload)

    ev, errs = read_elf(
        io.BytesIO(repointed), "mod.so", PATTERNS, vendored=False, max_strings_bytes=4096
    )

    assert ev.partial_analysis is True
    assert ev.partial_reasons == (evidence.PARTIAL_ELF_DYNSYM_UNREAD,)
    assert [e.message for e in errs] == [
        ".dynsym or its string table declares more bytes than the budget allows"
    ]
    assert ev.matched_symbols == ()


def test_an_ordinary_go_buildinfo_over_the_budget_still_parses_its_recovered_prefix() -> None:
    """The third call site sharing `_bounded_section_data`, for the uncompressed case:
    an honest `.go.buildinfo` over budget is refused past the budget the same way
    `.rodata` is, but -- unlike `.rodata`/`.comment` -- keeping the recovered prefix
    here does not also drop `elf_go_buildinfo_unread`/the error: the section's own
    declared size was not honoured, and that stays true regardless of whether the
    version string happened to sit inside the part that was. The version itself is
    real evidence recovered from the kept prefix, not discarded downstream the way an
    outright refusal would have thrown it away.
    """
    payload = b"\xff Go buildinf:" + bytes([8, 2]) + b"\x00" * 16 + b"\x08go1.22.3"
    payload = payload + b"\x00" * (8192 - len(payload))
    data = ElfBuilder(go_buildinfo=payload).build()
    ev, errs = read_elf(
        io.BytesIO(data), "mod.so", PATTERNS, vendored=False, max_strings_bytes=4096
    )
    assert ev.partial_analysis is True
    assert evidence.PARTIAL_ELF_GO_BUILDINFO_UNREAD in ev.partial_reasons
    assert any(e.kind == ELF_PARSE_ERROR for e in errs)
    assert ev.go is not None
    assert ev.go.go_version == "go1.22.3"


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


# --- an error means the object was not read in full --------------------------


def test_an_unresolvable_dynamic_section_no_longer_reads_as_a_complete_read() -> None:
    """The dangerous one: `needed` empties, and the record used to call that complete.

    A consumer filtering on `partial_analysis` would have taken this for an object that
    genuinely declares no dependencies, which is the "looks clean because we could not
    read it" failure the whole tool is built to avoid.
    """
    data = ElfBuilder(
        needed=("libcrypto.so.3",),
        dynsyms=(DynSym("EVP_DigestInit_ex", defined=False),),
        rodata=b"hello",
        dynamic_strtab_broken=True,
    ).build()
    ev, errors = _read(data)
    assert [e.kind for e in errors] == [ELF_PARSE_ERROR, ELF_PARSE_ERROR]
    assert ev.needed == ()
    assert ev.partial_analysis is True
    # `elf_dynsym_unread` joins `elf_sections_unread` now: `.dynsym`'s own string table
    # has nothing to corroborate against once `.dynamic` could not be read, so it is
    # untrusted too rather than read through regardless (#56 round 4).
    assert set(ev.partial_reasons) == {
        evidence.PARTIAL_ELF_SECTIONS_UNREAD,
        evidence.PARTIAL_ELF_DYNSYM_UNREAD,
    }


def test_a_readable_object_is_still_not_partial() -> None:
    ev, errors = _read(
        ElfBuilder(
            needed=("libcrypto.so.3",),
            dynsyms=(DynSym("EVP_DigestInit_ex", defined=False),),
            with_symtab=True,
        ).build()
    )
    assert errors == ()
    assert ev.partial_analysis is False
    assert ev.partial_reasons == ()


# --- the declaration itself can lie ------------------------------------------

_HIDDEN = (
    DynSym("PyInit__ext", defined=True),
    DynSym("EVP_DigestInit_ex", defined=False),
    DynSym("SSL_new", defined=False),
)


def test_a_dynsym_size_that_stops_short_of_the_rows_is_not_a_clean_read() -> None:
    """`sh_size` is a field the object fills in about itself.

    Cover one entry of four and the two OpenSSL imports behind it are never read.
    Nothing is malformed: pyelftools reads the declared table without complaint, every
    index resolves, and the object comes out saying it has no crypto in it. `.dynstr`
    still holds both names, which is what gives it away.
    """
    honest = ElfBuilder(needed=("libc.so.6",), dynsyms=_HIDDEN).build()
    ev, errors = _read(patch_section_header(honest, ".dynsym", "sh_size", 24))
    assert ev.matched_symbols == ()
    assert ev.partial_analysis is True
    # Both: the format's own cause, and the one a consumer can filter an index on
    # without caring which format told the lie.
    assert list(ev.partial_reasons) == ["elf_dynsym_unread", "symtab_understates_rows"]
    assert [e.message for e in errors] == [
        ".dynsym declares fewer entries than .dynstr holds names for"
    ]


def test_a_dynsym_size_of_zero_over_rows_full_of_symbols_is_not_a_clean_read() -> None:
    """The blunt version, and the one that also empties `symbol_counts.dynsym`."""
    honest = ElfBuilder(needed=("libc.so.6",), dynsyms=_HIDDEN).build()
    ev, errors = _read(patch_section_header(honest, ".dynsym", "sh_size", 0))
    assert ev.dynsym_count == 0
    assert ev.partial_analysis is True
    assert [e.message for e in errors] == [
        ".dynsym declares fewer entries than .dynstr holds names for"
    ]


def test_evidence_already_read_survives_the_rows_that_were_hidden() -> None:
    """A count that lies costs the rows behind it, never the ones in front of it.

    Three entries of 24 bytes covers the null entry, `PyInit__ext` and
    `EVP_DigestInit_ex`, leaving `SSL_new` unread. The OpenSSL import that *was*
    declared is evidence and has to survive, or the check trades one silent hole for
    another. The `sh_size = 24` case above cannot hold this: it covers the null entry
    alone, so an empty `matched_symbols` passes there whatever the code does.
    """
    honest = ElfBuilder(needed=("libc.so.6",), dynsyms=_HIDDEN).build()
    ev, errors = _read(patch_section_header(honest, ".dynsym", "sh_size", 72))
    assert [m.name for m in ev.matched_symbols] == ["EVP_DigestInit_ex"]
    assert ev.partial_analysis is True
    assert [e.message for e in errors] == [
        ".dynsym declares fewer entries than .dynstr holds names for"
    ]


def test_a_dynstr_that_does_not_hold_the_names_dynsym_points_at_is_not_a_clean_read() -> None:
    """The same lie, one field over: shrink `.dynstr` instead of `.dynsym`.

    Every row stays, `symbol_counts.dynsym` stays at four, and pyelftools reads the
    table without complaint -- the names simply are not reachable any more. Without a
    check on the indices this is a statically linked extension, with no `DT_NEEDED` to
    make it opaque, reporting `NO_CRYPTO_DETECTED` while carrying two OpenSSL imports.
    """
    honest = ElfBuilder(dynsyms=_HIDDEN).build()
    for size in (0, 8, 16):
        ev, errors = _read(patch_section_header(honest, ".dynstr", "sh_size", size))
        assert ev.dynsym_count == 4, size
        assert ev.matched_symbols == (), size
        assert ev.partial_analysis is True, size
        assert [e.message for e in errors] == [".dynsym names strings .dynstr does not hold"]


def test_a_name_cut_short_by_dynstr_is_not_reported_as_a_symbol() -> None:
    """A run `.dynstr` never closes is a name we could not resolve, not a short name.

    Cut to 24 bytes, the bytes reachable from `EVP_DigestInit_ex`'s index are
    `EVP_DigestI`, which a rule claims by prefix. Reporting it would put a symbol in
    the record that the object does not carry, in the field the whole tool turns on.
    """
    honest = ElfBuilder(dynsyms=_HIDDEN).build()
    ev, errors = _read(patch_section_header(honest, ".dynstr", "sh_size", 24))
    assert ev.matched_symbols == ()
    assert ev.partial_analysis is True
    assert [e.message for e in errors] == [".dynsym names strings .dynstr does not hold"]


def test_an_honest_dynsym_costs_nothing_and_stays_complete() -> None:
    """The cross-check must not fire on an object that declared what it carries."""
    ev, errors = _read(ElfBuilder(needed=("libc.so.6",), dynsyms=_HIDDEN).build())
    assert errors == ()
    assert ev.partial_analysis is False
    assert [m.name for m in ev.matched_symbols] == ["EVP_DigestInit_ex", "SSL_new"]


def test_a_name_the_ruleset_does_not_claim_is_not_a_hidden_symbol() -> None:
    """The check asks whether a *crypto* name went unread, not whether any name did.

    `.dynstr` holds section and version strings as well as symbol names, and an object
    is free to carry any of them without declaring a symbol for it.
    """
    honest = ElfBuilder(
        needed=("libc.so.6",),
        dynsyms=(DynSym("PyInit__ext", defined=True), DynSym("helper", defined=True)),
    ).build()
    ev, errors = _read(patch_section_header(honest, ".dynsym", "sh_size", 24))
    assert errors == ()
    assert ev.partial_analysis is False


def test_a_leading_underscore_is_a_name_here_not_an_abi_prefix() -> None:
    """Darwin adds an underscore to every C symbol; ELF does not, and neither does this.

    `binfmt.macho` inverts that prefix before matching, and the cross-check it shares
    with this reader has to invert exactly what the reader inverts. Stripping it here
    would read `_EVP_DigestInit_ex` as the OpenSSL entry point, which this object does
    not have and never declared -- an honest wheel reported as one hiding a symbol.
    """
    ev, errors = _read(
        ElfBuilder(
            needed=("libc.so.6",),
            dynsyms=(
                DynSym("PyInit__ext", defined=True),
                DynSym("_EVP_DigestInit_ex", defined=False),
            ),
        ).build()
    )
    assert errors == ()
    assert ev.partial_analysis is False
    assert ev.matched_symbols == ()


# --- a symbol name has a cap, and the table a whole-table budget (#61) --------
#
# `_iter_symbols` used to decode and `sanitize` every dynsym name in full, with no
# per-name bound and no table-wide budget: a table pointing many rows at one enormous
# name cost rows times that name's length, all of it in `sanitize`, a per-character
# Python pass. `binfmt.symtab.BoundedNames` ports `binfmt.pe`'s `_MAX_NAME_BYTES` /
# `_MAX_NAME_TOTAL_BYTES` (#53) to close it. `tests/test_hardening.py` holds the
# bounded-time and memoization-effectiveness cases; these hold the boundary itself and
# the whole-table budget a repeated single name does not exercise.


def _crypto_name(index: int, length: int) -> str:
    """A distinct, `openssl`-matching dynsym name of exactly `length` bytes.

    `ElfBuilder` interns `.dynstr` by exact text (`_StrTab.add`), so two symbols
    sharing one string share one table entry -- distinct indices are what keeps this a
    table of many different names, rather than one name many rows point at.
    """
    prefix = f"EVP_{index:08d}_"
    assert len(prefix) < length
    return prefix + "A" * (length - len(prefix))


def test_a_dynsym_name_exactly_at_the_cap_is_still_read() -> None:
    """The bound is generous, not absent: a name of exactly the cap still resolves."""
    name = "EVP_" + "A" * (symtab._MAX_NAME_BYTES - 4)
    assert len(name) == symtab._MAX_NAME_BYTES
    ev, errors = _read(ElfBuilder(dynsyms=(DynSym(name, defined=False),)).build())
    assert errors == ()
    assert ev.partial_analysis is False
    assert [m.name for m in ev.matched_symbols] == [name]


def test_a_dynsym_name_one_byte_over_the_cap_is_not_read() -> None:
    """One byte further and the row is unresolved, not truncated into the record.

    Raising a limit is how a limit quietly stops being one, so the far side of it is
    pinned rather than assumed -- the same reason #53's PE test pins its own boundary.
    """
    name = "EVP_" + "A" * (symtab._MAX_NAME_BYTES - 3)
    assert len(name) == symtab._MAX_NAME_BYTES + 1
    ev, errors = _read(ElfBuilder(dynsyms=(DynSym(name, defined=False),)).build())
    assert ev.matched_symbols == ()
    assert ev.partial_analysis is True
    assert list(ev.partial_reasons) == [evidence.PARTIAL_ELF_DYNSYM_UNREAD]
    assert [e.message for e in errors] == [".dynsym names strings .dynstr does not hold"]


def test_many_long_names_under_the_cap_exhaust_the_table_wide_budget() -> None:
    """The per-name cap bounds one row; nothing bounds the table without a budget too.

    Every name here is individually well inside `_MAX_NAME_BYTES`, but there are enough
    of them, all distinct, that their total resolved bytes run past
    `_MAX_NAME_TOTAL_BYTES` -- the shape a table gets from many different long names
    rather than from one name repeated, which the cap alone does not bound.
    """
    length = symtab._MAX_NAME_BYTES - 200
    count = (symtab._MAX_NAME_TOTAL_BYTES // length) + 200
    dynsyms = tuple(DynSym(_crypto_name(i, length), defined=False) for i in range(count))
    ev, errors = _read(ElfBuilder(dynsyms=dynsyms).build())
    # Bounded, not abandoned: the names the budget could afford are read (roughly
    # `_MAX_NAME_TOTAL_BYTES // length` of them), and the rest are unresolved rather
    # than reported as an object with no crypto in it.
    assert 0 < len(ev.matched_symbols) < count
    assert ev.partial_analysis is True
    assert list(ev.partial_reasons) == [evidence.PARTIAL_ELF_DYNSYM_UNREAD]
    assert [e.message for e in errors] == [".dynsym names strings .dynstr does not hold"]


# --- sections are found by type, not by a name nobody checks (#56) -----------
#
# The dynamic linker never reads section names or the section header table at all --
# it walks `PT_DYNAMIC` and the tags it points at -- so a name-based lookup trusted a
# label the loader itself never checks. Renaming `.dynsym` (or `.dynamic`, or
# `.symtab`) in `.shstrtab` produced a loadable object a name-based reader treated as
# carrying none of them: no error, `partial_analysis: false`, every symbol and
# dependency gone from the record.


def test_a_renamed_dynsym_is_still_found_by_type() -> None:
    honest = ElfBuilder(needed=("libc.so.6",), dynsyms=_HIDDEN).build()
    renamed = honest.replace(b".dynsym\x00", b".dynsyx\x00")
    ev, errors = _read(renamed)
    assert errors == ()
    assert ev.partial_analysis is False
    assert ev.needed == ("libc.so.6",)
    assert {m.name for m in ev.matched_symbols} == {"EVP_DigestInit_ex", "SSL_new"}
    assert all(m.binding == evidence.BINDING_IMPORTED for m in ev.matched_symbols)


def test_renaming_dynamic_too_still_populates_needed() -> None:
    """`.dynamic` is found by `sh_type` the same way, so both renames close together."""
    honest = ElfBuilder(needed=("libc.so.6",), dynsyms=_HIDDEN).build()
    renamed = honest.replace(b".dynsym\x00", b".dynsyx\x00").replace(
        b".dynamic\x00", b".dynamix\x00"
    )
    ev, errors = _read(renamed)
    assert errors == ()
    assert ev.partial_analysis is False
    assert ev.needed == ("libc.so.6",)
    assert {m.name for m in ev.matched_symbols} == {"EVP_DigestInit_ex", "SSL_new"}


def test_a_renamed_symtab_still_reports_stripped_status() -> None:
    honest = ElfBuilder(needed=("libc.so.6",), dynsyms=_HIDDEN, with_symtab=True).build()
    renamed = honest.replace(b".symtab\x00", b".symtax\x00")
    ev, errors = _read(renamed)
    assert errors == ()
    assert ev.partial_analysis is False
    assert ev.stripped is False
    assert ev.symtab_count == len(_HIDDEN) + 1  # the mandatory null entry, plus three


def test_multiple_dynsym_sections_after_the_real_one_are_ambiguous_not_clean() -> None:
    """More than one `SHT_DYNSYM` section is unusual but not forbidden.

    Picking "the first in section order" would be exactly the shape #56 exists to
    close, one level down: a decoy could be crafted to sort first and hide the real
    section. Instead neither is trusted, and the object reads as ambiguous rather than
    as one carrying no symbols at all.
    """
    honest = ElfBuilder(needed=("libc.so.6",), dynsyms=_HIDDEN).build()
    ev, errors = _read(append_duplicate_dynsym_section(honest))
    assert ev.partial_analysis is True
    assert list(ev.partial_reasons) == [evidence.PARTIAL_ELF_SECTION_TYPE_AMBIGUOUS]
    assert ev.dynsym_count == 0
    assert ev.matched_symbols == ()
    assert any(e.kind == ELF_PARSE_ERROR for e in errors)


def test_a_decoy_dynsym_section_spliced_in_before_the_real_one_no_longer_reads_clean() -> None:
    """The shape a "first match wins" rule would get wrong: a decoy earlier in the
    section list than the real `.dynsym`, so a naive type-based lookup would pick the
    decoy and read the object as carrying nothing -- exactly the "renamed and now
    reads clean" failure #56 exists to close, reintroduced one level down. Ambiguity
    detection has to be order-independent to close it.
    """
    honest = ElfBuilder(needed=("libc.so.6",), dynsyms=_HIDDEN).build()
    spliced = insert_bogus_section_before(honest, ".dynsym", SHT_DYNSYM)
    ev, errors = _read(spliced)
    assert ev.partial_analysis is True
    assert list(ev.partial_reasons) == [evidence.PARTIAL_ELF_SECTION_TYPE_AMBIGUOUS]
    assert ev.dynsym_count == 0
    assert ev.matched_symbols == ()
    assert any(e.kind == ELF_PARSE_ERROR for e in errors)


def test_an_ambiguous_dynamic_section_costs_needed_too() -> None:
    """The same ambiguity handling applies to `.dynamic`, not just `.dynsym`.

    It also costs `.dynsym`'s symbols: an ambiguous `.dynamic` means no `DT_STRTAB` to
    corroborate `.dynsym`'s own `sh_link` against (#56 round 4), so that string table
    is untrusted too rather than read through regardless.
    """
    honest = ElfBuilder(needed=("libc.so.6",), dynsyms=_HIDDEN).build()
    spliced = insert_bogus_section_before(honest, ".dynamic", SHT_DYNAMIC)
    ev, errors = _read(spliced)
    assert ev.partial_analysis is True
    assert set(ev.partial_reasons) == {
        evidence.PARTIAL_ELF_SECTION_TYPE_AMBIGUOUS,
        evidence.PARTIAL_ELF_DYNSYM_UNREAD,
    }
    assert ev.needed == ()
    assert ev.soname is None
    assert ev.matched_symbols == ()
    assert any(e.kind == ELF_PARSE_ERROR for e in errors)


def test_an_ambiguous_symtab_section_costs_stripped_too() -> None:
    """The same ambiguity handling applies to `.symtab`, not just `.dynsym`."""
    honest = ElfBuilder(needed=("libc.so.6",), dynsyms=_HIDDEN, with_symtab=True).build()
    spliced = insert_bogus_section_before(honest, ".symtab", SHT_SYMTAB)
    ev, errors = _read(spliced)
    assert ev.partial_analysis is True
    assert list(ev.partial_reasons) == [evidence.PARTIAL_ELF_SECTION_TYPE_AMBIGUOUS]
    assert ev.symtab_count == 0
    assert ev.stripped is True
    assert any(e.kind == ELF_PARSE_ERROR for e in errors)


def test_a_forged_dynsym_type_with_the_name_left_intact_does_not_read_as_absent() -> None:
    """A section still called `.dynsym`, whose `sh_type` was changed away from
    `SHT_DYNSYM` alone, is a section that exists and cannot be trusted, not a section
    that is genuinely absent. A type-based lookup that finds nothing here has to check
    whether a name-based match with a mismatched type exists before reading the object
    as carrying no dynamic symbol table at all.
    """
    honest = ElfBuilder(needed=("libc.so.6",), dynsyms=_HIDDEN).build()
    forged = patch_section_header(honest, ".dynsym", "sh_type", SHT_PROGBITS)
    ev, errors = _read(forged)
    assert ev.partial_analysis is True
    assert list(ev.partial_reasons) == [evidence.PARTIAL_ELF_DYNSYM_UNREAD]
    assert ev.dynsym_count == 0
    assert ev.matched_symbols == ()
    assert any(e.kind == ELF_PARSE_ERROR for e in errors)
    assert any("SHT_DYNSYM" in e.message for e in errors)


def test_a_forged_dynamic_type_with_the_name_left_intact_does_not_read_as_absent() -> None:
    """Also costs `.dynsym`: no readable `.dynamic` means no `DT_STRTAB` to
    corroborate `.dynsym`'s `sh_link` against either (#56 round 4)."""
    honest = ElfBuilder(needed=("libc.so.6",), dynsyms=_HIDDEN).build()
    forged = patch_section_header(honest, ".dynamic", "sh_type", SHT_PROGBITS)
    ev, errors = _read(forged)
    assert ev.partial_analysis is True
    assert set(ev.partial_reasons) == {
        evidence.PARTIAL_ELF_DYNAMIC_UNREAD,
        evidence.PARTIAL_ELF_DYNSYM_UNREAD,
    }
    assert ev.needed == ()
    assert ev.matched_symbols == ()
    assert any(e.kind == ELF_PARSE_ERROR for e in errors)


def test_a_forged_symtab_type_with_the_name_left_intact_does_not_read_as_absent() -> None:
    honest = ElfBuilder(needed=("libc.so.6",), dynsyms=_HIDDEN, with_symtab=True).build()
    forged = patch_section_header(honest, ".symtab", "sh_type", SHT_PROGBITS)
    ev, errors = _read(forged)
    assert ev.partial_analysis is True
    assert list(ev.partial_reasons) == [evidence.PARTIAL_ELF_SYMTAB_UNREAD]
    assert ev.symtab_count == 0
    assert any(e.kind == ELF_PARSE_ERROR for e in errors)


# --- a decoy of the target type must not disable the name/type-mismatch check ------
#
# The mismatch check used to run only when the type-based lookup found nothing
# (`dynsym is None and _type_mismatch(...)`). One harmless decoy `SHT_DYNSYM` section
# is enough to satisfy the type-based lookup on its own -- unambiguously, since there
# is exactly one candidate of that type -- so `dynsym is None` was False and the
# mismatch check was never even consulted. The REAL section, still correctly named but
# with its own `sh_type` forged away, then went completely unseen: not found by type
# (wrong type) and not checked by name (the gate never fired). The check now runs
# unconditionally, regardless of what the type-based lookup found elsewhere.


def test_a_decoy_dynsym_does_not_disable_the_check_on_the_real_forged_one() -> None:
    honest = ElfBuilder(needed=("libc.so.6",), dynsyms=_HIDDEN).build()
    with_decoy = append_duplicate_dynsym_section(honest)
    decoy_and_forged = patch_section_header(with_decoy, ".dynsym", "sh_type", SHT_PROGBITS)
    ev, errors = _read(decoy_and_forged)
    assert ev.partial_analysis is True
    assert list(ev.partial_reasons) == [evidence.PARTIAL_ELF_DYNSYM_UNREAD]
    assert ev.matched_symbols == ()
    assert any(e.kind == ELF_PARSE_ERROR for e in errors)
    # `.dynamic` was untouched by this attack, so `needed` still reads correctly --
    # only `.dynsym`'s evidence is what this shape costs.
    assert ev.needed == ("libc.so.6",)


def test_a_decoy_dynamic_does_not_disable_the_check_on_the_real_forged_one() -> None:
    honest = ElfBuilder(needed=("libc.so.6",), dynsyms=_HIDDEN).build()
    with_decoy = insert_bogus_section_before(honest, ".dynamic", SHT_DYNAMIC)
    decoy_and_forged = patch_section_header(with_decoy, ".dynamic", "sh_type", SHT_PROGBITS)
    ev, errors = _read(decoy_and_forged)
    assert ev.partial_analysis is True
    assert set(ev.partial_reasons) == {
        evidence.PARTIAL_ELF_DYNAMIC_UNREAD,
        evidence.PARTIAL_ELF_DYNSYM_UNREAD,
    }
    assert ev.needed == ()
    assert ev.matched_symbols == ()
    assert any(e.kind == ELF_PARSE_ERROR for e in errors)


def test_a_decoy_symtab_does_not_disable_the_check_on_the_real_forged_one() -> None:
    honest = ElfBuilder(needed=("libc.so.6",), dynsyms=_HIDDEN, with_symtab=True).build()
    with_decoy = insert_bogus_section_before(honest, ".symtab", SHT_SYMTAB)
    decoy_and_forged = patch_section_header(with_decoy, ".symtab", "sh_type", SHT_PROGBITS)
    ev, errors = _read(decoy_and_forged)
    assert ev.partial_analysis is True
    assert list(ev.partial_reasons) == [evidence.PARTIAL_ELF_SYMTAB_UNREAD]
    assert any(e.kind == ELF_PARSE_ERROR for e in errors)


# --- a same-named decoy must not disable the name/type-mismatch check either -------
#
# `_type_mismatch` finds "the section named X" the same way `_find_section` always
# has: the first match in section order. A decoy that reuses the real section's own
# *name* rather than its type sorts first, is read as correctly typed (it is -- that
# is the whole trick), and reports no mismatch, leaving a same-named real section
# sitting behind it -- still carrying its own forged `sh_type` -- completely unseen:
# not found by type (wrong type) and not caught by the mismatch check (a differently
# ambiguous, but equally untrustworthy, name match). Ambiguous by name is now treated
# the same as ambiguous by type: neither is trusted.


def test_a_same_named_decoy_dynsym_does_not_disable_the_check_either() -> None:
    honest = ElfBuilder(needed=("libc.so.6",), dynsyms=_HIDDEN).build()
    with_decoy = insert_bogus_section_before(honest, ".dynsym", SHT_DYNSYM, same_name=True)
    decoy_and_forged = patch_section_header(
        with_decoy, ".dynsym", "sh_type", SHT_PROGBITS, occurrence=2
    )
    ev, errors = _read(decoy_and_forged)
    assert ev.partial_analysis is True
    assert list(ev.partial_reasons) == [evidence.PARTIAL_ELF_DYNSYM_UNREAD]
    assert ev.matched_symbols == ()
    assert any(e.kind == ELF_PARSE_ERROR for e in errors)
    assert ev.needed == ("libc.so.6",)


def test_a_same_named_decoy_dynamic_does_not_disable_the_check_either() -> None:
    honest = ElfBuilder(needed=("libc.so.6",), dynsyms=_HIDDEN).build()
    with_decoy = insert_bogus_section_before(honest, ".dynamic", SHT_DYNAMIC, same_name=True)
    decoy_and_forged = patch_section_header(
        with_decoy, ".dynamic", "sh_type", SHT_PROGBITS, occurrence=2
    )
    ev, errors = _read(decoy_and_forged)
    assert ev.partial_analysis is True
    assert set(ev.partial_reasons) == {
        evidence.PARTIAL_ELF_DYNAMIC_UNREAD,
        evidence.PARTIAL_ELF_DYNSYM_UNREAD,
    }
    assert ev.needed == ()
    assert ev.matched_symbols == ()
    assert any(e.kind == ELF_PARSE_ERROR for e in errors)


def test_a_same_named_decoy_symtab_does_not_disable_the_check_either() -> None:
    honest = ElfBuilder(needed=("libc.so.6",), dynsyms=_HIDDEN, with_symtab=True).build()
    with_decoy = insert_bogus_section_before(honest, ".symtab", SHT_SYMTAB, same_name=True)
    decoy_and_forged = patch_section_header(
        with_decoy, ".symtab", "sh_type", SHT_PROGBITS, occurrence=2
    )
    ev, errors = _read(decoy_and_forged)
    assert ev.partial_analysis is True
    assert list(ev.partial_reasons) == [evidence.PARTIAL_ELF_SYMTAB_UNREAD]
    assert any(e.kind == ELF_PARSE_ERROR for e in errors)


def test_extended_section_numbering_is_not_mistaken_for_sectionless() -> None:
    """`e_shnum == 0` with a real `e_shoff` is the legal extended-numbering encoding --
    the true count lives in the first section's `sh_size` -- not `e_shoff == 0`, which
    is what actually means "no section header table". Confusing the two would treat a
    normal, if unusually large, object as though it had none at all.
    """
    honest = ElfBuilder(needed=("libc.so.6",), dynsyms=_HIDDEN).build()
    (real_shnum,) = struct.unpack_from("<H", honest, E_SHNUM_OFFSET[64])
    extended = patch_section_header(honest, "", "sh_size", real_shnum)
    extended = patch_header_field(extended, "e_shnum", 0)
    ev, errors = _read(extended)
    assert errors == ()
    assert ev.partial_analysis is False
    assert ev.needed == ("libc.so.6",)
    assert {m.name for m in ev.matched_symbols} == {"EVP_DigestInit_ex", "SSL_new"}


def test_a_malformed_section_found_by_type_still_degrades_normally() -> None:
    """A type-based lookup changes how a section is found, not what a corrupt one does.

    Renamed first, so the section is reachable only through `sh_type`, then its
    `sh_offset` is pushed past the object: a `BytesIO` seek out there does not raise,
    it just returns nothing to read, so this reaches the *existing* cross-check
    degrade path (`.dynstr` still holds names nothing read resolved to) rather than a
    raw exception -- the same shape `test_a_dynsym_size_that_stops_short_of_the_rows_
    is_not_a_clean_read` already covers for a lying `sh_size`. The point here is only
    that a type-based lookup does not change it.
    """
    honest = ElfBuilder(needed=("libc.so.6",), dynsyms=_HIDDEN).build()
    renamed = honest.replace(b".dynsym\x00", b".dynsyx\x00")
    corrupt = patch_section_header(renamed, ".dynsyx", "sh_offset", 1 << 30)
    ev, errors = _read(corrupt)
    assert ev.partial_analysis is True
    assert list(ev.partial_reasons) == [
        evidence.PARTIAL_ELF_DYNSYM_UNREAD,
        evidence.PARTIAL_SYMTAB_UNDERSTATES_ROWS,
    ]
    assert any(e.kind == ELF_PARSE_ERROR for e in errors)


def test_a_section_header_table_entirely_absent_falls_back_to_whole_file_strings() -> None:
    """`e_shoff == 0`: no section header table at all, which a loadable object may have.

    `.dynamic`, `.dynsym` and `.symtab` cannot be found by type or by name when there
    is no section list to search, so every field derived from one is genuinely empty
    rather than merely unread -- but the strings pass still runs, over the whole file,
    the same fallback a header that would not parse already gets. Worse than that
    fallback used to be silent: no error, no `partial_analysis`, and the string pass
    itself found nothing because it had no section list to filter to either.
    """
    built = ElfBuilder(rodata=b"OpenSSL 3.0.14 4 Jun 2024").build()
    sectionless = patch_header_field(patch_header_field(built, "e_shnum", 0), "e_shoff", 0)
    ev, errors = _read(sectionless)
    assert ev.partial_analysis is True
    assert list(ev.partial_reasons) == [evidence.PARTIAL_ELF_SECTION_TABLE_ABSENT]
    assert len(errors) == 1
    assert errors[0].kind == ELF_PARSE_ERROR
    assert ev.needed == ()
    assert ev.matched_symbols == ()
    assert ev.matched_strings == (
        evidence.StringMatch(group="openssl_banner", value="OpenSSL 3.0.14 4 Jun 2024"),
    )


def test_a_renamed_dynsym_no_longer_reads_completely_clean() -> None:
    """The reproduction end to end: on `main` this used to classify as clean.

    `needed` and `matched_symbols` come back right on their own (proved above); this
    pins that the verdict downstream of them changes too, since a rule keys on the
    symbol group, not merely on the field being non-empty.
    """
    ruleset = load_ruleset()
    honest = ElfBuilder(needed=("libc.so.6",), dynsyms=_HIDDEN).build()
    renamed = honest.replace(b".dynsym\x00", b".dynsyx\x00")
    binary_ev, _ = _read(renamed, path="pkg/_ext.so")
    wheel_evidence = evidence.Evidence(
        filename="demo-1.0-linux_x86_64.whl",
        sha256="0" * 64,
        size_bytes=1,
        artifacts=evidence.ArtifactInventory(),
        binaries=(binary_ev,),
    )
    linkage = resolve_linkage(ruleset, wheel_evidence)
    findings = apply_rules(ruleset, wheel_evidence, linkage)
    verdict = classify(ruleset, findings, linkage)
    assert verdict.headline != NO_CRYPTO_DETECTED


# --- sh_link is only trusted when it corroborates .dynamic's own DT_STRTAB (#56 rd 4)
#
# The dynamic linker resolves `.dynamic` and `.dynsym`'s names through `DT_STRTAB`
# from `PT_DYNAMIC`, never through any section's `sh_link`. A decoy `SHT_STRTAB`
# section -- correctly typed, so pyelftools accepts it without complaint -- planted
# purely to be read through `sh_link` used to be trusted outright: an all-NUL decoy
# resolves every symbol name to `""`, which is not flagged unresolved, so a real
# `libcrypto.so.3` read completely clean instead of carrying its 64 crypto symbols.
# `.dynamic`'s own `sh_link` has the same hole and is worse: it can fabricate a
# `DT_NEEDED` entry the object never declared, not merely erase one.


def test_a_decoy_string_table_erases_dynsym_symbols_without_corroboration() -> None:
    honest = ElfBuilder(needed=("libc.so.6",), dynsyms=_HIDDEN).build()
    with_decoy, decoy_index = append_strtab_decoy(honest, b"\x00" * 64)
    repointed = patch_section_header(with_decoy, ".dynsym", "sh_link", decoy_index)
    ev, errors = _read(repointed)
    assert ev.partial_analysis is True
    assert evidence.PARTIAL_ELF_DYNSYM_UNREAD in ev.partial_reasons
    assert ev.matched_symbols == ()
    assert any(e.kind == ELF_PARSE_ERROR for e in errors)
    # `.dynamic`'s own sh_link is untouched, so `needed` still reads correctly: only
    # `.dynsym`'s evidence is what this shape costs.
    assert ev.needed == ("libc.so.6",)


def test_a_decoy_string_table_erases_dynamic_tags_without_corroboration() -> None:
    honest = ElfBuilder(needed=("libc.so.6",), dynsyms=_HIDDEN).build()
    with_decoy, decoy_index = append_strtab_decoy(honest, b"\x00" * 64)
    repointed = patch_section_header(with_decoy, ".dynamic", "sh_link", decoy_index)
    ev, errors = _read(repointed)
    assert ev.partial_analysis is True
    assert evidence.PARTIAL_ELF_DYNAMIC_UNREAD in ev.partial_reasons
    assert ev.needed == ()
    assert ev.soname is None
    assert any(e.kind == ELF_PARSE_ERROR for e in errors)
    # `.dynsym`'s own sh_link is untouched and DT_STRTAB's `d_ptr` (read directly off
    # the tag, not through .dynamic's sh_link) still names the real .dynstr, so the
    # symbol split is unaffected by this attack on .dynamic alone.
    assert {m.name for m in ev.matched_symbols} == {"EVP_DigestInit_ex", "SSL_new"}


def test_a_decoy_string_table_cannot_fabricate_a_needed_dependency() -> None:
    """`.dynamic`'s sh_link hole is worse than `.dynsym`'s: it can invent evidence.

    `libz.so.1` is the real dependency; its `DT_NEEDED` tag's string-table offset is
    fixed by the builder. The decoy spells `libc.so.6` -- a name the object never
    declares -- at that exact offset, so a reader that trusted the decoy would report
    a dependency that does not exist. `.dynamic`'s reads must fail closed instead.
    """
    real_needed = "libz.so.1"
    fabricated = "libc.so.6"
    assert len(real_needed) == len(fabricated)  # same offset lines up in the decoy
    honest = ElfBuilder(needed=(real_needed,), dynsyms=_HIDDEN).build()
    decoy_dynstr = b"\x00" + fabricated.encode("ascii") + b"\x00"
    with_decoy, decoy_index = append_strtab_decoy(honest, decoy_dynstr)
    repointed = patch_section_header(with_decoy, ".dynamic", "sh_link", decoy_index)
    ev, errors = _read(repointed)
    assert ev.partial_analysis is True
    assert evidence.PARTIAL_ELF_DYNAMIC_UNREAD in ev.partial_reasons
    assert fabricated not in ev.needed
    assert ev.needed == ()
    assert any(e.kind == ELF_PARSE_ERROR for e in errors)


# --- .symtab matching, only when .dynsym is genuinely absent (#117) ----------------


def test_a_relocatable_object_matches_a_defined_symtab_crypto_symbol() -> None:
    """The reproduction #117 was filed over: a `.o` -- a relocatable object, the shape
    every member of a real `.a`/`.lib` static archive has -- normally carries no
    `.dynsym` at all, only `.symtab`. A genuine definition there was invisible to
    symbol-based detection before this.
    """
    honest = ElfBuilder(
        e_type=ET_REL,
        dynsyms=(),
        with_symtab=True,
        symtab_syms=(DynSym("EVP_DigestInit_ex", defined=True),),
    ).build()
    ev, errors = _read(honest)
    assert errors == ()
    assert ev.partial_analysis is False
    assert list(ev.matched_symbols) == [
        evidence.SymbolMatch("EVP_DigestInit_ex", "openssl", evidence.BINDING_DEFINED)
    ]


def test_a_relocatable_object_matches_an_imported_symtab_crypto_symbol() -> None:
    """The other binding: an external reference in `.symtab` is `SHN_UNDEF`, the
    identical bit `.dynsym`'s own imported/defined split already reads."""
    honest = ElfBuilder(
        e_type=ET_REL,
        dynsyms=(),
        with_symtab=True,
        symtab_syms=(DynSym("EVP_DigestInit_ex", defined=False),),
    ).build()
    ev, errors = _read(honest)
    assert errors == ()
    assert list(ev.matched_symbols) == [
        evidence.SymbolMatch("EVP_DigestInit_ex", "openssl", evidence.BINDING_IMPORTED)
    ]


def test_a_local_definition_in_symtab_is_read_when_dynsym_is_present() -> None:
    """A statically linked copy whose symbols a version script kept local.

    #117 gated `.symtab` matching on `.dynsym` being genuinely absent, which made the
    existing corpus unaffected by construction -- and left the case this tool exists
    for unread: cryptography 50.0.1 carries 776 `EVP_*` definitions, every one local
    in `.symtab` and none in `.dynsym`, beside a `.dynsym` that exports only
    `PyInit__rust`. A definition nobody else can satisfy is what a static copy *is*,
    so it is read now, and the corpus claim is carried by measurement instead (#127).
    """
    honest = ElfBuilder(
        needed=("libc.so.6",),
        dynsyms=(DynSym("some_unrelated_export", defined=True),),
        with_symtab=True,
        symtab_syms=(DynSym("EVP_DigestInit_ex", defined=True),),
    ).build()
    ev, errors = _read(honest)
    assert errors == ()
    assert list(ev.matched_symbols) == [
        evidence.SymbolMatch("EVP_DigestInit_ex", "openssl", evidence.BINDING_DEFINED)
    ]
    assert ev.partial_analysis is False


def test_an_import_in_symtab_is_not_read_when_dynsym_is_present() -> None:
    """Only definitions cross the gate #117 put up, and this is the half that stays.

    A dynamically linked object must declare every import in `.dynsym` to link at all,
    so `.symtab` can say nothing new about imports; taking them would record the same
    dependency twice under a second provenance, and would let an undefined entry
    planted in a debug table read as a dependency the object does not have.
    """
    honest = ElfBuilder(
        needed=("libc.so.6",),
        dynsyms=(DynSym("some_unrelated_export", defined=True),),
        with_symtab=True,
        symtab_syms=(DynSym("EVP_DigestInit_ex", defined=False),),
    ).build()
    ev, errors = _read(honest)
    assert errors == ()
    assert ev.matched_symbols == ()


def test_an_ambiguous_dynsym_does_not_fall_back_to_symtab_matching() -> None:
    """`dynsym is None` is also true for an ambiguous `.dynsym` -- but the object is
    not claiming to have none: this reader cannot trust which of several candidates is
    real, which is not the same fact a genuinely relocatable object's absence is.
    Falling back to `.symtab` here would read a crafted object's debug table as though
    it were a relocatable object's only symbol table.
    """
    honest = ElfBuilder(
        needed=("libc.so.6",),
        dynsyms=(DynSym("some_unrelated_export", defined=True),),
        with_symtab=True,
        symtab_syms=(DynSym("EVP_DigestInit_ex", defined=True),),
    ).build()
    ev, errors = _read(append_duplicate_dynsym_section(honest))
    assert ev.matched_symbols == ()
    assert list(ev.partial_reasons) == [evidence.PARTIAL_ELF_SECTION_TYPE_AMBIGUOUS]


def test_a_forged_dynsym_type_does_not_fall_back_to_symtab_matching() -> None:
    """The other shape `dynsym is None` does not mean genuinely absent: a section
    still named `.dynsym` whose `sh_type` was forged away, which exists and cannot be
    trusted rather than being absent."""
    honest = ElfBuilder(
        needed=("libc.so.6",),
        dynsyms=(DynSym("some_unrelated_export", defined=True),),
        with_symtab=True,
        symtab_syms=(DynSym("EVP_DigestInit_ex", defined=True),),
    ).build()
    forged = patch_section_header(honest, ".dynsym", "sh_type", SHT_PROGBITS)
    ev, errors = _read(forged)
    assert ev.matched_symbols == ()
    assert list(ev.partial_reasons) == [evidence.PARTIAL_ELF_DYNSYM_UNREAD]


def test_a_symtab_size_that_stops_short_of_the_rows_is_not_a_clean_read() -> None:
    """The `.symtab` mirror of `.dynsym`'s own understated-rows check: `.strtab` still
    holds every name, which is what gives a truncated `.symtab` away."""
    honest = ElfBuilder(e_type=ET_REL, dynsyms=(), with_symtab=True, symtab_syms=_HIDDEN).build()
    ev, errors = _read(patch_section_header(honest, ".symtab", "sh_size", 24))
    assert ev.matched_symbols == ()
    assert ev.partial_analysis is True
    assert list(ev.partial_reasons) == ["elf_symtab_unread", "symtab_understates_rows"]
    assert [e.message for e in errors] == [
        ".symtab declares fewer entries than .strtab holds names for"
    ]


def test_a_strtab_that_does_not_hold_the_names_symtab_points_at_is_not_a_clean_read() -> None:
    """The `.symtab` mirror of the `.dynstr`-shrink check: every row stays,
    `symbol_counts.symtab` is unaffected, and pyelftools reads the table without
    complaint -- the names simply are not reachable any more.
    """
    honest = ElfBuilder(e_type=ET_REL, dynsyms=(), with_symtab=True, symtab_syms=_HIDDEN).build()
    for size in (0, 8, 16):
        ev, errors = _read(patch_section_header(honest, ".strtab", "sh_size", size))
        assert ev.symtab_count == 4, size
        assert ev.matched_symbols == (), size
        assert ev.partial_analysis is True, size
        assert [e.message for e in errors] == [".symtab names strings .strtab does not hold"]


def test_a_decoy_strtab_repointed_from_symtab_does_not_read_completely_clean() -> None:
    """The severe finding two independent adversarial reviews reproduced: `.symtab`
    has no `.dynsym`-style address authority to corroborate `sh_link` against, so a
    `.symtab` repointed at a decoy, all-NUL `SHT_STRTAB` resolved every name to `""`
    -- not unresolved, resolved -- and the real `.strtab`, sitting untouched elsewhere
    in the section table, was never asked. A crafted object could hide a genuine
    `EVP_DigestInit_ex` definition and read completely clean: `matched_symbols=()`,
    `partial_analysis=False`, no error. `_any_strtab_holds_a_name_not_read` closes it
    by asking every `SHT_STRTAB` section, not just the one `sh_link` names, so the
    real `.strtab` still gets to contradict the decoy.
    """
    honest = ElfBuilder(
        e_type=ET_REL,
        dynsyms=(),
        with_symtab=True,
        symtab_syms=(DynSym("EVP_DigestInit_ex", defined=True),),
    ).build()
    decoyed, decoy_index = append_strtab_decoy(honest, b"\x00" * 512)
    attacked = patch_section_header(decoyed, ".symtab", "sh_link", decoy_index)
    ev, errors = _read(attacked)

    assert ev.matched_symbols == (), "the decoy hid a real crypto symbol definition"
    assert ev.partial_analysis is True
    assert list(ev.partial_reasons) == ["elf_symtab_unread", "symtab_understates_rows"]
    assert [e.message for e in errors] == [
        ".symtab declares fewer entries than .strtab holds names for"
    ]


def test_a_small_decoy_beside_an_over_budget_real_strtab_is_still_not_a_clean_read() -> None:
    """A second construction of the same attack, found verifying the fix above: a
    *small* decoy `.symtab` is happy to point at (so the primary read is clean),
    sitting beside the genuine `.strtab` with its own declared `sh_size` inflated past
    the budget. An earlier version of `_any_strtab_holds_a_name_not_read` silently
    skipped a section it could not fully read rather than treating that as suspicious,
    so the one section that could have contradicted the decoy was never actually
    checked. Skipping must count as a hit, not nothing to worry about.
    """
    from wheel_crypto_scan.binfmt.strings import MAX_STRINGS_BYTES

    honest = ElfBuilder(
        e_type=ET_REL,
        dynsyms=(),
        with_symtab=True,
        symtab_syms=(DynSym("EVP_DigestInit_ex", defined=True),),
    ).build()
    decoyed, decoy_index = append_strtab_decoy(honest, b"\x00" * 64)
    attacked = patch_section_header(decoyed, ".symtab", "sh_link", decoy_index)
    inflated = patch_section_header(attacked, ".strtab", "sh_size", MAX_STRINGS_BYTES + 1000)
    ev, errors = _read(inflated)

    assert ev.matched_symbols == (), "the decoy hid a real crypto symbol definition"
    assert ev.partial_analysis is True
    assert list(ev.partial_reasons) == ["elf_symtab_unread", "symtab_understates_rows"]
    assert [e.message for e in errors] == [
        ".symtab declares fewer entries than .strtab holds names for"
    ]


def test_an_stt_file_pseudo_symbol_does_not_match_by_coincidence_of_its_name() -> None:
    """`.symtab` carries symbol types `.dynsym` never does. A source-file pseudo-symbol
    named `EVP_md5.c` -- ordinary in a real relocatable object -- must not match the
    `openssl` group by nothing but a filename's coincidence with the code it
    implements. Also must not be reported as an unclaimed crypto name the object
    understates: it was read and accounted for, only excluded from evidence by type.
    """
    file_symbol = DynSym("EVP_md5.c", defined=True, info=(STB_GLOBAL << 4) | 4)  # STT_FILE
    honest = ElfBuilder(
        e_type=ET_REL, dynsyms=(), with_symtab=True, symtab_syms=(file_symbol,)
    ).build()
    ev, errors = _read(honest)

    assert ev.matched_symbols == ()
    assert ev.partial_analysis is False
    assert errors == ()


def test_an_stt_section_pseudo_symbol_is_also_excluded_from_matching() -> None:
    section_symbol = DynSym("crypto_box_section", defined=True, info=(STB_GLOBAL << 4) | 3)
    honest = ElfBuilder(
        e_type=ET_REL, dynsyms=(), with_symtab=True, symtab_syms=(section_symbol,)
    ).build()
    ev, errors = _read(honest)

    assert ev.matched_symbols == ()
    assert ev.partial_analysis is False
    assert errors == ()


def test_a_dynsym_whose_own_section_header_failed_does_not_fall_back_to_symtab_matching() -> None:
    """A fourth shape `dynsym is None` does not mean genuinely absent: a `.dynsym`
    section header that fails to read at all -- an `sh_link` field pointing past the
    section count, so `elf.get_section` itself raises -- never reaches `sections`, so
    neither the ambiguity check nor the type-mismatch check (which both scan the same
    already-truncated list) ever see it. This is an ordinary shared object, not a
    relocatable one, and must not have its `.symtab` matched just because its
    `.dynsym` could not be read.
    """
    honest = ElfBuilder(
        needed=("libc.so.6",),
        dynsyms=(DynSym("some_unrelated_export", defined=True),),
        with_symtab=True,
        symtab_syms=(DynSym("EVP_DigestInit_ex", defined=True),),
    ).build()
    attacked = patch_section_header(honest, ".dynsym", "sh_link", 0xFFFFFF)
    ev, errors = _read(attacked)

    assert ev.matched_symbols == ()
    assert evidence.PARTIAL_ELF_SECTIONS_UNREAD in ev.partial_reasons
