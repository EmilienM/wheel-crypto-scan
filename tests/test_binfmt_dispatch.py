"""`read_binary`: format sniffing plus dispatch, including the strings-only fallback."""

from __future__ import annotations

import io

from helpers.elfbuilder import DynSym, ElfBuilder, MachOBuilder, PEBuilder, PEImport
from wheel_crypto_scan import evidence
from wheel_crypto_scan.binfmt import read_binary
from wheel_crypto_scan.errors import PE_PARSE_ERROR
from wheel_crypto_scan.ruleset import load_ruleset

PATTERNS = load_ruleset().compile_patterns().binary


def _read(data: bytes, path: str = "obj", *, vendored: bool = False):
    return read_binary(io.BytesIO(data), path, PATTERNS, vendored=vendored)


def test_dispatches_elf_to_the_elf_reader() -> None:
    data = ElfBuilder(dynsyms=(DynSym("EVP_DigestInit_ex", defined=False),)).build()
    ev, errors = _read(data, path="mod.so")
    assert errors == ()
    assert ev.format == evidence.FORMAT_ELF
    assert ev.partial_analysis is False
    assert ev.matched_symbols != ()


def test_dispatches_macho_to_the_macho_reader() -> None:
    data = MachOBuilder(id_dylib="libfoo.dylib").build()
    ev, errors = _read(data, path="libfoo.dylib")
    assert errors == ()
    assert ev.format == evidence.FORMAT_MACHO
    assert ev.soname == "libfoo.dylib"


def test_dispatches_pe_to_the_pe_reader() -> None:
    data = PEBuilder(
        imports=(PEImport("libcrypto-3-x64.dll", names=("EVP_DigestInit_ex",)),),
        dll_name="_ext.pyd",
    ).build()
    ev, errors = _read(data, path="mod.pyd")
    assert errors == ()
    assert ev.format == evidence.FORMAT_PE
    assert ev.needed == ("libcrypto-3-x64.dll",)
    assert ev.soname == "_ext.pyd"
    assert ev.partial_analysis is False


def test_a_dos_stub_with_no_pe_header_keeps_its_strings() -> None:
    """Plenty of files start with MZ. Failing to parse one must not cost its strings."""
    data = b"MZ" + b"\x00" * 60 + b"This program cannot be run in DOS mode" + b"OpenSSL 3."
    ev, errors = _read(data, path="mod.pyd")
    assert [error.kind for error in errors] == [PE_PARSE_ERROR]
    assert ev.format == evidence.FORMAT_PE
    assert ev.partial_analysis is True
    assert ev.matched_strings != ()


def test_unknown_format_gets_a_populated_strings_only_evidence() -> None:
    data = b"\x00\x01\x02\x03" + b"crypto/internal/boring somewhere in here"
    ev, errors = _read(data, path="mod.bin")
    assert errors == ()
    assert ev.format == evidence.FORMAT_UNKNOWN
    assert ev.partial_analysis is True


def test_a_pe_that_will_not_parse_still_extracts_rust_crates() -> None:
    path = "cargo/registry/src/index.crates.io-x/ring-0.17.8/src/lib.rs"
    data = b"MZ" + b"\x00" * 20 + path.encode("ascii")
    ev, _ = _read(data, path="mod.pyd")
    assert ev.rust_crates == (evidence.RustCrate(name="ring", version="0.17.8"),)


def test_strings_only_path_still_extracts_rust_crates() -> None:
    path = "cargo/registry/src/index.crates.io-x/ring-0.17.8/src/lib.rs"
    data = b"\x00\x01\x02\x03" + path.encode("ascii")
    ev, _ = _read(data, path="mod.bin")
    assert ev.rust_crates == (evidence.RustCrate(name="ring", version="0.17.8"),)


def test_vendored_flag_passes_through_every_branch() -> None:
    elf_data = ElfBuilder().build()
    macho_data = MachOBuilder(id_dylib="libfoo.dylib").build()
    pe_data = PEBuilder(dll_name="_ext.pyd").build()
    unknown_data = b"\x00\x01\x02\x03"
    for data in (elf_data, macho_data, pe_data, unknown_data):
        ev, _ = _read(data, vendored=True)
        assert ev.vendored_path is True
