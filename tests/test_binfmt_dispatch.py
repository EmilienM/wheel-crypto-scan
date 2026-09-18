"""`read_binary`: format sniffing plus dispatch, including the strings-only fallback."""

from __future__ import annotations

import io

from helpers.binfmt import DynSym, ElfBuilder, MachOBuilder, PEBuilder, PEImport
from wheel_crypto_scan import binfmt, evidence
from wheel_crypto_scan.binfmt import _READERS, read_binary
from wheel_crypto_scan.binfmt.detect import SNIFF_BYTES, detect_format
from wheel_crypto_scan.binfmt.strings import MAX_STRINGS_BYTES
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


def test_every_table_entry_is_reachable_from_detection() -> None:
    """A reader nothing can sniff its way to is a reader that never runs."""
    assert set(_READERS) <= {
        evidence.FORMAT_ELF,
        evidence.FORMAT_MACHO,
        evidence.FORMAT_PE,
        evidence.FORMAT_UNKNOWN,
    }
    for fmt, data in (
        (evidence.FORMAT_ELF, ElfBuilder().build()),
        (evidence.FORMAT_MACHO, MachOBuilder().build()),
        (evidence.FORMAT_PE, PEBuilder(dll_name="_ext.pyd").build()),
    ):
        assert fmt in _READERS
        assert detect_format(data[:SNIFF_BYTES]) == fmt
    # The fallback is reached by missing the table, so `unknown` must never be in it.
    assert evidence.FORMAT_UNKNOWN not in _READERS


def test_dispatch_goes_through_the_table(monkeypatch) -> None:
    """Swapping a table entry swaps the reader: the chain is gone, not just hidden."""
    called: dict[str, object] = {}

    def dummy_reader(stream, path, patterns, *, vendored, max_strings_bytes=1024):
        called["path"] = path
        called["vendored"] = vendored
        called["max_strings_bytes"] = max_strings_bytes
        return evidence.BinaryEvidence(path=path, format="stand_in", vendored_path=vendored), ()

    monkeypatch.setitem(_READERS, evidence.FORMAT_ELF, dummy_reader)
    ev, errors = _read(ElfBuilder().build(), path="custom.so", vendored=True)
    assert errors == ()
    assert ev.format == "stand_in"
    assert called == {"path": "custom.so", "vendored": True, "max_strings_bytes": MAX_STRINGS_BYTES}


def test_a_detected_format_with_no_reader_keeps_its_own_name(monkeypatch) -> None:
    """The fallback records what was sniffed, never a blanket `unknown`.

    Adding a format to `detect_format` is meant to be safe before its reader exists:
    the object still gets a strings pass, and its record still says which format it
    was. A fallback that defaulted the name would turn that into a mislabelled record
    and nothing would fail.
    """
    monkeypatch.setattr(binfmt, "detect_format", lambda head: "wasm")
    ev, errors = _read(b"\x00asm\x01\x00\x00\x00 OpenSSL 3.2.1 ", path="mod.wasm")
    assert errors == ()
    assert ev.format == "wasm"
    assert ev.partial_analysis is True
    assert ev.matched_strings != ()


def test_unsniffable_bytes_fall_back_as_unknown() -> None:
    ev, errors = _read(b"\x00\x01\x02\x03 OpenSSL 3.2.1 ", path="mystery.bin")
    assert errors == ()
    assert ev.format == evidence.FORMAT_UNKNOWN
    assert ev.partial_analysis is True
