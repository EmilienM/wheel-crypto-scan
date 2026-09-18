"""`read_binary`: format sniffing plus dispatch, including the strings-only fallback."""

from __future__ import annotations

import inspect
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
    assert ev.partial_reasons == ("strings_only",)


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


def test_every_registered_format_is_one_detection_can_return() -> None:
    """A reader nothing can sniff its way to is a reader that never runs.

    The set of known formats is derived rather than spelled out, so registering a
    fourth format stays the one-line change #16 was about: a typo'd key still fails,
    a real new format does not.
    """
    known = {value for name, value in vars(evidence).items() if name.startswith("FORMAT_")}
    assert set(_READERS) <= known - {evidence.FORMAT_UNKNOWN}
    # The fallback is reached by missing the table, so `unknown` must never be in it.
    assert evidence.FORMAT_UNKNOWN not in _READERS
    for fmt, data in (
        (evidence.FORMAT_ELF, ElfBuilder().build()),
        (evidence.FORMAT_MACHO, MachOBuilder().build()),
        (evidence.FORMAT_PE, PEBuilder(dll_name="_ext.pyd").build()),
    ):
        assert fmt in _READERS
        assert detect_format(data[:SNIFF_BYTES]) == fmt


def test_every_registered_reader_has_the_dispatch_signature() -> None:
    """Nothing type-checks this repo, so the `_Reader` protocol is asserted here.

    A reader registered with a drifted signature raises only when a wheel of that
    format is scanned, and `layers.binaries` catches it as one more unreadable object.
    The run survives and says nothing loud, which is the worst possible way to find out.
    """
    for fmt, reader in _READERS.items():
        parameters = inspect.signature(reader).parameters
        assert list(parameters) == [
            "stream",
            "path",
            "patterns",
            "vendored",
            "max_strings_bytes",
        ], fmt
        assert parameters["vendored"].kind is inspect.Parameter.KEYWORD_ONLY, fmt
        assert parameters["max_strings_bytes"].kind is inspect.Parameter.KEYWORD_ONLY, fmt


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


def test_a_callers_max_strings_bytes_reaches_both_paths() -> None:
    """Dispatch forwards the caller's bound, rather than letting a default stand in."""
    banner = b"OpenSSL 3.2.1 30 Jan 2024"
    for data in (ElfBuilder(rodata=banner).build(), b"\x00\x01\x02\x03" + banner):
        stream = io.BytesIO(data)
        ev, _ = read_binary(stream, "obj", PATTERNS, vendored=False, max_strings_bytes=8)
        assert ev.strings_truncated is True
        assert ev.matched_strings == ()


def test_a_detected_format_with_no_reader_keeps_its_own_name(monkeypatch) -> None:
    """The fallback records what was sniffed, never a blanket `unknown`.

    Adding a format to `detect_format` is meant to be safe before its reader exists:
    the object still gets a strings pass, and its record still says which format it
    was. A fallback that defaulted the name would put the wrong format into the record,
    into `engine`'s partial-read finding subject and into its evidence line, and
    nothing would fail. The name here is one no reader will ever be registered for, so
    this test cannot be defeated by someone taking #16 up on its offer.
    """
    monkeypatch.setattr(binfmt, "detect_format", lambda head: "format-with-no-reader")
    ev, errors = _read(b"\x00\x01\x02\x03 OpenSSL 3.2.1 30 Jan 2024 ", path="mod.bin")
    assert errors == ()
    assert ev.format == "format-with-no-reader"
    assert ev.partial_analysis is True
    assert ev.matched_strings != ()


def test_unsniffable_bytes_fall_back_as_unknown() -> None:
    ev, errors = _read(b"\x00\x01\x02\x03 OpenSSL 3.2.1 30 Jan 2024 ", path="mystery.bin")
    assert errors == ()
    assert ev.format == evidence.FORMAT_UNKNOWN
    assert ev.partial_analysis is True
