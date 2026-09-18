"""Behaviour of `binfmt.macho.read_macho`.

Mach-O support is deliberately medium-depth (see the module docstring in
`binfmt.macho`): load commands only, no symbol table, `partial_analysis` always
True. These tests hold it to exactly that contract.
"""

from __future__ import annotations

import io

from helpers.elfbuilder import MachOBuilder, build_fat
from wheel_crypto_scan import evidence
from wheel_crypto_scan.binfmt.macho import read_macho
from wheel_crypto_scan.errors import MACHO_PARSE_ERROR
from wheel_crypto_scan.ruleset import load_ruleset

PATTERNS = load_ruleset().compile_patterns().binary


def _read(data: bytes, path: str = "libfoo.dylib", *, vendored: bool = False):
    return read_macho(io.BytesIO(data), path, PATTERNS, vendored=vendored)


def test_id_dylib_and_load_dylib_round_trip() -> None:
    data = MachOBuilder(
        id_dylib="@rpath/libfoo.dylib",
        load_dylibs=("/usr/lib/libcrypto.3.dylib", "/usr/lib/libSystem.B.dylib"),
    ).build()
    ev, errors = _read(data)
    assert errors == ()
    assert ev.soname == "@rpath/libfoo.dylib"
    assert ev.needed == ("/usr/lib/libSystem.B.dylib", "/usr/lib/libcrypto.3.dylib")
    assert ev.partial_analysis is True
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


def test_partial_analysis_is_always_true() -> None:
    data = MachOBuilder(id_dylib="libfoo.dylib").build()
    ev, _ = _read(data)
    assert ev.partial_analysis is True
    assert ev.matched_symbols == ()  # symbols are not implemented for Mach-O


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
    ).build()
    first, first_errors = _read(data)
    second, second_errors = _read(data)
    assert first == second
    assert first_errors == second_errors
