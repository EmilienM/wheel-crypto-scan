"""Format sniffing: ELF, Mach-O (thin/fat, both byte orders), PE and unknown."""

from __future__ import annotations

from wheel_crypto_scan import evidence
from wheel_crypto_scan.binfmt.detect import SNIFF_BYTES, detect_format


def test_sniff_bytes_is_small_and_sufficient() -> None:
    # Every magic this module recognises fits within SNIFF_BYTES.
    assert SNIFF_BYTES <= 8
    assert detect_format(b"\x7fELF"[:SNIFF_BYTES]) == evidence.FORMAT_ELF


def test_elf_magic() -> None:
    assert detect_format(b"\x7fELF\x02\x01\x01\x00") == evidence.FORMAT_ELF


def test_macho_thin_32_and_64_both_byte_orders() -> None:
    for magic in (
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
    ):
        assert detect_format(magic) == evidence.FORMAT_MACHO


def test_macho_fat_magic() -> None:
    assert detect_format(b"\xca\xfe\xba\xbe") == evidence.FORMAT_MACHO
    assert detect_format(b"\xbe\xba\xfe\xca") == evidence.FORMAT_MACHO


def test_pe_magic() -> None:
    assert detect_format(b"MZ\x90\x00") == evidence.FORMAT_PE


def test_unknown_format() -> None:
    assert detect_format(b"\x00\x01\x02\x03") == evidence.FORMAT_UNKNOWN


def test_short_head_is_unknown_not_a_crash() -> None:
    assert detect_format(b"") == evidence.FORMAT_UNKNOWN
    assert detect_format(b"M") == evidence.FORMAT_UNKNOWN
