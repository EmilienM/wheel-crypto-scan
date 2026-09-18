"""Go buildinfo parsing and BoringCrypto/stock-crypto marker detection."""

from __future__ import annotations

from wheel_crypto_scan.binfmt.golang import build_go_info, parse_go_buildinfo
from wheel_crypto_scan.ruleset import load_ruleset

_PATTERNS = load_ruleset().compile_patterns()

_MAGIC = b"\xff Go buildinf:"


def _uvarint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _buildinfo(version: str, *, flags: int = 0x2, ptrsize: int = 8) -> bytes:
    header = _MAGIC + bytes([ptrsize, flags]) + b"\x00" * 16
    assert len(header) == 32
    return header + _uvarint(len(version)) + version.encode("ascii")


def test_parses_a_go_118_plus_inline_version() -> None:
    assert parse_go_buildinfo(_buildinfo("go1.22.3")) == "go1.22.3"


def test_no_magic_returns_none() -> None:
    assert parse_go_buildinfo(b"not a go buildinfo section at all, just filler") is None


def test_too_short_returns_none() -> None:
    assert parse_go_buildinfo(_MAGIC + b"\x08\x02") is None


def test_pre_118_pointer_layout_returns_none_rather_than_guess() -> None:
    # flags without the inline-string bit set: the pre-1.18 pointer-based layout,
    # which this reader deliberately does not attempt to resolve.
    data = _buildinfo("go1.22.3", flags=0x0)
    assert parse_go_buildinfo(data) is None


def test_corrupt_length_prefix_returns_none_not_an_exception() -> None:
    header = _MAGIC + bytes([8, 0x2]) + b"\x00" * 16
    # A length prefix claiming far more bytes than actually follow.
    corrupt = header + _uvarint(9999) + b"go1"
    assert parse_go_buildinfo(corrupt) is None


def test_non_version_looking_string_returns_none() -> None:
    data = _buildinfo("not-a-go-version")
    assert parse_go_buildinfo(data) is None


def test_build_go_info_none_when_nothing_present() -> None:
    assert build_go_info(None, "nothing to see here", _PATTERNS) is None


def test_build_go_info_reports_version_and_boring_marker() -> None:
    text = "junk\ncrypto/internal/boring\nmore junk"
    info = build_go_info(_buildinfo("go1.22.3"), text, _PATTERNS)
    assert info is not None
    assert info.go_version == "go1.22.3"
    assert info.boring_crypto is True
    assert "go_boring" in info.markers


def test_build_go_info_stock_crypto_marker_is_not_boring() -> None:
    text = "crypto/sha256.\nmore junk"
    info = build_go_info(None, text, _PATTERNS)
    assert info is not None
    assert info.go_version is None
    assert info.boring_crypto is False
    assert info.markers == ("go_stock_crypto",)


def test_build_go_info_present_buildinfo_with_unparseable_version_still_reports() -> None:
    # A buildinfo section that exists but does not parse confidently still means
    # this is a Go binary; the version is simply unknown, not fabricated.
    info = build_go_info(_buildinfo("go1.22.3", flags=0x0), "no markers here", _PATTERNS)
    assert info is not None
    assert info.go_version is None
    assert info.markers == ()
