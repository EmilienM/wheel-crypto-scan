"""Tests for Layer 2's member classification: `layers.binaries.is_binary_member`.

Deciding what is worth reading as a native object is a suffix check first, a vendor
path check second, and two "no dot in the name" fallbacks last. `.exe` used to fail
all four: wrong suffix, and the dot disqualified it from both fallbacks (#65). These
tests pin the suffix check directly, independently of any particular reader, and hold
the untouched routes (vendor paths, sniff directories, the executable bit, and every
other recognised suffix) to their exact prior behaviour.
"""

from __future__ import annotations

import pytest

from wheel_crypto_scan.layers.binaries import is_binary_member
from wheel_crypto_scan.ruleset import load_ruleset
from wheel_crypto_scan.wheelfile import MemberInfo

CONVENTIONS = load_ruleset().conventions

# A regular file, world-readable, no execute bit.
_MODE_FILE = 0o100644
# A regular file with the owner execute bit set.
_MODE_EXEC = 0o100755


def member(
    name: str, *, size: int = 128, mode: int = _MODE_FILE, is_symlink: bool = False
) -> MemberInfo:
    return MemberInfo(name=name, size=size, compressed_size=size, is_symlink=is_symlink, mode=mode)


# --------------------------------------------------------------------------
# #65: `.exe` is now a recognised suffix
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "pkg-1.0.data/scripts/openssl.exe",
        # Suffix matching is case-insensitive, like every other entry in
        # `_BINARY_SUFFIX`.
        "pkg-1.0.data/scripts/OPENSSL.EXE",
        "pkg-1.0.data/scripts/openssl.Exe",
        # The suffix alone is enough: no sniff directory, no vendor path, no
        # executable bit.
        "somewhere/random/tool.exe",
    ],
)
def test_an_exe_member_is_now_recognized(name: str) -> None:
    assert is_binary_member(member(name, mode=_MODE_FILE), CONVENTIONS) is True


def test_an_exe_member_below_the_sniff_floor_is_still_skipped() -> None:
    """The suffix check does not bypass the size floor every route already respects."""
    assert is_binary_member(member("tool.exe", size=8), CONVENTIONS) is False


def test_a_symlinked_exe_is_still_never_read_as_a_binary() -> None:
    assert is_binary_member(member("tool.exe", is_symlink=True), CONVENTIONS) is False


# --------------------------------------------------------------------------
# Regression: the suffixes `.exe` joins were already recognized, and stay recognized
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "pkg/_ext.pyd",
        "pkg/_ext.PYD",
        "pkg/libcrypto-3-x64.dll",
        "pkg/libcrypto-3-x64.DLL",
        "pkg/_ext.abi3.so",
        "pkg/libcrypto.so.3",
        # A versioned dylib, matched by `_VERSIONED_DYLIB` rather than `_BINARY_SUFFIX`.
        "pkg/libcrypto.3.dylib",
        "pkg/libcrypto.dylib",
    ],
)
def test_every_previously_recognized_suffix_is_unchanged(name: str) -> None:
    assert is_binary_member(member(name, mode=_MODE_FILE), CONVENTIONS) is True


@pytest.mark.parametrize(
    "name",
    [
        "pkg-1.0.data/scripts/README.txt",
        "pkg/manifest.json",
        "pkg/module.py",
    ],
)
def test_an_unrelated_extension_is_still_not_a_binary_member(name: str) -> None:
    """A regression guard for suffix matching in general, not just `.exe`.

    Each of these sits in a sniff directory or would otherwise pass the "no dot"
    fallbacks if the dot in its own name were ignored the way `.exe`'s used to be.
    """
    assert is_binary_member(member(name, mode=_MODE_FILE), CONVENTIONS) is False


def test_a_suffixless_sniff_directory_member_is_unaffected() -> None:
    """The route `.exe` used to be locked out of still works for what it always covered."""
    name = "pkg-1.0.data/scripts/openssl"
    assert is_binary_member(member(name, mode=_MODE_FILE), CONVENTIONS) is True


def test_an_executable_bit_suffixless_member_is_unaffected() -> None:
    assert is_binary_member(member("somewhere/tool", mode=_MODE_EXEC), CONVENTIONS) is True
