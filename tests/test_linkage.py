"""How the tool decides whether a wheel uses the system OpenSSL or carries its own.

This is the question the whole tool exists to answer, so these tests are written
against hand-built evidence rather than against real wheels: they pin the decision
itself, independently of whether the ELF reader can see a given field.
"""

from __future__ import annotations

import pytest

from wheel_crypto_scan.evidence import (
    BINDING_DEFINED,
    BINDING_IMPORTED,
    FORMAT_ELF,
    FORMAT_PE,
    STAGE_BINARY,
    ArtifactInventory,
    BinaryEvidence,
    Evidence,
    RustCrate,
    ScanError,
    StringMatch,
    SymbolMatch,
)
from wheel_crypto_scan.linkage import (
    LINKAGE_BUNDLED,
    LINKAGE_MIXED,
    LINKAGE_NONE,
    LINKAGE_STATIC,
    LINKAGE_SYSTEM,
    LINKAGE_UNKNOWN,
    resolve_linkage,
)
from wheel_crypto_scan.ruleset import load_ruleset

OPENSSL_BANNER = StringMatch(group="openssl_banner", value="OpenSSL 3.0.14 4 Jun 2024")


@pytest.fixture(scope="module")
def ruleset():
    return load_ruleset()


def binary(path: str, **kwargs) -> BinaryEvidence:
    kwargs.setdefault("format", FORMAT_ELF)
    return BinaryEvidence(path=path, **kwargs)


def wheel(*binaries: BinaryEvidence, errors: tuple[ScanError, ...] = ()) -> Evidence:
    return Evidence(
        filename="demo-1.0-py3-none-any.whl",
        sha256="0" * 64,
        size_bytes=1,
        artifacts=ArtifactInventory(),
        binaries=binaries,
        errors=errors,
    )


# --- the acceptance pair ----------------------------------------------------


def test_a_wheel_linking_the_system_openssl_is_system(ruleset) -> None:
    """A distro build: it resolves to whatever OpenSSL the host provides."""
    evidence = wheel(
        binary(
            "cryptography/hazmat/bindings/_openssl.abi3.so",
            needed=("libcrypto.so.3", "libc.so.6"),
            matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_IMPORTED),),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_SYSTEM


@pytest.mark.parametrize(
    "dll",
    [
        "libcrypto-3-x64.dll",
        "libcrypto-3.dll",
        "libcrypto-1_1-x64.dll",
        "libcrypto-3-arm64.dll",
        # A version this reader has never heard of resolves too, which is the point of
        # reducing the name rather than listing the spellings.
        "libcrypto-4-x64.dll",
        # Windows file names are case-insensitive and an import carries whatever case
        # the linker wrote.
        "LIBCRYPTO-3-X64.dll",
        "libcrypto-3-x64.DLL",
        # The OpenSSL 1.0.2 era name: a different name, not a decorated one, so this
        # one is in the ruleset rather than reduced by a convention.
        "libeay32.dll",
    ],
)
def test_a_windows_extension_depending_on_openssl_is_system(ruleset, dll: str) -> None:
    """OpenSSL's Windows file names carry the version and the architecture.

    `[conventions]` reduces that decoration before the library table is consulted.
    Without it a `.pyd` that plainly depends on OpenSSL resolves to no library at all,
    and the wheel reads as having no crypto in it rather than as depending on the
    host's.
    """
    evidence = wheel(
        binary(
            "pkg/_ext.pyd",
            format=FORMAT_PE,
            needed=(dll, "python312.dll"),
            matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_IMPORTED),),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_SYSTEM


@pytest.mark.parametrize(
    ("dll", "library"),
    [
        ("libgnutls-30.dll", "gnutls"),
        ("libgcrypt-20.dll", "libgcrypt"),
        ("libnettle-8.dll", "nettle"),
        ("libhogweed-6.dll", "nettle"),
        ("libsodium-26.dll", "libsodium"),
    ],
)
def test_the_other_crypto_libraries_resolve_on_windows_too(ruleset, dll: str, library: str) -> None:
    """MSYS2 and conda spell every one of them this way, not just OpenSSL.

    Reducing the name in `[conventions]` is what makes this hold for the whole table.
    Enumerating spellings on the openssl entry would have fixed one library out of
    thirteen and left the rest reporting a dependency the resolver cannot see.
    """
    evidence = wheel(binary("pkg/_ext.pyd", format=FORMAT_PE, needed=(dll, "python312.dll")))
    assert resolve_linkage(ruleset, evidence)[library] == LINKAGE_SYSTEM


def test_a_windows_extension_with_a_hash_renamed_dll_is_bundled(ruleset) -> None:
    """delvewheel appends the hash after the whole name, decoration included.

    It is the Windows counterpart of auditwheel and delocate; neither of those runs
    on Windows, so neither produces this name.
    """
    evidence = wheel(
        binary("pkg/_ext.pyd", format=FORMAT_PE, needed=("libcrypto-3-x64-a1b2c3d4.dll",))
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_BUNDLED


def test_a_wheel_shipping_its_own_openssl_is_bundled(ruleset) -> None:
    """The PyPI manylinux build: auditwheel copied libcrypto in and renamed it."""
    evidence = wheel(
        binary(
            "cryptography/hazmat/bindings/_openssl.abi3.so",
            needed=("libcrypto-3a1f2b4c.so.3",),
            runpath=("$ORIGIN/../../../cryptography.libs",),
            matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_IMPORTED),),
        ),
        binary(
            "cryptography.libs/libcrypto-3a1f2b4c.so.3",
            vendored_path=True,
            soname="libcrypto-3a1f2b4c.so.3",
            matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_DEFINED),),
            matched_strings=(OPENSSL_BANNER,),
        ),
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_BUNDLED


# --- the case a vendor-directory check alone would miss ---------------------


def test_openssl_compiled_into_an_extension_is_static(ruleset) -> None:
    """cryptography 42+ links OpenSSL into _rust.abi3.so: no .libs, no DT_NEEDED."""
    evidence = wheel(
        binary(
            "cryptography/hazmat/bindings/_rust.abi3.so",
            needed=("libc.so.6",),
            matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_DEFINED),),
            matched_strings=(OPENSSL_BANNER,),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_STATIC


def test_a_banner_alone_is_enough_for_static(ruleset) -> None:
    """A version script can hide every symbol; the version banner survives it."""
    evidence = wheel(
        binary("pkg/_ext.abi3.so", needed=("libc.so.6",), matched_strings=(OPENSSL_BANNER,))
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_STATIC


def test_imported_symbols_without_a_bundled_copy_are_not_static(ruleset) -> None:
    """Imported means the code is elsewhere. Calling it static would be backwards."""
    evidence = wheel(
        binary(
            "pkg/_ext.abi3.so",
            matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_IMPORTED),),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_UNKNOWN


# --- aggregation across several binaries ------------------------------------


def test_system_and_bundled_together_are_mixed(ruleset) -> None:
    evidence = wheel(
        binary("pkg/_a.so", needed=("libcrypto.so.3",)),
        binary(
            "pkg.libs/libcrypto-3a1f2b4c.so.3",
            vendored_path=True,
            soname="libcrypto-3a1f2b4c.so.3",
        ),
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_MIXED


def test_a_wheel_with_no_openssl_evidence_is_none(ruleset) -> None:
    evidence = wheel(binary("pkg/_ext.so", needed=("libc.so.6", "libstdc++.so.6")))
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_NONE


def test_a_wheel_with_no_binaries_at_all_is_none(ruleset) -> None:
    assert resolve_linkage(ruleset, wheel())["openssl"] == LINKAGE_NONE


# --- opacity ----------------------------------------------------------------


def test_an_opaque_binary_makes_the_answer_unknown_not_none(ruleset) -> None:
    """Absence of evidence is not evidence of absence, and the field must say so."""
    evidence = wheel(binary("pkg/_ext.so", stripped=True))
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_UNKNOWN


def test_a_binary_is_opaque_only_when_it_yielded_nothing() -> None:
    """The property `linkage` and the opaque-binary rule both turn on."""
    assert binary("pkg/_ext.so").is_opaque
    assert not binary("pkg/_ext.so", dynsym_count=12).is_opaque
    assert not binary("pkg/_ext.so", needed=("libcrypto.so.3",)).is_opaque
    assert not binary("pkg/_ext.so", rust_crates=(RustCrate("ring", "0.17.8"),)).is_opaque


def test_an_unparseable_binary_makes_the_answer_unknown(ruleset) -> None:
    evidence = wheel(
        errors=(
            ScanError(
                stage=STAGE_BINARY, kind="elf_parse_error", message="truncated", path="pkg/_x.so"
            ),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_UNKNOWN


def test_real_evidence_beats_an_opaque_sibling(ruleset) -> None:
    """One unreadable object must not erase what the readable ones told us."""
    evidence = wheel(
        binary("pkg/_ext.so", needed=("libcrypto.so.3",)),
        binary("pkg/_opaque.so", stripped=True),
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_SYSTEM


# --- other libraries --------------------------------------------------------


def test_a_bundled_libsodium_is_reported_under_its_own_name(ruleset) -> None:
    evidence = wheel(
        binary("nacl.libs/libsodium-abc123de.so.23", vendored_path=True, soname="libsodium.so.23")
    )
    assert resolve_linkage(ruleset, evidence)["libsodium"] == LINKAGE_BUNDLED


def test_libraries_without_evidence_are_omitted(ruleset) -> None:
    """Except OpenSSL, which consumers filter on and so is always present."""
    result = resolve_linkage(ruleset, wheel())
    assert "openssl" in result
    assert "libsodium" not in result


def test_a_soname_is_matched_after_stripping_its_version(ruleset) -> None:
    evidence = wheel(binary("pkg/_ext.so", needed=("libssl.so.1.1",)))
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_SYSTEM


def test_an_unrelated_library_is_not_mistaken_for_openssl(ruleset) -> None:
    evidence = wheel(binary("pkg/_ext.so", needed=("libcryptography_helper.so.1",)))
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_NONE


# --- determinism ------------------------------------------------------------


def test_the_result_does_not_depend_on_binary_order(ruleset) -> None:
    first = binary("pkg/_a.so", needed=("libcrypto.so.3",))
    second = binary("pkg.libs/libcrypto-3a1f2b4c.so.3", vendored_path=True, soname="libcrypto.so.3")
    assert resolve_linkage(ruleset, wheel(first, second)) == resolve_linkage(
        ruleset, wheel(second, first)
    )
