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
    STAGE_BINARY,
    ArtifactInventory,
    BinaryEvidence,
    Evidence,
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
    return BinaryEvidence(path=path, format=FORMAT_ELF, **kwargs)


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
    """The Red Hat build: it resolves to whatever OpenSSL the host provides."""
    evidence = wheel(
        binary(
            "cryptography/hazmat/bindings/_openssl.abi3.so",
            needed=("libcrypto.so.3", "libc.so.6"),
            matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_IMPORTED),),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_SYSTEM


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
