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
    FORMAT_MACHO,
    FORMAT_PE,
    PARTIAL_ELF_GO_BUILDINFO_UNREAD,
    PARTIAL_ELF_SYMTAB_UNREAD,
    PARTIAL_MACHO_SYMTAB_INCOMPLETE,
    PARTIAL_PE_DELAY_LOAD,
    PARTIAL_PE_NO_IMPORT_DIRECTORY,
    PARTIAL_PE_ORDINAL_EXPORT,
    PARTIAL_PE_ORDINAL_IMPORT,
    PARTIAL_REASONS,
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
from wheel_crypto_scan.ruleset import LinkagePolicy, load_ruleset

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


def test_which_symbol_count_means_something_is_read_depends_on_the_format() -> None:
    """Mach-O and PE never set `dynsym_count`; their counts land in `symtab_count`.

    Keying on `dynsym_count` for every format called every Mach-O and every PE opaque
    however much of it was read, which is how a crypto-free universal2 wheel whose
    slices all parsed came back saying it had told us nothing.
    """
    for fmt in (FORMAT_MACHO, FORMAT_PE):
        assert not binary("pkg/_ext", format=fmt, symtab_count=12).is_opaque, fmt
        assert binary("pkg/_ext", format=fmt).is_opaque, fmt


def test_an_elf_with_a_symtab_and_no_dynsym_is_still_opaque() -> None:
    """The reason the counts are chosen by format rather than simply both tested.

    That is the ordinary shape of a static executable. Whether it has told us anything
    is a separate question from the Mach-O and PE one, and answering it by widening
    this property would be answering it by accident.
    """
    assert binary("pkg/_ext.so", format=FORMAT_ELF, symtab_count=12).is_opaque
    assert not binary("pkg/_ext.so", format=FORMAT_ELF, dynsym_count=12).is_opaque


def test_a_readable_crypto_free_macho_resolves_openssl_to_none(ruleset) -> None:
    """`is_opaque` is what `linkage` falls back on, and it is the half users filter.

    Both of this property's callers in `linkage` could be deleted with the whole suite
    still green, which is how the format bug reached the field at all.
    """
    evidence = wheel(binary("pkg/_ext.so", format=FORMAT_MACHO, symtab_count=12))
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_NONE


def test_a_macho_that_yielded_nothing_keeps_openssl_unknown(ruleset) -> None:
    """Absence of evidence is not evidence of absence, for Mach-O as much as ELF."""
    evidence = wheel(binary("pkg/_ext.so", format=FORMAT_MACHO))
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


# --- a partial read is not a definite posture -------------------------------


def test_a_binary_not_read_in_full_costs_the_answer(ruleset) -> None:
    """The case the record used to answer twice, each time differently.

    A stripped macOS extension: `LC_SYMTAB` was not read, so the imported/defined
    split is missing, and every loadable dylib links `libSystem`, so `is_opaque` is
    false and the errors are empty. Nothing else in the wheel said anything, so
    `openssl_linkage` used to read `none` beside a `partial_reasons` saying we could
    not look.
    """
    evidence = wheel(
        binary(
            "pkg/_ext.dylib",
            format=FORMAT_MACHO,
            needed=("/usr/lib/libSystem.B.dylib",),
            partial_analysis=True,
            partial_reasons=(PARTIAL_MACHO_SYMTAB_INCOMPLETE,),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_UNKNOWN


def test_a_linker_convention_still_leaves_a_definite_posture(ruleset) -> None:
    """Why the tuple is not simply counted wholesale.

    `WS2_32` is normally bound by ordinal, so this is the ordinary shape of a Windows
    extension that touches sockets. Counting every cause would have made every one of
    them `unknown`, which is the noise removed when the same split was drawn for
    verdicts.
    """
    evidence = wheel(
        binary(
            "pkg/_ext.pyd",
            format=FORMAT_PE,
            needed=("python311.dll", "WS2_32.dll"),
            symtab_count=4,
            partial_analysis=True,
            partial_reasons=(PARTIAL_PE_ORDINAL_IMPORT,),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_NONE


def test_one_serious_cause_beside_a_routine_one_still_costs_the_answer(ruleset) -> None:
    """Any cause not on the list is enough; the excluded ones do not vote it down."""
    evidence = wheel(
        binary(
            "pkg/_ext.pyd",
            format=FORMAT_PE,
            needed=("python311.dll",),
            symtab_count=4,
            partial_analysis=True,
            partial_reasons=(PARTIAL_PE_DELAY_LOAD, PARTIAL_PE_ORDINAL_IMPORT),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_UNKNOWN


def test_real_evidence_beats_a_partially_read_sibling(ruleset) -> None:
    """Same rule as for an opaque sibling: `unknown` never outvotes an observation."""
    evidence = wheel(
        binary("pkg/_ext.so", needed=("libcrypto.so.3",)),
        binary(
            "pkg/_other.dylib",
            format=FORMAT_MACHO,
            needed=("/usr/lib/libSystem.B.dylib",),
            partial_analysis=True,
            partial_reasons=(PARTIAL_MACHO_SYMTAB_INCOMPLETE,),
        ),
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_SYSTEM


def test_a_cause_the_policy_does_not_name_costs_the_answer(ruleset) -> None:
    """Excluding rather than including: a token added later is serious by default.

    Written against the whole vocabulary rather than one token, so a cause added to
    `PARTIAL_REASONS` and forgotten here is still covered. The excluded ones are
    asserted to be exactly the five the ruleset names, so widening that list has to
    be done on purpose.
    """
    excluded = ruleset.linkage_policy.exclude_reasons
    assert excluded == frozenset(
        {
            PARTIAL_PE_ORDINAL_IMPORT,
            PARTIAL_PE_ORDINAL_EXPORT,
            PARTIAL_ELF_SYMTAB_UNREAD,
            PARTIAL_ELF_GO_BUILDINFO_UNREAD,
            PARTIAL_PE_NO_IMPORT_DIRECTORY,
        }
    )
    for reason in sorted(PARTIAL_REASONS):
        evidence = wheel(
            binary(
                "pkg/_ext.so",
                needed=("libc.so.6",),
                partial_analysis=True,
                partial_reasons=(reason,),
            )
        )
        posture = resolve_linkage(ruleset, evidence)["openssl"]
        expected = LINKAGE_NONE if reason in excluded else LINKAGE_UNKNOWN
        assert posture == expected, reason


def test_an_empty_policy_reads_every_cause_as_serious() -> None:
    """The dataclass default excludes nothing; `[linkage_policy]`'s absence is derived."""
    assert LinkagePolicy().costs_an_answer((PARTIAL_PE_ORDINAL_IMPORT,))
    assert not LinkagePolicy().costs_an_answer(())


def test_a_partial_read_that_names_no_cause_costs_the_answer(ruleset) -> None:
    """The two consumers of one field must not read it in opposite directions.

    `engine._match_partial_binary` singles this shape out as the most serious there
    is: no reader produces it, so the evidence was built by hand. Reading the empty
    tuple as "nothing excluded, so nothing costs us anything" made `linkage` the one
    consumer that quietly downgraded it.
    """
    evidence = wheel(
        binary("pkg/_ext.so", needed=("libc.so.6",), partial_analysis=True, partial_reasons=())
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_UNKNOWN


def test_an_unanswered_object_costs_only_the_libraries_always_reported(ruleset) -> None:
    """The gate that keeps `verdict.conditions` from growing a key per crypto library.

    `_aggregate` is handed `unanswered and library.always_report`, and without the
    second half a wheel whose one object was not read in full reports every library in
    the ruleset as `unknown` -- a dozen keys, none of them backed by any evidence that
    the library is anywhere near this wheel. Deleting that clause left the whole suite
    green, which is how a documented promise turns out to be a coincidence.
    """
    evidence = wheel(
        binary(
            "pkg/_ext.dylib",
            format=FORMAT_MACHO,
            needed=("/usr/lib/libSystem.B.dylib",),
            partial_analysis=True,
            partial_reasons=(PARTIAL_MACHO_SYMTAB_INCOMPLETE,),
        )
    )
    resolved = resolve_linkage(ruleset, evidence)
    assert resolved["openssl"] == LINKAGE_UNKNOWN
    reported = {name for name, library in ruleset.libraries.items() if library.always_report}
    assert set(resolved) == reported, "a library with no evidence gained a posture"
    assert "libsodium" not in resolved


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
