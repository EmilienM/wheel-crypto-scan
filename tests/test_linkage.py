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
    PARTIAL_MACHO_HEADER_UNREAD,
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
from wheel_crypto_scan.errors import MEMBER_READ_ERROR
from wheel_crypto_scan.linkage import (
    LINKAGE_BUNDLED,
    LINKAGE_MIXED,
    LINKAGE_NONE,
    LINKAGE_STATIC,
    LINKAGE_SYSTEM,
    LINKAGE_UNKNOWN,
    resolve_linkage,
)
from wheel_crypto_scan.ruleset import LinkagePolicy
from wheel_crypto_scan.ruleset_loader import load_ruleset

OPENSSL_BANNER = StringMatch(group="openssl_banner", value="OpenSSL 3.0.14 4 Jun 2024")


@pytest.fixture(scope="module")
def ruleset():
    return load_ruleset()


def binary(path: str, **kwargs) -> BinaryEvidence:
    kwargs.setdefault("format", FORMAT_ELF)
    return BinaryEvidence(path=path, **kwargs)


def wheel(
    *binaries: BinaryEvidence,
    errors: tuple[ScanError, ...] = (),
    artifacts: ArtifactInventory | None = None,
) -> Evidence:
    return Evidence(
        filename="demo-1.0-py3-none-any.whl",
        sha256="0" * 64,
        size_bytes=1,
        artifacts=artifacts if artifacts is not None else ArtifactInventory(),
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


# --- delocate: bundled without a rename (#57) --------------------------------
#
# delocate copies a dependency into `.dylibs/` and rewrites the load command to point
# there, but never renames the file the way auditwheel and delvewheel do. A plain
# `libcrypto.3.dylib` `needed` entry can therefore resolve entirely inside the wheel,
# so `mangled` cannot be the only test for "does this name a copy the wheel ships".


def test_a_loader_path_dependency_resolving_to_a_shipped_object_is_bundled(ruleset) -> None:
    """`@loader_path/.dylibs/libcrypto.3.dylib`: delocate's usual load-command form.

    Before #57 this read `mixed`: the extension's `needed` entry was unmangled, so it
    resolved to `system`, disagreeing with the vendored copy's own `bundled` record.
    """
    evidence = wheel(
        binary(
            "pkg/_ext.cpython-312-darwin.so",
            format=FORMAT_MACHO,
            needed=("/usr/lib/libSystem.B.dylib", "@loader_path/.dylibs/libcrypto.3.dylib"),
            matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_IMPORTED),),
        ),
        binary(
            "pkg/.dylibs/libcrypto.3.dylib",
            format=FORMAT_MACHO,
            vendored_path=True,
            soname="@loader_path/libcrypto.3.dylib",
            matched_symbols=(
                SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_DEFINED),
                SymbolMatch("SSL_new", "openssl", BINDING_DEFINED),
            ),
        ),
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_BUNDLED


def test_an_rpath_dependency_resolving_to_a_shipped_object_is_bundled(ruleset) -> None:
    """`@rpath/libcrypto.3.dylib` plus an `LC_RPATH` pointing at `.dylibs/`."""
    evidence = wheel(
        binary(
            "pkg/_ext.cpython-312-darwin.so",
            format=FORMAT_MACHO,
            needed=("/usr/lib/libSystem.B.dylib", "@rpath/libcrypto.3.dylib"),
            rpath=("@loader_path/.dylibs",),
        ),
        binary(
            "pkg/.dylibs/libcrypto.3.dylib",
            format=FORMAT_MACHO,
            vendored_path=True,
            soname="libcrypto.3.dylib",
        ),
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_BUNDLED


def test_an_unmangled_elf_dependency_beside_the_extension_is_bundled(ruleset) -> None:
    """The same gap on Linux: no vendor directory at all, the library just sits next
    to the extension, and `RUNPATH $ORIGIN` says to look there. Delocate has no ELF
    equivalent, but an unmangled dependency placed beside the extension hits the same
    `mangled`-only check.
    """
    evidence = wheel(
        binary("pkg/_ext.so", needed=("libcrypto.so.3", "libc.so.6"), runpath=("$ORIGIN",)),
        binary("pkg/libcrypto.so.3", soname="libcrypto.so.3", needed=("libc.so.6",)),
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_BUNDLED


def test_an_unreadable_vendored_copy_still_lets_the_needed_entry_resolve(ruleset) -> None:
    """The vendored copy's own structure could not be parsed -- no `needed`, no
    symbols read -- but `layers.binaries.scan_binaries` still records its `path` for
    any member it attempted to read (AGENTS.md: "a structure that does not parse costs
    that structure, never the evidence already gathered"), so the extension's `needed`
    entry still resolves against it.
    """
    evidence = wheel(
        binary(
            "pkg/_ext.cpython-312-darwin.so",
            format=FORMAT_MACHO,
            needed=("/usr/lib/libSystem.B.dylib", "@loader_path/.dylibs/libcrypto.3.dylib"),
        ),
        binary(
            "pkg/.dylibs/libcrypto.3.dylib",
            format=FORMAT_MACHO,
            vendored_path=True,
            partial_analysis=True,
            partial_reasons=(PARTIAL_MACHO_HEADER_UNREAD,),
        ),
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_BUNDLED


# --- BLOCKING 1 (adversarial review of #57): a needed entry cannot confirm itself ---
#
# `member_stem_counts` is built from every object in the wheel, the querying object
# included. An object's own file name can coincidentally share a stem with a dependency
# it declares -- most sharply, an object literally called `libcrypto.so` that itself
# declares an absolute, genuinely-system `/usr/lib64/libcrypto.so.3` -- and without
# discounting the object's own contribution, that coincidence answered the object's own
# question, reading a plain system dependency as `bundled` with nothing behind it.


def test_a_needed_entry_matching_its_own_declaring_objects_name_is_not_self_confirmed(
    ruleset,
) -> None:
    """One object, no vendor directory, no second file. `/usr/lib64/libcrypto.so.3` is
    an absolute path to the host's OpenSSL and can never resolve to the object that
    names it, whatever its own file name happens to be.
    """
    evidence = wheel(
        binary(
            "fakecrypto/libcrypto.so",
            soname="libcrypto.so",
            needed=("/usr/lib64/libcrypto.so.3", "libc.so.6"),
            matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_IMPORTED),),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_SYSTEM


def test_a_second_genuinely_different_object_sharing_that_name_still_confirms_bundled(
    ruleset,
) -> None:
    """Discounting an object's own contribution to its own answer must not also blind
    the check to a second, real object that happens to share the same stem -- the
    documented residual (two different files, one basename), which stays possible on
    purpose and is what `DECISIONS.md` accepts as an imprecise but never silent read.
    """
    evidence = wheel(
        binary(
            "fakecrypto/libcrypto.so", soname="libcrypto.so", needed=("/usr/lib64/libcrypto.so.3",)
        ),
        binary("fakecrypto/plugins/libcrypto.so", soname="libcrypto.so", needed=("libc.so.6",)),
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_BUNDLED


# --- BLOCKING 2 (adversarial review of #57): vendoring something else is not evidence
# --- about openssl -------------------------------------------------------------------
#
# `_looks_vendored` used to treat "this object HAS a vendor-shaped rpath/runpath
# anywhere" as grounds for `unknown`, regardless of whether anything the wheel ships
# could plausibly be the target -- so a FIPS-conscious build that genuinely links the
# system OpenSSL (auditwheel's `--exclude libcrypto.so.3`) while vendoring an unrelated
# library in the same wheel read as `unknown`/`OPAQUE` instead of `system`.


def test_a_genuine_system_openssl_dependency_beside_unrelated_vendoring_stays_system(
    ruleset,
) -> None:
    """ELF: `RUNPATH` is vendor-shaped because the wheel vendors an unrelated libjpeg,
    but nothing under it, or anywhere else in this fully-read wheel, answers to
    `libcrypto` -- that is evidence the dependency resolves outside the wheel, not
    grounds for `unknown`.
    """
    evidence = wheel(
        binary(
            "fakecrypto/_ext.so",
            needed=("libcrypto.so.3", "libc.so.6"),
            runpath=("$ORIGIN/../fakecrypto.libs",),
        ),
        binary(
            "fakecrypto.libs/libjpeg.so.8",
            soname="libjpeg.so.8",
            vendored_path=True,
            needed=("libc.so.6",),
        ),
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_SYSTEM


def test_a_genuine_macos_system_openssl_dependency_beside_unrelated_vendoring_stays_system(
    ruleset,
) -> None:
    """The same shape via `LC_RPATH`: the wheel vendors an unrelated libjpeg under
    `.dylibs/`, but the extension's own OpenSSL dependency is an absolute, genuinely
    system path.
    """
    evidence = wheel(
        binary(
            "fakecrypto/_ext.cpython-312-darwin.so",
            format=FORMAT_MACHO,
            needed=("/usr/lib/libSystem.B.dylib", "/usr/lib/libcrypto.3.dylib"),
            rpath=("@loader_path/.dylibs",),
        ),
        binary(
            "fakecrypto/.dylibs/libjpeg.9.dylib",
            format=FORMAT_MACHO,
            vendored_path=True,
            soname="libjpeg.9.dylib",
        ),
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_SYSTEM


def test_a_vendor_shaped_loader_path_naming_nothing_shipped_is_system_when_fully_read(
    ruleset,
) -> None:
    """The path looks like delocate's convention, but the wheel does not actually ship
    anything under it, and every member of the wheel was read: `member_stem_counts`
    already speaks for the whole wheel, so this is genuine `system`, not `unknown`
    -- asserting `unknown` from the path shape alone would be a different overconfident
    misreading in the other direction. #57.
    """
    evidence = wheel(
        binary(
            "pkg/_ext.cpython-312-darwin.so",
            format=FORMAT_MACHO,
            needed=("/usr/lib/libSystem.B.dylib", "@loader_path/.dylibs/libcrypto.3.dylib"),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_SYSTEM


def test_a_vendor_shaped_rpath_naming_nothing_shipped_is_system_when_fully_read(ruleset) -> None:
    """Same call, reached through `@rpath` plus an `LC_RPATH` this time."""
    evidence = wheel(
        binary(
            "pkg/_ext.cpython-312-darwin.so",
            format=FORMAT_MACHO,
            needed=("/usr/lib/libSystem.B.dylib", "@rpath/libcrypto.3.dylib"),
            rpath=("@loader_path/.dylibs",),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_SYSTEM


def test_a_bare_needed_entry_with_a_vendor_shaped_runpath_naming_nothing_is_system_when_full(
    ruleset,
) -> None:
    """The ELF counterpart: no path in `DT_NEEDED` itself, but `RUNPATH` alone points
    at a vendor directory that does not actually contain the library, in a wheel read
    in full.
    """
    evidence = wheel(
        binary("pkg/_ext.so", needed=("libcrypto.so.3", "libc.so.6"), runpath=("$ORIGIN/.libs",))
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_SYSTEM


def test_a_vendor_shaped_path_is_unknown_when_a_member_could_not_be_read(ruleset) -> None:
    """Genuine incompleteness, this time: a member of the wheel raised on open and
    never became a `BinaryEvidence` at all, so `member_stem_counts` cannot rule
    anything out, and the vendor-shaped path it cannot confirm stays `unknown` rather
    than a confident `system`.
    """
    evidence = wheel(
        binary(
            "pkg/_ext.cpython-312-darwin.so",
            format=FORMAT_MACHO,
            needed=("/usr/lib/libSystem.B.dylib", "@loader_path/.dylibs/libcrypto.3.dylib"),
        ),
        errors=(
            ScanError(
                stage=STAGE_BINARY,
                kind=MEMBER_READ_ERROR,
                message="could not read member: BadZipFile",
                path="pkg/.dylibs/libcrypto.3.dylib",
            ),
        ),
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_UNKNOWN


def test_a_vendor_shaped_path_is_unknown_when_the_archive_skipped_a_member(ruleset) -> None:
    """The other way a member never becomes a `BinaryEvidence`: an archive-level limit
    skipped it before Layer 2 ever tried to read it, recorded in `artifacts.skipped`.
    """
    evidence = wheel(
        binary(
            "pkg/_ext.cpython-312-darwin.so",
            format=FORMAT_MACHO,
            needed=("/usr/lib/libSystem.B.dylib", "@loader_path/.dylibs/libcrypto.3.dylib"),
        ),
        artifacts=ArtifactInventory(skipped=(("pkg/.dylibs/libcrypto.3.dylib", "oversized"),)),
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_UNKNOWN


def test_a_plain_dependency_stays_system_even_in_an_incompletely_read_wheel(ruleset) -> None:
    """The `incomplete` gate on `_looks_vendored` is not a blanket downgrade: a wheel
    can be incompletely read for a reason that has nothing to do with a given `needed`
    entry, and a plain, non-vendor-shaped name with no vendor-shaped `RPATH`/`RUNPATH`
    at all must still read `system`. Mutating `_looks_vendored` to unconditionally
    return `True` would flip only this test, not the `incomplete`-gating ones, so it
    is the one that pins the vendor-*shape* check rather than the gate around it.
    """
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libcrypto.so.3", "libc.so.6"),
            matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_IMPORTED),),
        ),
        errors=(
            ScanError(
                stage=STAGE_BINARY,
                kind=MEMBER_READ_ERROR,
                message="could not read member: BadZipFile",
                path="pkg/some_unrelated.so",
            ),
        ),
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_SYSTEM


def test_a_symlinked_vendored_library_is_treated_as_incompletely_read(ruleset) -> None:
    """`layers.binaries.is_binary_member` returns `False` for every symlink, so a
    vendored library shipped as one is never read as a binary at all: it records
    neither a `skipped` entry nor a `STAGE_BINARY` error, only `artifacts.symlinks`.
    Without checking that field, the extension's vendor-shaped `needed` entry read
    `system` -- `BIN_NEEDED_SYSTEM_OPENSSL`'s "Links the system OpenSSL" and
    `DERIVED_SYSTEM_OPENSSL_ONLY`'s "All OpenSSL use resolves to the system library"
    are both affirmatively wrong for an `@loader_path`-anchored load command, which
    can never be the host's system OpenSSL by construction.
    """
    evidence = wheel(
        binary(
            "demo/_ext.abi3.so",
            format=FORMAT_MACHO,
            needed=("/usr/lib/libSystem.B.dylib", "@loader_path/.dylibs/libcrypto.3.dylib"),
        ),
        artifacts=ArtifactInventory(
            symlinks=(("demo/.dylibs/libcrypto.3.dylib", "libcrypto.3.0.0.dylib"),)
        ),
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_UNKNOWN


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


# --- system and static within one object (#60) ------------------------------
#
# `_binary_posture` used to test `needed` first and return as soon as it found a
# system match, so an object that both declares `DT_NEEDED libssl.so.3` and defines
# `EVP_DigestInit_ex` itself (or carries an OpenSSL banner) never reached the
# defined/banner check at all: it read `system`, and the record then paired
# `DERIVED_SYSTEM_OPENSSL_ONLY` ("every piece of OpenSSL evidence points at the
# system library") with `BIN_OPENSSL_SYMBOLS_DEFINED` ("OpenSSL was compiled into
# it") -- a record contradicting itself in the favourable direction. Both
# observations are independently true, so the object's own posture is `mixed`,
# the same value `_aggregate` already gives two objects that disagree.


def test_a_needed_system_match_and_a_defined_symbol_together_are_mixed(ruleset) -> None:
    """The reproduction from #60: one object, both signals, in the same record."""
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libc.so.6", "libssl.so.3"),
            matched_symbols=(
                SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_DEFINED),
                SymbolMatch("SSL_new", "openssl", BINDING_IMPORTED),
            ),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_MIXED


def test_a_needed_system_match_and_a_banner_together_are_mixed(ruleset) -> None:
    """The banner-only shape of the same contradiction: a version script hid the
    symbols, but the string is still there, and the `needed` entry still resolves
    to the system library."""
    evidence = wheel(
        binary("pkg/_ext.so", needed=("libssl.so.3",), matched_strings=(OPENSSL_BANNER,))
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_MIXED


def test_a_merged_universal_binary_whose_slices_disagreed_is_now_mixed(ruleset) -> None:
    """`DECISIONS.md`'s "A universal binary is one record, and its slices are
    merged": an x86_64 slice linking the host OpenSSL and an arm64 slice with it
    compiled in, reduced by the Mach-O reader into one `BinaryEvidence` whose
    `needed` and `matched_symbols` are the union of both slices. This used to read
    `system` because `needed` was tested first; #60 makes it `mixed`, matching
    what reading the slices separately and letting `_aggregate` combine them would
    have said all along.
    """
    evidence = wheel(
        binary(
            "pkg/_ext.cpython-312-darwin.so",
            format=FORMAT_MACHO,
            needed=("/usr/lib/libcrypto.3.dylib",),
            matched_symbols=(
                SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_IMPORTED),
                SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_DEFINED),
            ),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_MIXED


def test_a_needed_system_match_alone_is_still_system(ruleset) -> None:
    """No defined symbol and no banner: the ordinary system case is unchanged."""
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libssl.so.3",),
            matched_symbols=(SymbolMatch("SSL_new", "openssl", BINDING_IMPORTED),),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_SYSTEM


def test_a_defined_symbol_alone_is_still_static(ruleset) -> None:
    """No `needed` match at all: the ordinary static case is unchanged."""
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libc.so.6",),
            matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_DEFINED),),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_STATIC


# --- uncertain and static within one object (#87) ----------------------------
#
# `_binary_posture` returned `LINKAGE_UNKNOWN` for the `uncertain` case -- a `needed`
# entry whose path/rpath shape looks vendored but that an incompletely-read wheel
# cannot confirm either way (#57) -- before the defined/banner check a few lines
# below it ever ran. An object with both an unconfirmed vendor-shaped `needed` entry
# and a confirmed static definition (or banner) read `unknown` regardless, silently
# discarding the confirmed evidence. This is #60's own fix, extended: `mixed`, not a
# value that erases one of the two facts.


def test_an_uncertain_needed_match_and_a_defined_symbol_together_are_mixed(ruleset) -> None:
    """The reproduction from #87: an incompletely-read wheel (`errors` at
    `STAGE_BINARY`), a `needed` entry whose `RUNPATH` looks vendor-shaped but names
    nothing the wheel actually ships, and a real `EVP_DigestInit_ex` definition in
    the same object.
    """
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libcrypto.so.3",),
            runpath=("$ORIGIN/../p.libs",),
            matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_DEFINED),),
        ),
        errors=(
            ScanError(
                stage=STAGE_BINARY,
                kind=MEMBER_READ_ERROR,
                message="could not read member: BadZipFile",
                path="pkg/some_unrelated.so",
            ),
        ),
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_MIXED


def test_an_uncertain_needed_match_and_a_banner_together_are_mixed(ruleset) -> None:
    """Same shape, the banner-only variant: a version script hides the symbols but
    the string survives it, same as #60's banner variant."""
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libcrypto.so.3",),
            runpath=("$ORIGIN/../p.libs",),
            matched_strings=(OPENSSL_BANNER,),
        ),
        errors=(
            ScanError(
                stage=STAGE_BINARY,
                kind=MEMBER_READ_ERROR,
                message="could not read member: BadZipFile",
                path="pkg/some_unrelated.so",
            ),
        ),
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_MIXED


def test_an_uncertain_needed_match_alone_is_still_unknown(ruleset) -> None:
    """No static evidence at all: the ordinary `uncertain` case (#57) is unchanged."""
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libcrypto.so.3",),
            runpath=("$ORIGIN/../p.libs",),
        ),
        errors=(
            ScanError(
                stage=STAGE_BINARY,
                kind=MEMBER_READ_ERROR,
                message="could not read member: BadZipFile",
                path="pkg/some_unrelated.so",
            ),
        ),
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_UNKNOWN


def test_a_confirmed_system_match_beside_an_uncertain_one_stays_system(ruleset) -> None:
    """Two `needed` entries on one object: a plain one that resolves to the system
    library for certain, and a second whose own path is vendor-shaped (delocate's
    convention, embedded in the string itself rather than via a shared `RUNPATH`)
    that this incompletely-read wheel cannot confirm. `system` is a `_DEFINITE`
    posture; `uncertain` is exactly `needed_posture`'s `LINKAGE_UNKNOWN`, which is
    not, and `_aggregate` already treats a non-definite posture as one that never
    outvotes a definite one present elsewhere (`len(definite) == 1: return
    definite[0]`, discarding `LINKAGE_UNKNOWN`) -- the same rule applied here within
    one object: the confirmed `system` match needs no vote from the unconfirmed
    `uncertain` one, so this stays plain `system`, not a three-way `mixed`. See #87.
    """
    evidence = wheel(
        binary(
            "pkg/_ext.cpython-312-darwin.so",
            format=FORMAT_MACHO,
            needed=(
                "/usr/lib/libssl.3.dylib",
                "@loader_path/.dylibs/libcrypto.3.dylib",
            ),
        ),
        errors=(
            ScanError(
                stage=STAGE_BINARY,
                kind=MEMBER_READ_ERROR,
                message="could not read member: BadZipFile",
                path="pkg/some_unrelated.dylib",
            ),
        ),
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_SYSTEM


def test_system_uncertain_and_static_together_still_read_mixed(ruleset) -> None:
    """A characterization pin, not a guard for a specific ordering decision: the
    same three signals as the test above, plus a confirmed static definition.

    Whenever `system` and `uncertain` can both be true on one object, `system` and
    `static` are also both true here, so #60's `if system and static: return
    LINKAGE_MIXED` branch already answers `mixed` before `_binary_posture` ever
    reaches the new `if uncertain and static` branch #87 added. That makes this
    specific shape provably unable to distinguish the two branches, or their
    relative order, from `resolve_linkage`'s output alone: deleting the `#87`
    branch entirely, or moving it ahead of the `system` checks, both still leave
    this test green, because #60's branch (or the reordered #87 branch) produces
    the identical `mixed` either way. Confirmed by mutation during review.

    The `#87` branch's own ordering is pinned by the two-signal reproduction tests
    instead (`test_an_uncertain_needed_match_and_a_defined_symbol_together_are_mixed`
    and its banner variant, above), where `system` is false and only the new branch
    can produce `mixed` at all; reverting the fix turns those two red. This test
    stays only to confirm the three-way shape reads sensibly, not to attribute the
    answer to either branch.
    """
    evidence = wheel(
        binary(
            "pkg/_ext.cpython-312-darwin.so",
            format=FORMAT_MACHO,
            needed=(
                "/usr/lib/libssl.3.dylib",
                "@loader_path/.dylibs/libcrypto.3.dylib",
            ),
            matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_DEFINED),),
        ),
        errors=(
            ScanError(
                stage=STAGE_BINARY,
                kind=MEMBER_READ_ERROR,
                message="could not read member: BadZipFile",
                path="pkg/some_unrelated.dylib",
            ),
        ),
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_MIXED


# --- bundled and system/static within one object (#88) -----------------------
#
# `_binary_posture`'s `needed` loop used to return `LINKAGE_BUNDLED` as soon as one
# entry resolved that way, before a second, disagreeing `needed` entry on the same
# object -- or the defined/static check a few lines below -- ever ran. A universal
# Mach-O object merges its slices' `needed` tuples into one (`binfmt.macho`, pinned by
# `test_load_dylibs_merge_across_slices` in `test_binfmt_macho.py`), so a fat object
# whose slices disagreed about `bundled` versus `system` or `static` read `bundled`
# outright instead of `mixed`, unlike the same evidence read as two separate objects.


def test_a_bundled_needed_match_and_a_system_needed_match_together_are_mixed(ruleset) -> None:
    """The reproduction from #88: one object, one `needed` entry hash-renamed
    (`bundled`), a different `needed` entry an absolute path to the host library
    (`system`). Same evidence in two separate objects already reads `mixed` via
    `_aggregate`; this object's own evidence must read the same way.
    """
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libcrypto-3a1f2b4c.so.3", "/usr/lib64/libcrypto.so.3"),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_MIXED


def test_a_bundled_needed_match_and_a_defined_symbol_together_are_mixed(ruleset) -> None:
    """The second reproduction from #88: one hash-renamed `needed` entry, and a real
    `EVP_DigestInit_ex` definition in the same object -- the shape a Mach-O universal
    binary merges into one record when one slice declares the vendored dependency and
    the other has OpenSSL compiled in.
    """
    evidence = wheel(
        binary(
            "pkg/_ext.cpython-312-darwin.so",
            format=FORMAT_MACHO,
            needed=("libcrypto-3a1f2b4c.3.dylib",),
            matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_DEFINED),),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_MIXED


def test_a_bundled_needed_match_and_a_banner_together_are_mixed(ruleset) -> None:
    """The banner-only variant of the same contradiction, matching #60's and #87's
    own banner variants."""
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libcrypto-3a1f2b4c.so.3",),
            matched_strings=(OPENSSL_BANNER,),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_MIXED


def test_a_bundled_needed_match_alone_is_still_bundled(ruleset) -> None:
    """No other signal: the ordinary bundled case, now reached after the
    `_DEFINITE`-count check instead of returning from inside the loop, is unchanged.
    """
    evidence = wheel(binary("pkg/_ext.so", needed=("libcrypto-3a1f2b4c.so.3",)))
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_BUNDLED


def test_a_bundled_needed_match_beside_an_uncertain_one_stays_bundled(ruleset) -> None:
    """Two `needed` entries on one object: one hash-renamed and therefore confirmed
    `bundled`, and a second whose own path is vendor-shaped (delocate's convention)
    but that this incompletely-read wheel cannot confirm. `bundled`, like `system`,
    is read off `binary.needed` in the loop above, and a confirmed entry from that
    loop needs no vote from a different, unconfirmed one -- the same rule #87
    established for `system` beside `uncertain`, extended here to `bundled`. See #88.
    """
    evidence = wheel(
        binary(
            "pkg/_ext.cpython-312-darwin.so",
            format=FORMAT_MACHO,
            needed=(
                "libcrypto-3a1f2b4c.3.dylib",
                "@loader_path/.dylibs/libssl.3.dylib",
            ),
        ),
        errors=(
            ScanError(
                stage=STAGE_BINARY,
                kind=MEMBER_READ_ERROR,
                message="could not read member: BadZipFile",
                path="pkg/some_unrelated.dylib",
            ),
        ),
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_BUNDLED


def test_bundled_system_and_static_together_still_read_mixed(ruleset) -> None:
    """A characterization pin, not a guard for a specific branch: all three
    `_DEFINITE` signals true on one object at once (a third `needed` entry resolves
    `bundled`, another resolves `system`, and a real symbol makes `static` true too)
    still reads `mixed` -- the `_DEFINITE`-count check answers `mixed` regardless of
    which two, or all three, of the signals are the ones present.
    """
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libcrypto-3a1f2b4c.so.3", "/usr/lib64/libcrypto.so.3"),
            matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_DEFINED),),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_MIXED


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
    asserted to be exactly the four the ruleset names, so widening that list has to
    be done on purpose.
    """
    excluded = ruleset.linkage_policy.exclude_reasons
    assert excluded == frozenset(
        {
            PARTIAL_PE_ORDINAL_IMPORT,
            PARTIAL_ELF_SYMTAB_UNREAD,
            PARTIAL_ELF_GO_BUILDINFO_UNREAD,
            PARTIAL_PE_NO_IMPORT_DIRECTORY,
        }
    )
    assert PARTIAL_PE_ORDINAL_EXPORT not in excluded, (
        "an export with no name is a definition we could not read, and a definition is "
        "how `static` is recognised"
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
