"""How the tool decides whether a wheel uses the system OpenSSL or carries its own.

This is the question the whole tool exists to answer, so these tests are written
against hand-built evidence rather than against real wheels: they pin the decision
itself, independently of whether the ELF reader can see a given field.
"""

from __future__ import annotations

import ast
import inspect
import itertools
import sys
from dataclasses import replace

import pytest

from wheel_crypto_scan import linkage as linkage_module
from wheel_crypto_scan.engine import apply_rules
from wheel_crypto_scan.evidence import (
    BINDING_DEFINED,
    BINDING_IMPORTED,
    FORMAT_ELF,
    FORMAT_MACHO,
    FORMAT_PE,
    PARTIAL_ELF_GO_BUILDINFO_UNREAD,
    PARTIAL_MACHO_HEADER_UNREAD,
    PARTIAL_MACHO_SYMTAB_INCOMPLETE,
    PARTIAL_PE_DELAY_LOAD,
    PARTIAL_PE_NO_IMPORT_DIRECTORY,
    PARTIAL_PE_ORDINAL_EXPORT,
    PARTIAL_PE_ORDINAL_IMPORT,
    PARTIAL_REASONS,
    PARTIAL_STRINGS_BYTES_UNREAD,
    STAGE_BINARY,
    ArtifactInventory,
    BinaryEvidence,
    Evidence,
    MetadataEvidence,
    RustCrate,
    SbomComponent,
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
    declared_by_sbom,
    object_postures,
    resolve_linkage,
)
from wheel_crypto_scan.ruleset import LinkagePolicy
from wheel_crypto_scan.ruleset_loader import load_ruleset, parse_ruleset

OPENSSL_BANNER = StringMatch(group="openssl_banner", value="OpenSSL 3.0.14 4 Jun 2024")
OPENSSL_BUILD_INFO = StringMatch(group="openssl_build_info", value='OPENSSLDIR: "/usr/lib/ssl"')


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
    metadata: MetadataEvidence | None = None,
) -> Evidence:
    return Evidence(
        filename="demo-1.0-py3-none-any.whl",
        sha256="0" * 64,
        size_bytes=1,
        artifacts=artifacts if artifacts is not None else ArtifactInventory(),
        binaries=binaries,
        errors=errors,
        metadata=metadata,
    )


def sbom(*names: str, purl: str | None = None) -> MetadataEvidence:
    return MetadataEvidence(
        name="demo",
        canonical_name="demo",
        version="1.0",
        sbom_components=tuple(
            SbomComponent(n, "0.9.117", purl, "demo-1.0.dist-info/sboms/a.cdx.json") for n in names
        ),
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
    Enumerating spellings on the openssl entry would cover one library out of thirteen
    and leave the rest reporting a dependency the resolver cannot see.
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


# --- delocate: bundled without a rename -------------------------------------
#
# delocate copies a dependency into `.dylibs/` and rewrites the load command to point
# there, but never renames the file the way auditwheel and delvewheel do. A plain
# `libcrypto.3.dylib` `needed` entry can therefore resolve entirely inside the wheel,
# so `mangled` cannot be the only test for "does this name a copy the wheel ships".


def test_a_loader_path_dependency_resolving_to_a_shipped_object_is_bundled(ruleset) -> None:
    """`@loader_path/.dylibs/libcrypto.3.dylib`: delocate's usual load-command form.

    Keyed on `mangled` alone this reads `mixed`: the extension's `needed` entry is
    unmangled, so it resolves to `system`, disagreeing with the vendored copy's own
    `bundled` record.
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


# --- a needed entry cannot confirm itself -----------------------------------
#
# `member_stem_counts` is built from every object in the wheel, the querying object
# included. An object's own file name can coincidentally share a stem with a dependency
# it declares -- most sharply, an object literally called `libcrypto.so` that itself
# declares an absolute, genuinely-system `/usr/lib64/libcrypto.so.3` -- and without
# discounting the object's own contribution, that coincidence would answer the object's
# own question, reading a plain system dependency as `bundled` with nothing behind it.
#
# Every absolute `needed` entry has its own, earlier short-circuit in `needed_posture`,
# so the reproduction just below -- an absolute dependency -- does not reach
# `_resolves_within_wheel` at all, and does not exercise the discount; its assertion
# holds through the short-circuit's route instead, which
# `test_an_absolute_needed_entrys_basename_collision_reads_as_system` further down pins
# explicitly. The discount itself is live code for a *relative* same-named dependency,
# and the test just below exists to pin it:
# `test_a_relative_needed_entry_matching_its_own_declaring_objects_name_is_not_self_confirmed`.


def test_a_needed_entry_matching_its_own_declaring_objects_name_is_not_self_confirmed(
    ruleset,
) -> None:
    """One object, no vendor directory, no second file. `/usr/lib64/libcrypto.so.3` is
    an absolute path to the host's OpenSSL and can never resolve to the object that
    names it, whatever its own file name happens to be.

    This does not exercise `_resolves_within_wheel`'s own-stem discount: the absolute
    short-circuit in `needed_posture` answers `system` before that function is ever
    called, for this exact reproduction. It stands as a characterization pin
    of the end-to-end answer; the discount itself is pinned by the relative sibling
    just below, which cannot take the absolute short-circuit.
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


def test_a_relative_needed_entry_matching_its_own_declaring_objects_name_is_not_self_confirmed(
    ruleset,
) -> None:
    """The discount's own test, reached through a relative entry since the
    absolute short-circuit above answers before `_resolves_within_wheel` is reached
    for an absolute one: one object, named `libcrypto.so`, declares a plain relative
    `libcrypto.so.3` -- exactly its own stem -- with no vendor directory and no second
    file. `member_stem_counts` must not let the object answer its own question just
    because a relative dependency, unlike an absolute one, genuinely could resolve
    via `RUNPATH $ORIGIN` to some other object in the wheel, if one existed.
    """
    evidence = wheel(
        binary(
            "fakecrypto/libcrypto.so",
            soname="libcrypto.so",
            needed=("libcrypto.so.3", "libc.so.6"),
            runpath=("$ORIGIN",),
            matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_IMPORTED),),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_SYSTEM


def test_an_absolute_needed_entrys_basename_collision_reads_as_system(ruleset) -> None:
    """The absolute short-circuit applies here too. Discounting an object's own
    contribution to its own answer alone would leave a second, real object that happens
    to share the same stem free to confirm `bundled` -- but the `needed` entry here is
    an absolute path, and no real dynamic loader ever resolves an absolute path against
    anything the wheel ships. The basename coincidence is exactly as meaningless for a
    second object as it is for the declaring object's own name in the test above; only
    the object count differs, and the object count is never the right test for an
    absolute path.
    """
    evidence = wheel(
        binary(
            "fakecrypto/libcrypto.so", soname="libcrypto.so", needed=("/usr/lib64/libcrypto.so.3",)
        ),
        binary("fakecrypto/plugins/libcrypto.so", soname="libcrypto.so", needed=("libc.so.6",)),
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_SYSTEM


def test_a_relative_needed_entrys_basename_collision_still_confirms_bundled(ruleset) -> None:
    """The short-circuit covers absolute entries only. A relative, unmangled
    `needed` entry can genuinely be resolved by `$ORIGIN`/`RPATH`/`RUNPATH`, so a
    second, real object elsewhere in the wheel that happens to share its stem still
    confirms `bundled` -- imprecise when the coincidence is not real vendoring, but
    never silent about it (`BIN_NEEDED_VENDORED_CRYPTO`), and still the accepted trade
    `DESIGN.md` documents for anything that is not an absolute path.
    """
    evidence = wheel(
        binary("fakecrypto/_ext.so", needed=("libcrypto.so.3",)),
        binary("fakecrypto/plugins/libcrypto.so.3", soname="libcrypto.so.3", needed=("libc.so.6",)),
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_BUNDLED


def test_an_archive_members_soname_never_confirms_a_siblings_needed_entry(ruleset) -> None:
    """The same basename-collision shape as the test above, but the colliding object
    is `from_archive=True` -- a relocatable object `binfmt.ar` read out of a
    `.a`/`.lib` static archive. Unlike a real zip member, such an object is never a
    file any dynamic loader could resolve a `needed` entry to, and its `SONAME` is
    bytes the archive itself wrote, read exactly as written -- attacker-controlled the
    same way any other bytes in the wheel are. If `member_stem_counts` counted these,
    a crafted archive member could flip a genuinely system-linked sibling extension's
    own posture to `bundled`.
    """
    evidence = wheel(
        binary("fakecrypto/_ext.so", needed=("libcrypto.so.3",)),
        binary(
            "fakecrypto/vendor/lib.a(evil.o)",
            soname="libcrypto.so.3",
            needed=("libc.so.6",),
            from_archive=True,
        ),
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_SYSTEM


def test_an_absolute_mangled_needed_entry_is_still_bundled(ruleset) -> None:
    """The `mangled` check is unaffected by absoluteness on purpose: a
    hash-renamed basename is strong enough evidence on its own, independent of
    whether the path that carries it happens to be absolute, so this still reads
    `bundled` even though the entry itself is a path no loader could resolve within
    the wheel by search order.
    """
    evidence = wheel(binary("pkg/_ext.so", needed=("/opt/vendor/libcrypto-3a1f2b4c.so.3",)))
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_BUNDLED


def test_an_absolute_macho_install_name_basename_collision_is_not_manufactured_bundled(
    ruleset,
) -> None:
    """Mach-O is where an absolute `needed` entry is the norm, not the exception: an
    unrepaired Homebrew build's `LC_LOAD_DYLIB` genuinely does carry a literal
    install name like `/usr/local/opt/openssl@3/lib/libcrypto.3.dylib`, resolved by
    `dyld` exactly as written, never against the wheel. Same rule, same reproduction
    as the ELF tests above, checked against the other format the docstring claims it
    for.
    """
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            format=FORMAT_MACHO,
            needed=("/usr/local/opt/openssl@3/lib/libcrypto.3.dylib", "/usr/lib/libSystem.B.dylib"),
        ),
        binary(
            "pkg/plugins/libcrypto.3.dylib",
            format=FORMAT_MACHO,
            soname="libcrypto.3.dylib",
            needed=("/usr/lib/libSystem.B.dylib",),
        ),
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_SYSTEM


def test_an_absolute_basename_collision_beside_a_real_system_match_does_not_self_disagree(
    ruleset,
) -> None:
    """One object declares two `needed` entries: the absolute, basename-colliding one
    from the tests above, and a second, ordinary relative entry that genuinely matches
    the system library. The absolute short-circuit reads the absolute entry as
    `system` too, so there is only one definite posture on the object, not two: plain
    `system`, `DERIVED_SYSTEM_OPENSSL_ONLY` -- the accurate answer for a wheel that
    only ever links the system library, reached directly instead of by two postures
    disagreeing over a coincidence. Without that check, the absolute entry's spurious
    `bundled` would combine with the second entry's `system` on the *same* object, and
    `_binary_posture`'s `sum((system, bundled, static)) > 1` check would read that as
    the object's evidence disagreeing with itself: `mixed`, adding
    `BIN_OPENSSL_LINKAGE_UNKNOWN` to the findings and `OPAQUE` to `verdict.classes`
    (the headline stays `CONDITIONAL` either way here, since `BIN_NEEDED_VENDORED_
    CRYPTO` already forces it -- what the short-circuit decides is that tuple and those rule
    ids, not the headline). See `test_an_absolute_basename_collision_is_not_manufactured_bundled`
    and `test_an_absolute_needed_entry_beside_an_unreadable_basename_collision_stays_
    system` in `tests/test_acceptance.py` for the full-record assertions on findings
    and `verdict.classes` this unit test does not itself carry.
    """
    evidence = wheel(
        binary("pkg/_ext.so", needed=("/usr/lib64/libcrypto.so.3", "libssl.so.3", "libc.so.6")),
        binary("pkg/plugins/libcrypto.so.3", soname="libcrypto.so.3", needed=("libc.so.6",)),
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_SYSTEM


# --- vendoring something else is not evidence about openssl -----------------
#
# `_looks_vendored` must not treat "this object HAS a vendor-shaped rpath/runpath
# anywhere" as grounds for `unknown`, regardless of whether anything the wheel ships
# could plausibly be the target -- so a FIPS-conscious build that genuinely links the
# system OpenSSL (auditwheel's `--exclude libcrypto.so.3`) while vendoring an unrelated
# library in the same wheel would read as `unknown`/`OPAQUE` instead of `system`.


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
    misreading in the other direction.
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


def test_an_absolute_needed_entry_beside_a_vendor_shaped_runpath_stays_system_even_incomplete(
    ruleset,
) -> None:
    """`_looks_vendored` joins the *whole* `needed` string to each `RPATH`/`RUNPATH`
    entry, so an absolute path can produce a joined string that contains a vendor
    directory component by pure coincidence -- `$ORIGIN/pkg.libs` joined with
    `/usr/lib64/libcrypto.so.3` mentions `pkg.libs` in the combined string, even
    though a real loader never resolves an absolute path via RUNPATH at all. Consulted
    for this entry, `_looks_vendored` reads this incompletely-read wheel as `unknown`;
    an absolute path must never consult it, incomplete or not.
    """
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("/usr/lib64/libcrypto.so.3", "libc.so.6"),
            runpath=("$ORIGIN/pkg.libs",),
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


def test_an_absolute_needed_entry_shaped_like_a_vendor_path_itself_stays_system_even_incomplete(
    ruleset,
) -> None:
    """The other half of `_looks_vendored`: its *direct* branch,
    `conventions.is_vendor_path(needed)`, reads the `needed` string's own directory
    components without any `RPATH`/`RUNPATH` join at all -- delocate's exact
    convention, `@loader_path/.dylibs/...`, where the vendor-directory component
    means something only because the whole path is resolved relative to the loading
    object. An absolute path is never resolved relative to anything, so a real
    vendoring tool never emits one for a copy it ships -- both auditwheel and
    delocate always rewrite to a relative form -- and a vendor-glob-shaped component
    inside an absolute path (`/opt/vendor/pkg.libs/libcrypto.so.3`) is exactly as
    meaningless as the `RPATH`-join coincidence the test above pins, whether or not
    an `RPATH`/`RUNPATH` is even present.
    """
    evidence = wheel(
        binary("pkg/_ext.so", needed=("/opt/vendor/pkg.libs/libcrypto.so.3", "libc.so.6")),
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
    Without checking that field, the extension's vendor-shaped `needed` entry reads
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
    """A version script can hide every symbol; the version banner survives it. A
    real compiled-in copy keeps its build string beside its banner, which is what
    tells this apart from prose that merely names a version."""
    evidence = wheel(
        binary(
            "pkg/_ext.abi3.so",
            needed=("libc.so.6",),
            matched_strings=(OPENSSL_BANNER, OPENSSL_BUILD_INFO),
        )
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


# --- OpenSSL-named definitions beside a fork of OpenSSL's own API -----------
#
# AWS-LC and BoringSSL both implement OpenSSL's public API under OpenSSL's own
# names, so a defined `EVP_*`/`BN_*`/... symbol alone cannot tell which library was
# actually compiled in when a marker for one of them is present too.

_AWS_LC_FIPS_SYMBOL = SymbolMatch("aws_lc_fips_0_14_2_SHA256_Init", "aws_lc_fips", BINDING_DEFINED)
_AWS_LC_SYMBOL = SymbolMatch("AWSLC_fips_evp_pkey_methods_init", "aws_lc", BINDING_DEFINED)
_BORINGSSL_SYMBOL = SymbolMatch("BORINGSSL_self_test", "boringssl", BINDING_DEFINED)
_AWS_LC_STRING = StringMatch("aws_lc", "/aws-lc/crypto/mem.c")
_BORINGSSL_STRING = StringMatch("boringssl", "BoringSSL")


@pytest.mark.parametrize(
    "marker",
    [_AWS_LC_FIPS_SYMBOL, _AWS_LC_SYMBOL, _BORINGSSL_SYMBOL, _AWS_LC_STRING, _BORINGSSL_STRING],
    ids=[
        "aws-lc-fips-symbol",
        "aws-lc-symbol",
        "boringssl-symbol",
        "aws-lc-string",
        "boringssl-string",
    ],
)
def test_openssl_named_definitions_beside_a_fork_are_unknown(ruleset, marker) -> None:
    """A definition alone says an OpenSSL-API library was compiled in, not which
    one: this is the awscrt/curl_cffi/aws-lc-rs-fips shape, with no banner."""
    symbols = (SymbolMatch("BN_from_montgomery_word", "openssl", BINDING_DEFINED),)
    strings: tuple[StringMatch, ...] = ()
    if isinstance(marker, SymbolMatch):
        symbols = symbols + (marker,)
    else:
        strings = (marker,)
    evidence = wheel(
        binary(
            "pkg/_ext.so", needed=("libc.so.6",), matched_symbols=symbols, matched_strings=strings
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_UNKNOWN


def test_a_fork_symbol_the_object_only_imports_does_not_claim_its_definitions(ruleset) -> None:
    """An imported fork symbol says the object calls a fork it does not compile in
    here, so it must not turn a real, locally defined OpenSSL symbol `unknown`."""
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libc.so.6",),
            matched_symbols=(
                SymbolMatch("BN_from_montgomery_word", "openssl", BINDING_DEFINED),
                SymbolMatch("AWSLC_fips_evp_pkey_methods_init", "aws_lc", BINDING_IMPORTED),
            ),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_STATIC


def test_a_banner_beside_a_fork_still_reads_static(ruleset) -> None:
    """A banner match on a printable run distinct from any fork marker -- a real,
    dotted OpenSSL version with its own build string beside it -- is still real
    evidence of a copy, whatever else the same object also carries. The fork
    demotion only excludes a banner match that is itself the fork's own header
    text (`test_a_banner_that_is_the_forks_own_header_text_is_unknown`, below)."""
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libc.so.6",),
            matched_symbols=(SymbolMatch("BN_from_montgomery_word", "openssl", BINDING_DEFINED),),
            matched_strings=(OPENSSL_BANNER, OPENSSL_BUILD_INFO, _AWS_LC_STRING),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_STATIC


@pytest.mark.parametrize(
    ("fork_group", "banner_text"),
    [
        ("aws_lc", "OpenSSL 1.1.1 (compatible; AWS-LC 1.49.0)"),
        ("boringssl", "OpenSSL 1.1.1 (compatible; BoringSSL)"),
    ],
    ids=["aws-lc", "boringssl"],
)
def test_a_banner_that_is_the_forks_own_header_text_is_unknown(
    ruleset, fork_group, banner_text
) -> None:
    """AWS-LC's and BoringSSL's own public headers define `OPENSSL_VERSION_TEXT` as
    one string literal, which `openssl_banner` and the fork's own string group both
    match inside the very same printable run: `match_string_groups` records a
    match's `value` as the whole run, so the two matches carry the identical value.
    That banner is the fork's own header macro, not a real OpenSSL copy -- and
    `OPENSSLDIR: n/a`, both forks' own `OpenSSL_version()`, clears the copy-marker
    gate the same way a real copy's does, so the copy marker alone cannot tell them
    apart either."""
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libc.so.6",),
            matched_symbols=(SymbolMatch("BN_from_montgomery_word", "openssl", BINDING_DEFINED),),
            matched_strings=(
                StringMatch("openssl_banner", banner_text),
                StringMatch("openssl_build_info", "OPENSSLDIR: n/a"),
                StringMatch(fork_group, banner_text),
            ),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_UNKNOWN


def test_a_fork_beside_a_system_dependency_stays_mixed(ruleset) -> None:
    """A confirmed `system` dependency beside a fork-claimed definition is still a
    real posture disagreement on this one object, the same as any other
    `system`-beside-`static` shape: the fork demotion only applies once `system` and
    `bundled` have both already been ruled out."""
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libcrypto.so.3",),
            matched_symbols=(
                SymbolMatch("BN_from_montgomery_word", "openssl", BINDING_DEFINED),
                _AWS_LC_SYMBOL,
            ),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_MIXED


def test_a_fork_beside_a_system_dependency_and_its_own_banner_stays_mixed(ruleset) -> None:
    """A confirmed `system` dependency, beside the fork's own header banner rather
    than a defined fork symbol, is still `mixed`: the fork demotion only decides
    which of `static`'s two constituents -- `defined` or `banner` -- corroborates a
    real, distinct copy once `system` and `bundled` have both already been ruled
    out, in the `if static:` branch below. It never removes `banner` from `static`
    itself, so this object's own confirmed `system` dependency and its own banner
    evidence still disagree the same way `test_a_fork_beside_a_system_dependency_
    stays_mixed` does for a defined fork symbol."""
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libcrypto.so.3", "libc.so.6"),
            matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_IMPORTED),),
            matched_strings=(
                StringMatch("openssl_banner", "OpenSSL 1.1.1 (compatible; BoringSSL)"),
                StringMatch("openssl_build_info", "OPENSSLDIR: n/a"),
                StringMatch("boringssl", "OpenSSL 1.1.1 (compatible; BoringSSL)"),
            ),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_MIXED


def test_a_fork_beside_a_bundled_dependency_and_its_own_banner_stays_mixed(ruleset) -> None:
    """The bundled-shaped variant of the guarantee above: a `needed` entry that
    resolves inside the wheel, beside the fork's own header banner, is still a real
    posture disagreement on this object rather than `bundled` outright."""
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libcrypto-3a1f2b4c.so.3",),
            matched_strings=(
                StringMatch("openssl_banner", "OpenSSL 1.1.1 (compatible; BoringSSL)"),
                StringMatch("openssl_build_info", "OPENSSLDIR: n/a"),
                StringMatch("boringssl", "OpenSSL 1.1.1 (compatible; BoringSSL)"),
            ),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_MIXED


def test_a_fork_banner_alone_beside_a_copy_marker_is_unknown(ruleset) -> None:
    """The fork's own header banner, with the copy-marker string beside it and no
    `needed` entry naming any copy at all, has `static` true from `banner` alone --
    and that banner is entirely explained by `_banner_is_fork_text`. Nothing here
    is evidence of a real, distinct OpenSSL copy, only that some OpenSSL-API
    implementation is compiled in, so this reads `unknown`: real, library-specific
    evidence that does not say which copy, not `LINKAGE_NONE`."""
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libc.so.6",),
            matched_strings=(
                StringMatch("openssl_banner", "OpenSSL 1.1.1 (compatible; BoringSSL)"),
                StringMatch("openssl_build_info", "OPENSSLDIR: n/a"),
                StringMatch("boringssl", "OpenSSL 1.1.1 (compatible; BoringSSL)"),
            ),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_UNKNOWN


def test_a_real_banner_beside_the_forks_own_banner_still_reads_static(ruleset) -> None:
    """Two separate `openssl_banner` matches on one object -- a real, dotted OpenSSL
    version with its own build string, and the fork's own header text on a
    different run -- are not both fork text: `_banner_is_fork_text` only reads true
    when every `string_group` match on the object is explained by the fork's own
    patterns, and the real banner's run is not. The real banner still corroborates
    a copy, whatever else the same object also carries."""
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libc.so.6",),
            matched_symbols=(SymbolMatch("BN_from_montgomery_word", "openssl", BINDING_DEFINED),),
            matched_strings=(
                OPENSSL_BANNER,
                OPENSSL_BUILD_INFO,
                StringMatch("openssl_banner", "OpenSSL 1.1.1 (compatible; BoringSSL)"),
                StringMatch("boringssl", "OpenSSL 1.1.1 (compatible; BoringSSL)"),
            ),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_STATIC


def test_a_fork_marker_alone_leaves_openssl_none(ruleset) -> None:
    """A fork marker with no OpenSSL-named evidence at all creates none: it is not
    itself OpenSSL evidence, only a reason to read OpenSSL evidence differently."""
    evidence = wheel(
        binary("pkg/_ext.so", needed=("libc.so.6",), matched_symbols=(_AWS_LC_SYMBOL,))
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_NONE


# --- a crate says the object uses OpenSSL, not which copy -------------------


def rust_object(*crates: RustCrate, **fields) -> BinaryEvidence:
    """An object read in full that is not opaque without its crates."""
    fields.setdefault("needed", ("libc.so.6",))
    return binary("pkg/_rust.abi3.so", dynsym_count=1, rust_crates=crates, **fields)


@pytest.mark.parametrize("crate", ["openssl", "openssl-sys", "openssl-src"])
def test_an_openssl_crate_with_no_other_openssl_evidence_is_unknown(ruleset, crate) -> None:
    """`openssl-sys` links the host's OpenSSL or vendors its own on a build feature the
    object does not record. `none` here would say there is no OpenSSL beside a finding
    for the crate that binds it."""
    evidence = wheel(rust_object(RustCrate(crate, "0.9.117")))
    # The whole mapping, not one key: a crate moves only the library that lists it.
    assert resolve_linkage(ruleset, evidence) == {"openssl": LINKAGE_UNKNOWN}


def test_a_crate_that_does_not_bind_openssl_leaves_it_none(ruleset) -> None:
    """Only the crates `[[crypto_library]] openssl` lists: `ring` is crypto of its own."""
    evidence = wheel(rust_object(RustCrate("ring", "0.17.8")))
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_NONE


@pytest.mark.parametrize(
    ("fields", "posture"),
    [
        ({"matched_strings": (OPENSSL_BANNER, OPENSSL_BUILD_INFO)}, LINKAGE_STATIC),
        ({"needed": ("libc.so.6", "libssl.so.3")}, LINKAGE_SYSTEM),
    ],
    ids=["banner", "needed"],
)
def test_an_openssl_crate_never_overrides_the_objects_own_evidence(
    ruleset, fields, posture
) -> None:
    """cryptography off PyPI carries `openssl-sys` beside its banner; a build against the
    host's OpenSSL carries it beside `DT_NEEDED libssl.so.3`. The crate adds nothing."""
    evidence = wheel(rust_object(RustCrate("openssl-sys", "0.9.117"), **fields))
    assert resolve_linkage(ruleset, evidence)["openssl"] == posture


def test_an_openssl_crate_alone_does_not_outvote_a_sibling_that_answers(ruleset) -> None:
    """A crate's `unknown` aggregates like any other: never over a definite posture.

    The field keeps the sibling's posture: the crate-only object has no `needed`
    entry and no import, so it is more likely a static copy than a system one, and
    `resolve_linkage` still reads `system` for the wheel. The rules withhold
    `DERIVED_SYSTEM_OPENSSL_ONLY` beside the crate-only object instead (see
    `tests/test_engine.py::test_an_object_that_read_unknown_withholds_the_system_only_rule`).
    """
    evidence = wheel(
        rust_object(RustCrate("openssl-sys", "0.9.117")),
        binary("pkg/_ssl.so", needed=("libc.so.6", "libssl.so.3")),
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_SYSTEM


def test_object_postures_are_what_the_field_is_aggregated_from(ruleset) -> None:
    """`object_postures` is the per-object tuple `resolve_linkage` reduces through
    `_aggregate`, in `evidence.binaries` order -- not reversed, not deduplicated.
    """
    evidence = wheel(
        rust_object(RustCrate("openssl-sys", "0.9.117")),
        binary("pkg/_ssl.so", needed=("libc.so.6", "libssl.so.3")),
    )
    assert object_postures(ruleset, evidence, "openssl") == (LINKAGE_UNKNOWN, LINKAGE_SYSTEM)
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_SYSTEM


# --- an SBOM says the wheel uses a library, not which copy -------------------


@pytest.mark.parametrize("name", ["openssl", "openssl-sys", "openssl-src"])
def test_an_sbom_naming_an_openssl_crate_with_no_object_evidence_is_unknown(ruleset, name) -> None:
    """An SBOM naming `openssl-sys`, with only an unrelated dependency in the one
    object present, must not read `none`."""
    evidence = wheel(
        binary("pkg/_rust.abi3.so", needed=("libc.so.6",), dynsym_count=1),
        metadata=sbom(name),
    )
    assert resolve_linkage(ruleset, evidence) == {"openssl": LINKAGE_UNKNOWN}


def test_an_sbom_alone_with_no_binary_is_unknown(ruleset) -> None:
    """The signal does not depend on any object existing at all."""
    evidence = wheel(metadata=sbom("openssl-sys"))
    assert resolve_linkage(ruleset, evidence) == {"openssl": LINKAGE_UNKNOWN}


def test_an_sbom_component_moves_only_the_library_it_names(ruleset) -> None:
    """Library-specific, and not gated on `always_report`: `libsodium` is not always
    reported, but the SBOM naming it still moves its own field."""
    evidence = wheel(metadata=sbom("libsodium"))
    assert resolve_linkage(ruleset, evidence) == {
        "openssl": LINKAGE_NONE,
        "libsodium": LINKAGE_UNKNOWN,
    }


@pytest.mark.parametrize("name", ["ring", "cryptography", "libcrypto"])
def test_an_sbom_component_that_does_not_bind_openssl_leaves_it_none(ruleset, name) -> None:
    """`ring` is a rust_crate that is not one of openssl's `crates`; `cryptography` is
    a `crypto_distribution`, not a copy of the library; `libcrypto` is a soname, which
    this field never compares against an SBOM component name."""
    evidence = wheel(metadata=sbom(name))
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_NONE


@pytest.mark.parametrize("name", ["OpenSSL", "OPENSSL-SYS", "openssl_sys", "OpenSSL_Src"])
def test_an_sbom_component_spelled_differently_still_names_openssl(ruleset, name) -> None:
    """The comparison folds through `ruleset.sbom_library_key`/`sbom_crate_key`, like
    `SBOM_CRYPTO_COMPONENT`'s own (`engine._sbom_entry`'s table lookups): a C library
    name is only case-folded, and a crate name also treats `-` and `_` as the same
    character, the way crates.io does. A component spelled with different case, or
    with `-`/`_` swapped for a crate, still names the same library."""
    evidence = wheel(metadata=sbom(name))
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_UNKNOWN


@pytest.mark.parametrize("name", ["argon2", "blake2"])
def test_an_sbom_naming_a_pure_rust_crate_does_not_move_its_colliding_c_library(
    ruleset, name
) -> None:
    """`argon2` and `blake2` are each both a `[[crypto_library]]` (the C reference
    implementations, libargon2 and libb2) and a *different* `[[rust_crate]]` of the
    same name (the pure-Rust RustCrypto crates, which do not bind the C library).
    Neither C library lists its own name in `crates`, unlike `openssl`, whose crate of
    the same name really does bind libssl/libcrypto. An SBOM component naming the
    pure-Rust crate -- a `pkg:cargo/...` purl, the crates.io registry type -- must not
    move the C library's linkage: that would claim the wheel carries a C library it
    does not."""
    evidence = wheel(metadata=sbom(name, purl=f"pkg:cargo/{name}@0.5.3"))
    assert name not in resolve_linkage(ruleset, evidence)


@pytest.mark.parametrize("name", ["argon2", "blake2"])
@pytest.mark.parametrize("purl", [None, "pkg:generic/{name}"], ids=["no-purl", "generic-purl"])
def test_an_sbom_naming_the_c_library_under_the_colliding_name_still_moves_it(
    ruleset, name, purl
) -> None:
    """The same name collision as above, but the component's `purl` does not say
    `pkg:cargo/...` -- either there is none at all, or it is a non-cargo type such as
    `pkg:generic/...`, the shape a real libargon2/libb2 SBOM entry would carry. Only a
    cargo purl says "this is the pure-Rust crate"; anything else still could name the
    C library, so it must still move `<name>_linkage`, the same as any other
    `[[crypto_library]]` name with no rust_crate collision. Leaving this unmoved would
    report `SBOM_CRYPTO_COMPONENT` on the name (`engine._sbom_entry` matches by name
    alone) with no field reflecting it."""
    evidence = wheel(metadata=sbom(name, purl=purl.format(name=name) if purl else None))
    assert resolve_linkage(ruleset, evidence)[name] == LINKAGE_UNKNOWN


@pytest.mark.parametrize("name", ["argon2", "blake2"])
def test_an_sbom_naming_both_the_crate_and_the_c_library_under_the_colliding_name_moves_it(
    ruleset, name
) -> None:
    """A real SBOM can carry more than one component under the colliding name: the
    pure-Rust crate (a `pkg:cargo/...` purl) and, separately, the C reference
    implementation (`pkg:generic/...` or no purl at all) it does not bind. This is the
    `any`, not `all`, direction of `_declared_by_sbom`'s purl check -- only one of the
    two components present needs a non-cargo purl for the C library to still count,
    so the cargo-purl component naming the crate must not hide the other one that
    names the C library."""
    metadata = MetadataEvidence(
        name="demo",
        canonical_name="demo",
        version="1.0",
        sbom_components=(
            SbomComponent(
                name, "0.5.3", f"pkg:cargo/{name}@0.5.3", "demo-1.0.dist-info/sboms/a.cdx.json"
            ),
            SbomComponent(name, "1.0.0", None, "demo-1.0.dist-info/sboms/a.cdx.json"),
        ),
    )
    evidence = wheel(metadata=metadata)
    assert resolve_linkage(ruleset, evidence)[name] == LINKAGE_UNKNOWN


@pytest.mark.parametrize("name", ["Argon2", "BLAKE2"])
def test_the_collision_purl_check_also_folds_case(ruleset, name) -> None:
    """The same `argon2`/`blake2` collision as above, spelled with different case: the
    purl check has to run on the folded key, not the SBOM's own spelling, or a case
    variant of the pure-Rust crate's name would fall through to the C library's own
    name arm and move a field the cargo purl says it must not."""
    cargo = wheel(metadata=sbom(name, purl=f"pkg:cargo/{name.lower()}@0.5.3"))
    assert name.lower() not in resolve_linkage(ruleset, cargo)
    no_purl = wheel(metadata=sbom(name))
    assert resolve_linkage(ruleset, no_purl)[name.lower()] == LINKAGE_UNKNOWN


def _mixed_case_collision_ruleset():
    """A ruleset whose colliding `[[crypto_library]]`/`[[rust_crate]]` names are not
    already lower-case, unlike `argon2`/`blake2` in the shipped ruleset. Pins that
    `_declared_by_sbom` folds `library.name` itself -- not just the SBOM component's
    own spelling -- before comparing it: reverting either fold on `library.name` to a
    raw string compare still passes every collision test run against the shipped
    ruleset, because its colliding names are already lower-case there.

    Also carries `LibFoo`, a mixed-case `[[crypto_library]]` with no `[[rust_crate]]`
    of the same name: the non-collision arm of `_declared_by_sbom` folds
    `library.name` too, and every shipped library name is already lower-case, so a
    raw compare there would pass every other test in this file as well.
    """
    return parse_ruleset(
        {
            "ruleset_version": "test",
            "verdict": {"precedence": ["NON_APPROVED_CRYPTO", "NO_CRYPTO_DETECTED"]},
            "limits": {
                "max_locations_per_finding": 10,
                "max_symbols_per_binary": 64,
                "max_strings_per_binary": 64,
                "max_rust_crates_per_binary": 128,
                "max_evidence_chars": 200,
                "min_string_length": 4,
            },
            "conventions": {
                "vendor_dir_globs": ["*.libs", ".dylibs"],
                "mangled_soname_regex": r"^(?P<stem>lib.+)-(?P<hash>[0-9a-f]{6,32})$",
                "windows_version_suffix_regex": (
                    r"^(?P<stem>.+?)-(?P<version>[0-9]+(_[0-9]+)?)"
                    r"(-(?P<decoration>[A-Za-z0-9_]+))?$"
                ),
                "cargo_path_regex": (
                    r"cargo/registry/src/[^/]+/(?P<name>[a-z-]+)-(?P<version>[0-9.]+)/"
                ),
                "cargo_vendor_path_regex": r"vendor/(?P<name>[a-z-]+)(?:-(?P<version>[0-9.]+))?/",
                "cargo_git_path_regex": (
                    r"git/checkouts/(?P<name>[a-z-]+)-[0-9a-f]{16}/(?P<version>(?!))?"
                ),
                "weak_hash_algorithms": ["md5", "sha1"],
                "library_suffixes": [".so", ".dylib", ".dll", ".pyd"],
                "windows_library_suffixes": [".dll", ".pyd"],
                "go_boring_group": "go_boring",
                "go_stock_group": "go_stock_crypto",
                "go_fips140_group": "go_fips140",
            },
            "crypto_distribution": [],
            "crypto_library": [
                {
                    "name": "Argon2",
                    "sonames": ["libargon2"],
                    "verdict": "NON_APPROVED_CRYPTO",
                    "severity": "high",
                    "why": "the C reference implementation",
                },
                {
                    "name": "LibFoo",
                    "sonames": ["libfoo"],
                    "verdict": "NON_APPROVED_CRYPTO",
                    "severity": "high",
                    "why": "a mixed-case library with no rust_crate of the same name",
                },
            ],
            "symbol_group": [],
            "string_group": [
                {"name": "go_boring", "substrings": ["crypto/internal/boring"], "why": "boring"},
                {"name": "go_stock_crypto", "substrings": ["crypto/sha256."], "why": "stock"},
                {"name": "go_fips140", "substrings": ["GOFIPS140="], "why": "fips module"},
            ],
            "rust_crate": [
                {
                    "name": "argon2",
                    "verdict": "NON_APPROVED_CRYPTO",
                    "severity": "medium",
                    "why": "the pure-Rust RustCrypto crate of the same name",
                }
            ],
            "python_module": [],
            "ctypes_library": [],
            "rule": [
                {
                    "id": "SBOM_CRYPTO_COMPONENT",
                    "layer": "metadata",
                    "category": "bundled-crypto",
                    "severity": "high",
                    "confidence": "high",
                    "needs_human_review": True,
                    "title": "t",
                    "why": "w",
                    "match": {"kind": "sbom_component", "tables": ["crypto_library", "rust_crate"]},
                }
            ],
        }
    )


def test_the_collision_check_folds_the_rulesets_own_library_name_too() -> None:
    """`argon2` and `blake2` collide with a `[[rust_crate]]` of the same name in the
    shipped ruleset, but both are already lower-case there, so a mutation comparing
    `library.name` raw instead of through `sbom_library_key`/`sbom_crate_key` still
    passes every test run against it. A ruleset whose colliding name is not already
    lower-case (`Argon2`) pins the fold in both directions: a no-purl SBOM component
    still moves the field (it could name the C library), and a `pkg:cargo/...` one
    still does not (it names the unrelated pure-Rust crate instead)."""
    collision_ruleset = _mixed_case_collision_ruleset()
    no_purl = wheel(metadata=sbom("Argon2"))
    assert resolve_linkage(collision_ruleset, no_purl)["Argon2"] == LINKAGE_UNKNOWN
    cargo = wheel(metadata=sbom("Argon2", purl="pkg:cargo/argon2@0.1.0"))
    assert "Argon2" not in resolve_linkage(collision_ruleset, cargo)


def test_the_non_collision_check_folds_the_rulesets_own_library_name_too() -> None:
    """`LibFoo` has no `[[rust_crate]]` of the same name, so `_declared_by_sbom` takes
    the non-collision arm, comparing `library.name` against the SBOM's keys directly.
    Every shipped library name is already lower-case, so a mutation comparing
    `library.name` raw instead of through `sbom_library_key` still passes every other
    test in this file; this one pins the fold with a library name that is not."""
    collision_ruleset = _mixed_case_collision_ruleset()
    evidence = wheel(metadata=sbom("libfoo"))
    assert resolve_linkage(collision_ruleset, evidence)["LibFoo"] == LINKAGE_UNKNOWN


# --- declared_by_sbom agrees with the field it is folded into ----------------


def test_declared_by_sbom_agrees_with_the_field_for_every_library_and_its_crates(ruleset) -> None:
    """`declared_by_sbom` is the rule-facing view of the same signal `resolve_linkage`
    folds into `_aggregate` through `_declared_by_sbom`; a rule reading one and a
    record reading the other must never disagree about what one SBOM component means.
    Checked on a wheel with no binary objects at all, so nothing there can supply a
    `_DEFINITE` posture to outvote it either way.
    """
    for library in ruleset.libraries.values():
        for name in {library.name, *library.crates}:
            evidence = wheel(metadata=sbom(name))
            expected = resolve_linkage(ruleset, evidence).get(library.name) == LINKAGE_UNKNOWN
            assert declared_by_sbom(ruleset, evidence, library.name) == expected, (
                library.name,
                name,
            )


@pytest.mark.parametrize("name", ["ring", "cryptography"])
def test_declared_by_sbom_agrees_with_the_field_for_an_unrelated_component(ruleset, name) -> None:
    evidence = wheel(metadata=sbom(name))
    assert declared_by_sbom(ruleset, evidence, "openssl") is False
    assert resolve_linkage(ruleset, evidence).get("openssl", LINKAGE_NONE) != LINKAGE_UNKNOWN


@pytest.mark.parametrize(
    ("purl", "expected"),
    [("pkg:cargo/argon2@0.5.0", False), ("pkg:generic/argon2@0.5.0", True)],
)
def test_declared_by_sbom_agrees_with_the_field_for_the_argon2_collision(
    ruleset, purl, expected
) -> None:
    """The collision `declared_by_sbom` resolves through the component's own `purl`
    rather than by name alone: only a `pkg:cargo/...` purl names the unrelated
    pure-Rust crate, and only there must the C library's own field and this function
    both stay untouched.
    """
    evidence = wheel(metadata=sbom("argon2", purl=purl))
    assert declared_by_sbom(ruleset, evidence, "argon2") is expected
    moved = resolve_linkage(ruleset, evidence).get("argon2") == LINKAGE_UNKNOWN
    assert moved == expected


def test_declared_by_sbom_is_false_when_the_system_object_itself_carries_the_crate(
    ruleset,
) -> None:
    """A component naming a crate that is also the crate a `system`-posture object
    carries in its own cargo paths is not "declared beside system" at all: that object
    already answered `system` from its own evidence, and the SBOM restates it rather
    than naming a second, unaccounted-for copy. `openssl_linkage` itself is unaffected
    either way (`system`, from the object alone): `_aggregate` never reaches `declared`
    once a `_DEFINITE` posture exists.
    """
    rust_object = binary(
        "demo/_rust.abi3.so",
        needed=("libc.so.6", "libssl.so.3"),
        rust_crates=(RustCrate("openssl-sys", "0.9.117"),),
    )
    evidence = wheel(rust_object, metadata=sbom("openssl-sys"))
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_SYSTEM
    assert declared_by_sbom(ruleset, evidence, "openssl") is False


@pytest.mark.parametrize(
    ("carried", "spelling"),
    [
        ("openssl-sys", "OpenSSL_Sys"),
        ("openssl_sys", "openssl-sys"),
        ("OpenSSL_Sys", "OPENSSL-SYS"),
    ],
)
def test_declared_by_sbom_folds_the_crate_a_system_object_carries(
    ruleset, carried, spelling
) -> None:
    """The confirmation is compared through `sbom_crate_key` on both sides, the same
    fold every other SBOM name goes through: a component spelling the carried crate
    another way crates.io treats as the same crate is still the crate that object
    already answered `system` for, not a second copy.
    """
    rust_object = binary(
        "demo/_rust.abi3.so",
        needed=("libc.so.6", "libssl.so.3"),
        rust_crates=(RustCrate(carried, "0.9.117"),),
    )
    evidence = wheel(rust_object, metadata=sbom(spelling))
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_SYSTEM
    assert declared_by_sbom(ruleset, evidence, "openssl") is False


@pytest.mark.parametrize(
    "purl",
    [None, "pkg:generic/openssl@3.3.1", "pkg:rpm/redhat/openssl@3.2.2"],
    ids=["no-purl", "generic", "rpm"],
)
def test_declared_by_sbom_ignores_the_exemption_for_a_non_cargo_openssl_component(
    ruleset, purl
) -> None:
    """The exemption only ever reaches the plain by-name check: `openssl` collides
    with a `[[rust_crate]]` of its own name (it lists itself in `crates`), so a
    component named `openssl` is matched through its own `purl` instead, read straight
    off the unfiltered SBOM rather than the exemption's filtered name set. A component
    under a non-cargo purl, or none, does not claim to be the crate the exemption
    confirms -- only the C library itself -- so it still counts as declared even beside
    a system object that carries the `openssl` crate in its own cargo paths.
    """
    rust_object = binary(
        "demo/_rust.abi3.so",
        needed=("libc.so.6", "libssl.so.3"),
        rust_crates=(RustCrate("openssl", "0.10.66"),),
    )
    evidence = wheel(rust_object, metadata=sbom("openssl", purl=purl))
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_SYSTEM
    assert declared_by_sbom(ruleset, evidence, "openssl") is True


def test_declared_by_sbom_is_true_when_only_a_non_system_object_carries_the_crate(
    ruleset,
) -> None:
    """The exemption reads the crate-carrying object's own posture, not merely whether
    some object carries the crate: a second object that carries the same crate but
    reads `unknown` on its own (no `needed` entry naming it) does not confirm the SBOM
    component, so it still counts as declared beside the system-linked sibling.
    """
    system_object = binary("demo/_ssl.so", needed=("libc.so.6", "libssl.so.3"))
    crate_object = binary(
        "demo/_rust.abi3.so", needed=("libc.so.6",), rust_crates=(RustCrate("openssl-sys", None),)
    )
    evidence = wheel(system_object, crate_object, metadata=sbom("openssl-sys"))
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_SYSTEM
    assert declared_by_sbom(ruleset, evidence, "openssl") is True


@pytest.mark.parametrize(
    ("fields", "posture"),
    [
        ({"needed": ("libc.so.6", "libssl.so.3")}, LINKAGE_SYSTEM),
        ({"matched_strings": (OPENSSL_BANNER, OPENSSL_BUILD_INFO)}, LINKAGE_STATIC),
    ],
    ids=["needed", "banner"],
)
def test_an_sbom_never_overrides_what_an_object_answers(ruleset, fields, posture) -> None:
    evidence = wheel(binary("pkg/_ext.so", **fields), metadata=sbom("openssl-sys"))
    assert resolve_linkage(ruleset, evidence)["openssl"] == posture


# --- system and static within one object ------------------------------------
#
# Testing `needed` first and returning as soon as `_binary_posture` finds a system
# match would mean an object that both declares `DT_NEEDED libssl.so.3` and defines
# `EVP_DigestInit_ex` itself (or carries an OpenSSL banner) never reaches the
# defined/banner check at all: it reads `system`, and the record then pairs
# `DERIVED_SYSTEM_OPENSSL_ONLY` ("every piece of OpenSSL evidence points at the
# system library") with `BIN_OPENSSL_SYMBOLS_DEFINED` ("OpenSSL was compiled into
# it") -- a record contradicting itself in the favourable direction. Both
# observations are independently true, so the object's own posture is `mixed`,
# the same value `_aggregate` gives two objects that disagree.


def test_a_needed_system_match_and_a_defined_symbol_together_are_mixed(ruleset) -> None:
    """One object, both signals, in the same record."""
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
    to the system library.

    No imported symbol on this object, so it also guards gate (b) below: without a
    confirmed import from the resolved library, a banner beside a `needed` match
    stays a copy rather than becoming header text.
    """
    evidence = wheel(
        binary("pkg/_ext.so", needed=("libssl.so.3",), matched_strings=(OPENSSL_BANNER,))
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_MIXED


# --- a header banner beside imports from the resolved system library is not a copy --
#
# `OPENSSL_VERSION_TEXT` is a header macro: any consumer that includes OpenSSL's
# headers compiles the current banner in, whether or not it links OpenSSL at all. A
# banner is therefore not evidence of a compiled-in copy when the object also imports
# from a `needed` entry that already resolved to the system library -- it is exactly
# what the system library's own header would produce. A real copy's `OpenSSL_version()`
# returns the banner and the `OPENSSLDIR: ` string from the same switch, so a genuine
# static copy keeps both; a header only ever supplies the banner macro.


def test_a_header_banner_beside_imports_from_the_system_library_is_system(ruleset) -> None:
    """The Fedora shape: a `needed` match, imported OpenSSL symbols, and a banner with
    no build strings beside it. The banner is header text, so `static` is false and
    the object reads plain `system`."""
    evidence = wheel(
        binary(
            "cryptography/hazmat/bindings/_rust.abi3.so",
            needed=("libssl.so.3", "libcrypto.so.3", "libc.so.6"),
            matched_symbols=(
                SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_IMPORTED),
                SymbolMatch("SSL_CTX_new", "openssl", BINDING_IMPORTED),
            ),
            matched_strings=(OPENSSL_BANNER,),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_SYSTEM


def test_a_banner_beside_an_openssl_build_string_stays_mixed(ruleset) -> None:
    """The same object, but the banner is accompanied by a build string only a real
    compiled-in copy carries beside its banner -- which it does whenever something in
    the object actually calls `OpenSSL_version()`, the shape a merged universal
    binary's hidden slice or a static libcrypto beside a dynamic system libssl reads as
    when that call is reachable: the marker means the banner is not header text after
    all, so the object stays `mixed`."""
    evidence = wheel(
        binary(
            "cryptography/hazmat/bindings/_rust.abi3.so",
            needed=("libssl.so.3", "libcrypto.so.3", "libc.so.6"),
            matched_symbols=(
                SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_IMPORTED),
                SymbolMatch("SSL_CTX_new", "openssl", BINDING_IMPORTED),
            ),
            matched_strings=(OPENSSL_BANNER, OPENSSL_BUILD_INFO),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_MIXED


@pytest.mark.parametrize(
    "reason",
    [PARTIAL_STRINGS_BYTES_UNREAD, PARTIAL_ELF_GO_BUILDINFO_UNREAD],
)
def test_a_header_banner_on_a_partially_read_object_stays_mixed(ruleset, reason: str) -> None:
    """A partial read may have cut the very string that would have proven the banner
    is a copy, so the gate never opens for an object that was not read in full -- for
    any cause, not only the ones `[linkage_policy] exclude_reasons` leaves answerable.
    `PARTIAL_ELF_GO_BUILDINFO_UNREAD` is on that exclude list, which is what shows this
    gate is its own, stricter split rather than a reuse of it."""
    evidence = wheel(
        binary(
            "cryptography/hazmat/bindings/_rust.abi3.so",
            needed=("libssl.so.3", "libcrypto.so.3", "libc.so.6"),
            matched_symbols=(
                SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_IMPORTED),
                SymbolMatch("SSL_CTX_new", "openssl", BINDING_IMPORTED),
            ),
            matched_strings=(OPENSSL_BANNER,),
            partial_analysis=True,
            partial_reasons=(reason,),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_MIXED


def test_a_banner_and_imports_without_a_dependency_are_unknown(ruleset) -> None:
    """No `needed` entry resolves the library at all, so imports alone say "uses,
    not which copy" -- whatever provides them is outside this wheel -- and the
    banner, with none of the build strings a real copy keeps beside it, adds no
    copy either. Neither half of the object's own evidence confirms a copy, so the
    object reads `unknown` rather than `static`."""
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libc.so.6",),
            matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_IMPORTED),),
            matched_strings=(OPENSSL_BANNER,),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_UNKNOWN


def test_a_banner_with_build_strings_and_imports_without_a_dependency_is_static(ruleset) -> None:
    """Same shape, but the banner keeps its build string beside it: a real copy, so
    the imports the object also carries do not demote it below `static`."""
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libc.so.6",),
            matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_IMPORTED),),
            matched_strings=(OPENSSL_BANNER, OPENSSL_BUILD_INFO),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_STATIC


def test_a_library_without_a_copy_string_group_always_counts_its_banner(ruleset) -> None:
    """libsodium names no `copy_string_group`, so it has no way to tell a header
    banner from a copy, and a banner beside a system dependency and imports stays a
    real posture disagreement: `mixed`, the reading OpenSSL's banner would get with no
    `copy_string_group` to consult either."""
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libsodium.so.23",),
            matched_symbols=(SymbolMatch("crypto_box_seal", "libsodium", BINDING_IMPORTED),),
            matched_strings=(StringMatch("libsodium", "libsodium 1.0.18"),),
        )
    )
    assert resolve_linkage(ruleset, evidence)["libsodium"] == LINKAGE_MIXED


# --- a banner with no dependency and no build strings is uncorroborated prose ----
#
# `openssl_banner` matches any sentence naming a dotted OpenSSL version, not only the
# real banner: "enable OpenSSL 3.0 legacy provider" matches the same way "OpenSSL
# 3.0.14 4 Jun 2024" does. On an object with no `needed` entry naming the library at
# all, only the build strings a compiled-in copy keeps beside its banner tell the two
# apart.


@pytest.mark.parametrize(
    "value",
    [
        "OpenSSL 3.0 does not support direct access to RSA key",
        "enable OpenSSL 3.0 legacy provider",
        "For OpenSSL 3.0.0 and newer it returns the state of the default provider",
        "OpenSSL 3.0.14 4 Jun 2024",
    ],
    ids=["prose-1", "prose-2", "prose-3", "real-banner-as-header-text"],
)
def test_a_banner_without_build_strings_on_an_object_with_no_dependency_is_unknown(
    ruleset, value: str
) -> None:
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libc.so.6",),
            matched_strings=(StringMatch("openssl_banner", value),),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_UNKNOWN


def test_a_banner_beside_build_strings_on_an_object_with_no_dependency_is_static(ruleset) -> None:
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libc.so.6",),
            matched_strings=(OPENSSL_BANNER, OPENSSL_BUILD_INFO),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_STATIC


@pytest.mark.parametrize(
    "reason",
    [PARTIAL_STRINGS_BYTES_UNREAD, PARTIAL_ELF_GO_BUILDINFO_UNREAD],
)
def test_a_banner_without_build_strings_on_a_partially_read_object_stays_static(
    ruleset, reason: str
) -> None:
    """A partial read may have cut the very string that would have proven the
    banner is a copy, so the gate never opens for an object not read in full."""
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libc.so.6",),
            matched_strings=(OPENSSL_BANNER,),
            partial_analysis=True,
            partial_reasons=(reason,),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_STATIC


def test_a_library_without_a_copy_string_group_counts_a_banner_alone_as_static(ruleset) -> None:
    """libsodium names no `copy_string_group`, so it has no way to tell uncorroborated
    prose from a copy, and a banner with no dependency at all still counts as
    `static` outright -- the reading `openssl`'s banner would get with no
    `copy_string_group` to consult either."""
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libc.so.6",),
            matched_strings=(StringMatch("libsodium", "libsodium 1.0.18"),),
        )
    )
    assert resolve_linkage(ruleset, evidence)["libsodium"] == LINKAGE_STATIC


# `test_an_uncertain_needed_match_and_a_banner_together_are_mixed`, above, already
# guards the scope limit here by mutation: dropping `uncertain` from the
# `not (system or bundled or uncertain)` term would demote that object's confirmed
# `uncertain`-beside-`banner` disagreement to plain `unknown` instead of `mixed`.


def test_a_merged_universal_binary_whose_slices_disagree_is_mixed(ruleset) -> None:
    """`DESIGN.md`'s "A universal binary is one record, and its slices are
    merged": an x86_64 slice linking the host OpenSSL and an arm64 slice with it
    compiled in, reduced by the Mach-O reader into one `BinaryEvidence` whose
    `needed` and `matched_symbols` are the union of both slices. Testing `needed`
    first would read this `system`; it is `mixed`, matching what reading the slices
    separately and letting `_aggregate` combine them says.
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
    """No defined symbol and no banner: the ordinary system case."""
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libssl.so.3",),
            matched_symbols=(SymbolMatch("SSL_new", "openssl", BINDING_IMPORTED),),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_SYSTEM


def test_a_defined_symbol_alone_is_still_static(ruleset) -> None:
    """No `needed` match at all: the ordinary static case."""
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libc.so.6",),
            matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_DEFINED),),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_STATIC


# --- uncertain and static within one object ---------------------------------
#
# Returning `LINKAGE_UNKNOWN` from `_binary_posture` for the `uncertain` case -- a
# `needed` entry whose path/rpath shape looks vendored but that an incompletely-read
# wheel cannot confirm either way -- before the defined/banner check a few lines below
# it ever runs would read an object with both an unconfirmed vendor-shaped `needed`
# entry and a confirmed static definition (or banner) as `unknown` regardless,
# silently discarding the confirmed evidence. The same rule as `system` beside
# `static` applies: `mixed`, not a value that erases one of the two facts.


def test_an_uncertain_needed_match_and_a_defined_symbol_together_are_mixed(ruleset) -> None:
    """An incompletely-read wheel (`errors` at `STAGE_BINARY`), a `needed` entry
    whose `RUNPATH` looks vendor-shaped but names nothing the wheel actually ships, and
    a real `EVP_DigestInit_ex` definition in the same object.
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
    the string survives it, same as the `system`-beside-`static` banner variant."""
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
    """No static evidence at all: the ordinary `uncertain` case."""
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
    `uncertain` one, so this stays plain `system`, not a three-way `mixed`.
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
    `static` are also both true here, so the `_DEFINITE`-count branch already answers
    `mixed` before `_binary_posture` ever reaches the `if uncertain and static`
    branch. That makes this specific shape provably unable to distinguish the two
    branches, or their relative order, from `resolve_linkage`'s output alone:
    deleting the `uncertain`-and-`static` branch entirely, or moving it ahead of the
    `system` checks, both leave this test green, because either branch produces the
    identical `mixed`. Mutation confirms it.

    The `uncertain`-and-`static` branch's own ordering is pinned by the two-signal
    tests instead (`test_an_uncertain_needed_match_and_a_defined_symbol_together_are_
    mixed` and its banner variant, above), where `system` is false and only that
    branch can produce `mixed` at all; removing it turns those two red. This test
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


# --- bundled and system/static within one object ----------------------------
#
# Returning `LINKAGE_BUNDLED` from `_binary_posture`'s `needed` loop as soon as one
# entry resolves that way, before a second, disagreeing `needed` entry on the same
# object -- or the defined/static check a few lines below -- ever runs, would lose the
# disagreement. A universal Mach-O object merges its slices' `needed` tuples into one
# (`binfmt.macho`, pinned by `test_load_dylibs_merge_across_slices` in
# `test_binfmt_macho.py`), so a fat object whose slices disagree about `bundled` versus
# `system` or `static` would read `bundled` outright instead of `mixed`, unlike the
# same evidence read as two separate objects.


def test_a_bundled_needed_match_and_a_system_needed_match_together_are_mixed(ruleset) -> None:
    """One object, one `needed` entry hash-renamed (`bundled`), a different `needed`
    entry an absolute path to the host library (`system`). Same evidence in two separate
    objects already reads `mixed` via `_aggregate`; this object's own evidence must read
    the same way.
    """
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libcrypto-3a1f2b4c.so.3", "/usr/lib64/libcrypto.so.3"),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_MIXED


def test_a_bundled_needed_match_and_a_defined_symbol_together_are_mixed(ruleset) -> None:
    """One hash-renamed `needed` entry, and a real `EVP_DigestInit_ex` definition in
    the same object -- the shape a Mach-O universal binary merges into one record when
    one slice declares the vendored dependency and the other has OpenSSL compiled in.
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
    """The banner-only variant of the same contradiction, matching the `system` and
    `uncertain` banner variants above. No imported symbol on this object, so it also
    guards gate (b) on the bundled side of `_banner_is_header_text`: without a
    confirmed import from the resolved copy, a banner beside a bundled `needed`
    match stays a copy rather than becoming header text.
    """
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libcrypto-3a1f2b4c.so.3",),
            matched_strings=(OPENSSL_BANNER,),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_MIXED


def test_a_bundled_needed_match_alone_is_still_bundled(ruleset) -> None:
    """No other signal: the ordinary bundled case, reached after the `_DEFINITE`-count
    check rather than by returning from inside the loop.
    """
    evidence = wheel(binary("pkg/_ext.so", needed=("libcrypto-3a1f2b4c.so.3",)))
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_BUNDLED


# --- a header banner beside imports from a resolved bundled copy is not a copy --
#
# The same header-text reasoning as the system case applies once a `needed` entry
# resolved the library to a copy the wheel itself ships: auditwheel's own headers
# supply `OPENSSL_VERSION_TEXT` to the extension it patches, whether or not that
# extension calls into the copy it now depends on.


def test_a_header_banner_beside_imports_from_a_bundled_copy_is_bundled(ruleset) -> None:
    """The auditwheel shape: the extension NEEDs the hash-renamed vendored copy,
    imports from it, and carries a header banner with no build strings. The banner
    is header text, so `static` is false and the object reads plain `bundled`."""
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libcrypto-3a1f2b4c.so.3", "libc.so.6"),
            matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_IMPORTED),),
            matched_strings=(OPENSSL_BANNER,),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_BUNDLED


def test_a_bundled_banner_beside_an_openssl_build_string_stays_mixed(ruleset) -> None:
    """The same object, but the banner is accompanied by the build string only a
    real compiled-in copy carries beside its banner: the marker means the banner is
    not header text after all, so the object stays `mixed`."""
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libcrypto-3a1f2b4c.so.3", "libc.so.6"),
            matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_IMPORTED),),
            matched_strings=(OPENSSL_BANNER, OPENSSL_BUILD_INFO),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_MIXED


def test_a_header_banner_beside_a_bundled_copy_on_a_partially_read_object_stays_mixed(
    ruleset,
) -> None:
    """A partial read may have cut the build string that would have proven the
    banner is a copy, so the gate never opens for an object not read in full."""
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libcrypto-3a1f2b4c.so.3", "libc.so.6"),
            matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_IMPORTED),),
            matched_strings=(OPENSSL_BANNER,),
            partial_analysis=True,
            partial_reasons=(PARTIAL_STRINGS_BYTES_UNREAD,),
        )
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == LINKAGE_MIXED


def test_a_header_banner_beside_imports_and_an_uncertain_needed_match_stays_mixed(ruleset) -> None:
    """An `uncertain` `needed` entry does not open the header-text gate: nothing
    confirmed what it resolves to, so there is no confirmed copy for a header macro
    to belong to. The object still reads `mixed`, not `unknown`, because the
    confirmed import and the unconfirmed vendor-shaped entry already disagree
    without the banner's help."""
    evidence = wheel(
        binary(
            "pkg/_ext.so",
            needed=("libcrypto.so.3",),
            runpath=("$ORIGIN/../p.libs",),
            matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_IMPORTED),),
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


def test_a_bundled_needed_match_beside_an_uncertain_one_stays_bundled(ruleset) -> None:
    """Two `needed` entries on one object: one hash-renamed and therefore confirmed
    `bundled`, and a second whose own path is vendor-shaped (delocate's convention)
    but that this incompletely-read wheel cannot confirm. `bundled`, like `system`,
    is read off `binary.needed` in the loop above, and a confirmed entry from that
    loop needs no vote from a different, unconfirmed one -- the same rule as `system`
    beside `uncertain`, applied to `bundled`.
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


def test_an_opaque_binary_only_costs_the_libraries_always_reported(ruleset) -> None:
    """Answering `LINKAGE_UNKNOWN` for `is_opaque` directly, once per `(binary,
    library)` pair in `resolve_linkage`'s loop over the whole ruleset, would make an
    opaque object read every one of the thirteen libraries in the shipped ruleset as
    `unknown`, not only `openssl` (the only one with `always_report = true`). Going
    through the `unanswered and library.always_report` gate `_left_unanswered` already
    computes for exactly this signal, which
    `test_an_unanswered_object_costs_only_the_libraries_always_reported` pins for a
    *partially*-read object, gives the same promise for a wholly opaque one instead.
    """
    evidence = wheel(binary("pkg/_ext.so", stripped=True))
    resolved = resolve_linkage(ruleset, evidence)
    assert resolved == {"openssl": LINKAGE_UNKNOWN}
    reported = {name for name, library in ruleset.libraries.items() if library.always_report}
    assert set(resolved) == reported
    assert "libsodium" not in resolved


def test_a_binary_is_opaque_only_when_it_yielded_nothing() -> None:
    """The property `linkage` and the opaque-binary rule both turn on."""
    assert binary("pkg/_ext.so").is_opaque
    assert not binary("pkg/_ext.so", dynsym_count=12).is_opaque
    assert not binary("pkg/_ext.so", needed=("libcrypto.so.3",)).is_opaque
    assert not binary("pkg/_ext.so", rust_crates=(RustCrate("ring", "0.17.8"),)).is_opaque


def test_which_symbol_count_means_something_is_read_depends_on_the_format() -> None:
    """Mach-O and PE never set `dynsym_count`; their counts land in `symtab_count`.

    Keying on `dynsym_count` for every format would call every Mach-O and every PE
    opaque however much of it was read, so a crypto-free universal2 wheel whose slices
    all parsed would come back saying it had told us nothing.
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

    Without this test, both of this property's callers in `linkage` could be deleted
    with the whole suite green, and a format that reads every object as opaque would
    reach the field unnoticed.
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
    """A case that must not answer twice, each time differently.

    A stripped macOS extension: `LC_SYMTAB` is not read, so the imported/defined
    split is missing, and every loadable dylib links `libSystem`, so `is_opaque` is
    false and the errors are empty. Nothing else in the wheel says anything, so
    `openssl_linkage` must not read `none` beside a `partial_reasons` saying we could
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
    extension that touches sockets. Counting every cause would make every one of them
    `unknown`, the same noise the routine-cause split keeps out of verdicts.
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
    asserted to be exactly the three the ruleset names, so widening that list has to
    be done on purpose.

    `PARTIAL_ELF_SYMTAB_UNREAD` is not on this list: `.symtab` drives the
    imported-versus-defined split too, for a relocatable object with no `.dynsym`,
    and supplies local definitions beside one, so a cause that costs only `stripped` and
    `symbol_counts.symtab` on its own also costs the split linkage reads. The ruleset
    cannot tell, from the cause name alone, which of the two shapes fired -- so the safe
    direction this vocabulary already takes elsewhere (a cause added later costs the
    answer until someone decides otherwise) applies here too.
    """
    excluded = ruleset.linkage_policy.exclude_reasons
    assert excluded == frozenset(
        {
            PARTIAL_PE_ORDINAL_IMPORT,
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
    tuple as "nothing excluded, so nothing costs us anything" would make `linkage` the
    one consumer that quietly downgrades it.
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
    the library is anywhere near this wheel. Without this test, deleting that clause
    leaves the whole suite green, which is how a documented promise turns out to be a
    coincidence.
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


@pytest.mark.parametrize(
    "evidence",
    [
        pytest.param(wheel(binary("pkg/_ext.so", stripped=True)), id="opaque"),
        pytest.param(
            wheel(
                binary(
                    "pkg/_ext.dylib",
                    format=FORMAT_MACHO,
                    needed=("/usr/lib/libSystem.B.dylib",),
                    partial_analysis=True,
                    partial_reasons=(PARTIAL_MACHO_SYMTAB_INCOMPLETE,),
                )
            ),
            id="partial-read",
        ),
        pytest.param(
            wheel(
                errors=(
                    ScanError(
                        stage=STAGE_BINARY,
                        kind="elf_parse_error",
                        message="truncated",
                        path="pkg/_x.so",
                    ),
                )
            ),
            id="stage-binary-error",
        ),
    ],
)
def test_every_shape_of_unanswered_costs_only_the_libraries_always_reported(
    ruleset, evidence
) -> None:
    """`_left_unanswered` names three shapes of "this wheel did not answer"; all three
    must be gated on `library.always_report` the same way, not just the two shapes
    `test_an_opaque_binary_only_costs_the_libraries_always_reported` and
    `test_an_unanswered_object_costs_only_the_libraries_always_reported` each pin for
    their own single shape above. A new object-level non-answer added to
    `_left_unanswered` in the future is covered here too, by construction, rather
    than needing its own copy of this assertion remembered by hand.
    """
    resolved = resolve_linkage(ruleset, evidence)
    assert resolved["openssl"] == LINKAGE_UNKNOWN
    reported = {name for name, library in ruleset.libraries.items() if library.always_report}
    assert set(resolved) == reported


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


# --- every definite OpenSSL posture has a finding on its object -------------
#
# `system` and `static` each have an aggregate-level rule (`DERIVED_SYSTEM_OPENSSL_ONLY`,
# `BIN_STATIC_OPENSSL`) that fires off the wheel's own `openssl_linkage` value, whatever
# mechanism produced it. `bundled` has no such backstop: only the per-mechanism rules
# (`BIN_BUNDLED_OPENSSL`, `BIN_NEEDED_MANGLED_CRYPTO`, `BIN_NEEDED_VENDORED_CRYPTO`) do,
# audited one branch at a time against `_binary_posture`. No aggregate rule stands behind
# `bundled` the way `DERIVED_SYSTEM_OPENSSL_ONLY` stands behind `system`; the tests below
# are what would catch a fourth mechanism reaching `LINKAGE_BUNDLED` with no fourth rule
# to match it.
#
# The check below is per object, not per wheel: a wheel-level check ("some finding
# fired somewhere") passes even when the one object that actually reads a posture
# carries no finding of its own, because a different object's finding -- the vendored
# member's own `BIN_BUNDLED_OPENSSL`, say -- satisfies it instead. Each definite
# posture is mapped to the rule categories that can explain it; the map is this test's
# own and deliberately coarse -- an object with imported symbols satisfies `system`
# through `BIN_OPENSSL_SYMBOLS_IMPORTED` as well as `BIN_NEEDED_SYSTEM_OPENSSL`, both
# `system-crypto-link` -- so the fixtures below stay minimal, carrying only the
# evidence their own branch needs, so a different rule can never mask the one under
# test.
#
# Scoped to `openssl`: it is the only library the ruleset always reports, and the only
# field a `CONDITIONAL` verdict turns on. `test_openssl_is_the_only_library_always_reported`
# pins that scope so a second always-reported library forces its own fixtures rather
# than silently sharing these.

_DEFINITE_POSTURES = (LINKAGE_SYSTEM, LINKAGE_BUNDLED, LINKAGE_STATIC, LINKAGE_MIXED)

_EXPLAINING_CATEGORIES = {
    LINKAGE_SYSTEM: frozenset({"system-crypto-link"}),
    LINKAGE_BUNDLED: frozenset({"bundled-crypto"}),
    LINKAGE_STATIC: frozenset({"bundled-crypto"}),
    LINKAGE_MIXED: frozenset({"system-crypto-link", "bundled-crypto"}),
}

_POSTURE_FIXTURES = [
    pytest.param(
        wheel(
            binary(
                "demo.libs/libcrypto-3a1f2b4c.so.3",
                vendored_path=True,
                soname="libcrypto-3a1f2b4c.so.3",
            )
        ),
        id="vendored-member",
    ),
    pytest.param(
        wheel(binary("pkg/_ext.so", needed=("libcrypto-3a1f2b4c.so.3",))),
        id="mangled-needed",
    ),
    pytest.param(
        wheel(
            binary("pkg/_ext.so", needed=("libcrypto.so.3", "libc.so.6"), runpath=("$ORIGIN",)),
            binary("pkg/libcrypto.so.3", soname="libcrypto.so.3", needed=("libc.so.6",)),
        ),
        id="resolves-in-wheel",
    ),
    pytest.param(
        wheel(binary("pkg/_ext.so", needed=("libcrypto.so.3",))),
        id="system-plain",
    ),
    pytest.param(
        wheel(binary("pkg/_ext.so", needed=("/usr/lib64/libcrypto.so.3",))),
        id="system-absolute",
    ),
    pytest.param(
        wheel(
            binary(
                "cryptography/hazmat/bindings/_rust.abi3.so",
                needed=("libssl.so.3", "libcrypto.so.3", "libc.so.6"),
                matched_symbols=(
                    SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_IMPORTED),
                    SymbolMatch("SSL_CTX_new", "openssl", BINDING_IMPORTED),
                ),
                matched_strings=(OPENSSL_BANNER,),
            )
        ),
        id="system-header-banner",
    ),
    pytest.param(
        wheel(
            binary(
                "pkg/_ext.so",
                matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_DEFINED),),
            )
        ),
        id="static-defined",
    ),
    pytest.param(
        wheel(binary("pkg/_ext.so", matched_strings=(OPENSSL_BANNER, OPENSSL_BUILD_INFO))),
        id="static-banner",
    ),
    pytest.param(
        wheel(
            binary(
                "pkg/_ext.so",
                needed=("libc.so.6", "libssl.so.3"),
                matched_symbols=(
                    SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_DEFINED),
                    SymbolMatch("SSL_new", "openssl", BINDING_IMPORTED),
                ),
            )
        ),
        id="mixed-system-defined",
    ),
    pytest.param(
        wheel(
            binary(
                "pkg/_ext.so",
                needed=("libcrypto-3a1f2b4c.so.3", "/usr/lib64/libcrypto.so.3"),
            )
        ),
        id="mixed-bundled-system",
    ),
    pytest.param(
        wheel(
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
        ),
        id="mixed-uncertain-static",
    ),
    pytest.param(
        wheel(
            binary("pkg/_a.so", needed=("libssl.so.3",)),
            binary(
                "pkg/_b.so",
                matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_DEFINED),),
            ),
        ),
        id="mixed-across-objects",
    ),
]


def _unexplained(ruleset, evidence) -> list[str]:
    """Every definite `openssl` posture in `evidence` that no finding, on that same
    object and in a category that fits the posture, explains."""
    linkage = resolve_linkage(ruleset, evidence)
    findings = apply_rules(ruleset, evidence, linkage)
    library = ruleset.libraries["openssl"]
    identity = {name for name in (library.name, library.symbol_group, library.string_group) if name}
    postures = object_postures(ruleset, evidence, "openssl")

    problems = []
    for obj, posture in zip(evidence.binaries, postures, strict=True):
        if posture not in _DEFINITE_POSTURES:
            continue
        wanted = _EXPLAINING_CATEGORIES[posture]
        explained = any(
            finding.subject in identity
            and obj.path in {location.path for location in finding.locations}
            and finding.category in wanted
            for finding in findings
        )
        if not explained:
            problems.append(f"{obj.path} reads {posture} with no finding on it")

    if linkage.get("openssl") in _DEFINITE_POSTURES and not any(
        posture in _DEFINITE_POSTURES for posture in postures
    ):
        # A sanity check: `test_aggregate_never_returns_a_definite_posture_without_one`
        # below holds, exhaustively over `_aggregate`'s own inputs, that a definite
        # wheel-level value always traces back to at least one object reading a
        # definite posture of its own, so this branch is not expected to ever fire.
        problems.append(
            f"wheel resolves openssl to {linkage['openssl']} with no object posture explaining it"
        )
    return problems


def test_openssl_is_the_only_library_always_reported(ruleset) -> None:
    """The fixtures above are written for `openssl`'s own identity (`name`,
    `symbol_group`, `string_group`) and posture-explaining rules. A second library
    set `always_report` needs its own fixtures rather than silently reusing these."""
    assert [name for name, library in ruleset.libraries.items() if library.always_report] == [
        "openssl"
    ]


@pytest.mark.parametrize("evidence", _POSTURE_FIXTURES)
def test_every_definite_openssl_posture_has_a_finding_on_its_object(ruleset, evidence) -> None:
    postures = object_postures(ruleset, evidence, "openssl")
    assert any(posture in _DEFINITE_POSTURES for posture in postures), (
        "fixture reads no definite posture at all; it proves nothing"
    )
    assert _unexplained(ruleset, evidence) == []


@pytest.mark.parametrize(
    "rule_id",
    [
        "BIN_BUNDLED_OPENSSL",
        "BIN_NEEDED_MANGLED_CRYPTO",
        "BIN_NEEDED_VENDORED_CRYPTO",
        "BIN_NEEDED_SYSTEM_OPENSSL",
        "BIN_OPENSSL_SYMBOLS_DEFINED",
        "BIN_OPENSSL_BANNER",
    ],
)
def test_dropping_a_mechanism_rule_leaves_a_posture_unexplained(ruleset, rule_id: str) -> None:
    """Proves the invariant is not vacuous: losing any one mechanism rule leaves at
    least one fixture above with a posture no finding explains."""
    stripped = replace(ruleset, rules=tuple(rule for rule in ruleset.rules if rule.id != rule_id))
    assert any(_unexplained(stripped, param.values[0]) for param in _POSTURE_FIXTURES)


def test_dropping_both_system_rules_leaves_the_header_banner_object_unexplained(ruleset) -> None:
    """`test_dropping_a_mechanism_rule_leaves_a_posture_unexplained` never leaves a
    right-subject, wrong-category finding behind to test `_unexplained`'s category
    filter against: dropping one rule at a time always leaves the fixture's other
    mechanism rule (or no finding at all) on the object under test. Drop both
    rules that can explain `system` on `system-header-banner` at once: the object
    still carries its own `BIN_OPENSSL_BANNER` finding (category `bundled-crypto`,
    since the banner is read as header text rather than a copy), which is on the
    right object and the right subject but the wrong category. If the category
    filter were not applied, that finding would be accepted as explaining `system`."""
    stripped = replace(
        ruleset,
        rules=tuple(
            rule
            for rule in ruleset.rules
            if rule.id not in {"BIN_NEEDED_SYSTEM_OPENSSL", "BIN_OPENSSL_SYMBOLS_IMPORTED"}
        ),
    )
    fixture = next(
        param.values[0] for param in _POSTURE_FIXTURES if param.id == "system-header-banner"
    )
    assert _unexplained(stripped, fixture) == [
        "cryptography/hazmat/bindings/_rust.abi3.so reads system with no finding on it"
    ]


def test_dropping_the_bundled_openssl_rule_leaves_only_a_libsodium_finding(
    ruleset,
) -> None:
    """Mirrors the category case above for the subject filter: an object can carry a
    same-location, right-category finding for a different library. A `needed` entry
    that demangles to `libsodium` fires the same `BIN_NEEDED_MANGLED_CRYPTO` rule a
    mangled `openssl` entry would, at `category = "bundled-crypto"`, on the same
    object as this wheel's vendored-copy OpenSSL evidence. With `BIN_BUNDLED_OPENSSL`
    dropped, only that libsodium finding is left on the object; if the subject filter
    were not applied, it would be accepted as explaining the object's own `bundled`
    openssl posture."""
    evidence = wheel(
        binary(
            "demo.libs/libcrypto-3a1f2b4c.so.3",
            vendored_path=True,
            soname="libcrypto-3a1f2b4c.so.3",
            needed=("libsodium-a1b2c3d4.so.23",),
        )
    )
    stripped = replace(
        ruleset, rules=tuple(rule for rule in ruleset.rules if rule.id != "BIN_BUNDLED_OPENSSL")
    )
    assert _unexplained(stripped, evidence) == [
        "demo.libs/libcrypto-3a1f2b4c.so.3 reads bundled with no finding on it"
    ]


def test_every_definite_return_in_the_posture_functions_is_reached_by_a_fixture(ruleset) -> None:
    """Catches a fourth path to a definite posture that the fixtures above do not
    restate: every `return` in `_binary_posture` and `needed_posture` that names a
    `LINKAGE_SYSTEM`/`LINKAGE_BUNDLED`/`LINKAGE_STATIC`/`LINKAGE_MIXED` value must be
    executed by at least one fixture, or a mechanism could be added to either function
    with nothing here noticing that no fixture, and so no rule audit, covers it.
    """
    if sys.gettrace() is not None:
        pytest.skip("another tracer is active")

    functions = (linkage_module._binary_posture, linkage_module.needed_posture)
    definite_names = {"LINKAGE_SYSTEM", "LINKAGE_BUNDLED", "LINKAGE_STATIC", "LINKAGE_MIXED"}
    definite_lines = set()
    for fn in functions:
        offset = fn.__code__.co_firstlineno - 1
        tree = ast.parse(inspect.getsource(fn))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Return):
                continue
            if not isinstance(node.value, ast.Name) or not node.value.id.startswith("LINKAGE_"):
                raise AssertionError(
                    f"{fn.__qualname__} has a return at line {node.lineno + offset} this "
                    "test cannot classify; extend it to cover the new shape"
                )
            if node.value.id in definite_names:
                definite_lines.add((fn.__code__, node.lineno + offset))

    code_objects = {fn.__code__ for fn in functions}
    reached = set()

    def local_trace(frame, event, _arg):
        if event == "return":
            reached.add((frame.f_code, frame.f_lineno))
        return local_trace

    def global_trace(frame, event, arg):
        del event, arg
        return local_trace if frame.f_code in code_objects else None

    sys.settrace(global_trace)
    try:
        for param in _POSTURE_FIXTURES:
            _unexplained(ruleset, param.values[0])
    finally:
        sys.settrace(None)

    missing = definite_lines - reached
    assert not missing, f"definite return(s) never reached by a fixture: {sorted(missing)}"


def _aggregate_input_cases():
    """Every subset of the postures `_binary_posture`/`needed_posture` can produce,
    crossed with `unanswered` and `declared`: `_aggregate`'s whole input space."""
    universe = (
        LINKAGE_SYSTEM,
        LINKAGE_BUNDLED,
        LINKAGE_STATIC,
        LINKAGE_MIXED,
        LINKAGE_UNKNOWN,
        LINKAGE_NONE,
    )
    for size in range(len(universe) + 1):
        for combo in itertools.combinations(universe, size):
            for unanswered in (False, True):
                for declared in (False, True):
                    label = ",".join(combo) or "empty"
                    yield pytest.param(
                        frozenset(combo),
                        unanswered,
                        declared,
                        id=f"{label}-unanswered={unanswered}-declared={declared}",
                    )


@pytest.mark.parametrize("postures, unanswered, declared", list(_aggregate_input_cases()))
def test_aggregate_never_returns_a_definite_posture_without_one(
    postures: frozenset[str], unanswered: bool, declared: bool
) -> None:
    """Holds, exhaustively rather than by inspection, what `_unexplained`'s wheel-level
    sanity check above assumes: `_aggregate` cannot manufacture a definite
    `openssl_linkage` value out of `unanswered` or `declared` alone. `unanswered` and
    `declared` only ever promote a wheel to `unknown`; a result in `_DEFINITE_POSTURES`
    must always trace back to a definite posture already present in `postures`."""
    result = linkage_module._aggregate(set(postures), unanswered, declared)
    if result in _DEFINITE_POSTURES:
        assert postures & set(_DEFINITE_POSTURES), (
            f"_aggregate({sorted(postures)!r}, unanswered={unanswered}, declared={declared}) "
            f"= {result!r}, a definite posture, with no definite posture in the input"
        )
