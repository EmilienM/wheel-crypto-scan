"""The corpus the crypto engineer asked for, built offline and asserted end to end.

The pair that matters most is `fakecrypto_system` against `fakecrypto_bundled`: a wheel
that links the host's OpenSSL against one that ships its own. If the tool cannot tell
those apart from the wheel alone it is not worth shipping, so they are built here with
exactly the structure auditwheel produces and checked through the whole pipeline.

Fixtures are synthesised rather than downloaded, so the suite runs offline and
byte-identically on any host. Real wheels are covered by the opt-in `real` marker.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from helpers.binfmt import (
    STB_LOCAL,
    ArMember,
    DynSym,
    ElfBuilder,
    MachOBuilder,
    MachOSym,
    PEBuilder,
    PEExport,
    PEImport,
    build_ar,
    build_fat,
)
from helpers.binfmt.elf import STT_FUNC
from helpers.wheelbuilder import build_wheel

from wheel_crypto_scan.ruleset_loader import load_ruleset
from wheel_crypto_scan.scan import ScanContext, scan_wheel

OPENSSL_BANNER = b"OpenSSL 3.0.14 4 Jun 2024\x00"
EVP = "EVP_DigestInit_ex"
CARGO_RING = (
    b"/root/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ring-0.17.8/src/lib.rs\x00"
)
CARGO_BLAKE3 = (
    b"/root/.cargo/registry/src/index.crates.io-6f17d22bba15001f/blake3-1.5.1/src/lib.rs\x00"
)
MANYLINUX = "cp39-abi3-manylinux_2_28_x86_64"
WINDOWS = "cp39-abi3-win_amd64"


@pytest.fixture(scope="module")
def context() -> ScanContext:
    return ScanContext.build(load_ruleset())


def scan(context: ScanContext, path: Path) -> dict:
    return scan_wheel(path, context)


def extension(**kwargs) -> bytes:
    """An extension module: dynamic, with libc and whatever the test asks for."""
    kwargs.setdefault("needed", ("libc.so.6",))
    return ElfBuilder(**kwargs).build()


# --------------------------------------------------------------------------
# The acceptance pair, plus the third case a vendor-directory check would miss
# --------------------------------------------------------------------------


def subdir(tmp_path: Path, name: str) -> Path:
    """Each fixture gets its own directory: the wheels share a filename on purpose."""
    directory = tmp_path / name
    directory.mkdir(exist_ok=True)
    return directory


@pytest.fixture
def system_wheel(tmp_path: Path) -> Path:
    """A distro style build: it resolves libcrypto from the host."""
    return build_wheel(
        subdir(tmp_path, "system") / f"fakecrypto-42.0.5-{MANYLINUX}.whl",
        name="fakecrypto",
        version="42.0.5",
        tags=(MANYLINUX,),
        files={
            "fakecrypto/__init__.py": b"from fakecrypto import _openssl\n",
            "fakecrypto/_openssl.abi3.so": extension(
                needed=("libcrypto.so.3", "libssl.so.3", "libc.so.6"),
                dynsyms=(DynSym(EVP, defined=False), DynSym("SSL_CTX_new", defined=False)),
            ),
        },
    )


@pytest.fixture
def bundled_wheel(tmp_path: Path) -> Path:
    """A PyPI manylinux build: auditwheel copied libcrypto in and renamed it."""
    return build_wheel(
        subdir(tmp_path, "bundled") / f"fakecrypto-42.0.5-{MANYLINUX}.whl",
        name="fakecrypto",
        version="42.0.5",
        tags=(MANYLINUX,),
        files={
            "fakecrypto/__init__.py": b"from fakecrypto import _openssl\n",
            "fakecrypto/_openssl.abi3.so": extension(
                needed=("libcrypto-3a1f2b4c.so.3", "libc.so.6"),
                runpath=("$ORIGIN/../fakecrypto.libs",),
                dynsyms=(DynSym(EVP, defined=False),),
            ),
            "fakecrypto.libs/libcrypto-3a1f2b4c.so.3": ElfBuilder(
                soname="libcrypto-3a1f2b4c.so.3",
                needed=("libc.so.6",),
                dynsyms=(DynSym(EVP, defined=True),),
                rodata=OPENSSL_BANNER,
            ).build(),
        },
    )


@pytest.fixture
def static_wheel(tmp_path: Path) -> Path:
    """cryptography 42+: OpenSSL compiled into the Rust extension, nothing to point at."""
    return build_wheel(
        subdir(tmp_path, "static") / f"fakecrypto-43.0.0-{MANYLINUX}.whl",
        name="fakecrypto",
        version="43.0.0",
        tags=(MANYLINUX,),
        generator="maturin (1.7.0)",
        files={
            "fakecrypto/__init__.py": b"from fakecrypto import _rust\n",
            "fakecrypto/_rust.abi3.so": extension(
                dynsyms=(DynSym(EVP, defined=True),),
                rodata=OPENSSL_BANNER,
            ),
        },
    )


def test_a_system_linked_wheel_is_reported_as_system(context, system_wheel) -> None:
    record = scan(context, system_wheel)
    assert record["verdict"]["conditions"]["openssl_linkage"] == "system"
    assert record["verdict"]["class"] == "CONDITIONAL"
    assert "DERIVED_SYSTEM_OPENSSL_ONLY" in record["verdict"]["rule_ids"]


def test_a_bundled_wheel_is_reported_as_bundled(context, bundled_wheel) -> None:
    record = scan(context, bundled_wheel)
    assert record["verdict"]["conditions"]["openssl_linkage"] == "bundled"
    assert record["verdict"]["class"] == "CONDITIONAL"
    assert "BIN_BUNDLED_OPENSSL" in record["verdict"]["rule_ids"]


def test_the_two_builds_are_distinguished_from_the_wheel_alone(
    context, system_wheel, bundled_wheel
) -> None:
    """The acceptance gate. Same project, same version, same tags, different answer."""
    system = scan(context, system_wheel)
    bundled = scan(context, bundled_wheel)
    assert system["wheel"]["name"] == bundled["wheel"]["name"]
    assert system["wheel"]["version"] == bundled["wheel"]["version"]
    assert system["wheel"]["tags"] == bundled["wheel"]["tags"]
    assert (
        system["verdict"]["conditions"]["openssl_linkage"]
        != bundled["verdict"]["conditions"]["openssl_linkage"]
    )


def test_the_bundled_wheel_names_the_library_it_ships(context, bundled_wheel) -> None:
    record = scan(context, bundled_wheel)
    finding = next(f for f in record["findings"] if f["rule_id"] == "BIN_BUNDLED_OPENSSL")
    assert finding["locations"][0]["path"] == "fakecrypto.libs/libcrypto-3a1f2b4c.so.3"
    assert "OpenSSL 3.0.14" in finding["locations"][0]["evidence"]
    assert record["artifacts"]["bundled_libs"] == ["fakecrypto.libs/libcrypto-3a1f2b4c.so.3"]


def test_a_statically_linked_wheel_is_not_mistaken_for_system_linked(context, static_wheel) -> None:
    """No vendor directory and no DT_NEEDED, yet it carries OpenSSL. The subtle case."""
    record = scan(context, static_wheel)
    assert record["verdict"]["conditions"]["openssl_linkage"] == "static"
    assert "BIN_STATIC_OPENSSL" in record["verdict"]["rule_ids"]
    assert "DERIVED_SYSTEM_OPENSSL_ONLY" not in record["verdict"]["rule_ids"]


def test_a_system_linked_build_carrying_its_header_banner_is_system(
    context, tmp_path: Path
) -> None:
    """The Fedora shape: a system dependency, imported symbols, and a header's own
    version banner beside them, with none of the build strings a compiled-in copy
    keeps beside its banner. The banner is header text, not a copy, so the wheel
    reads `system` -- the banner is still reported as evidence, just not as a
    competing posture."""
    wheel_path = build_wheel(
        tmp_path / f"fakecrypto-50.0.0-{MANYLINUX}.whl",
        name="fakecrypto",
        version="50.0.0",
        tags=(MANYLINUX,),
        files={
            "fakecrypto/__init__.py": b"from fakecrypto import _openssl\n",
            "fakecrypto/_openssl.abi3.so": extension(
                needed=("libssl.so.3", "libcrypto.so.3", "libc.so.6"),
                dynsyms=(DynSym(EVP, defined=False), DynSym("SSL_CTX_new", defined=False)),
                rodata=OPENSSL_BANNER,
            ),
        },
    )
    record = scan(context, wheel_path)
    assert record["verdict"]["conditions"]["openssl_linkage"] == "system"
    assert "DERIVED_SYSTEM_OPENSSL_ONLY" in record["verdict"]["rule_ids"]
    assert "BIN_OPENSSL_LINKAGE_UNKNOWN" not in record["verdict"]["rule_ids"]
    assert any(f["rule_id"] == "BIN_OPENSSL_BANNER" for f in record["findings"])


def test_a_system_dependency_beside_a_compiled_in_copy_stays_mixed(context, tmp_path: Path) -> None:
    """Same shape, but the banner is accompanied by the build string a real
    compiled-in copy keeps beside it -- the merged-universal-binary or
    static-libcrypto-beside-dynamic-libssl shape the gate exists to keep reading
    `mixed`. This pins that the ELF strings pass really reads the marker end to end,
    not only that `linkage.py`'s own logic can be made to say so with hand-built
    evidence."""
    wheel_path = build_wheel(
        tmp_path / f"fakecrypto-50.0.0-{MANYLINUX}.whl",
        name="fakecrypto",
        version="50.0.0",
        tags=(MANYLINUX,),
        files={
            "fakecrypto/__init__.py": b"from fakecrypto import _openssl\n",
            "fakecrypto/_openssl.abi3.so": extension(
                needed=("libssl.so.3", "libcrypto.so.3", "libc.so.6"),
                dynsyms=(DynSym(EVP, defined=False), DynSym("SSL_CTX_new", defined=False)),
                rodata=OPENSSL_BANNER + b'OPENSSLDIR: "/usr/lib/ssl"\x00',
            ),
        },
    )
    record = scan(context, wheel_path)
    assert record["verdict"]["conditions"]["openssl_linkage"] == "mixed"
    assert "BIN_OPENSSL_LINKAGE_UNKNOWN" in record["verdict"]["rule_ids"]
    assert "DERIVED_SYSTEM_OPENSSL_ONLY" not in record["verdict"]["rule_ids"]
    binary_record = next(
        b for b in record["binaries"] if b["path"] == "fakecrypto/_openssl.abi3.so"
    )
    assert any(s["group"] == "openssl_build_info" for s in binary_record["matched_strings"])


def test_an_import_only_object_beside_a_system_link_is_opaque_not_system_only(
    context, tmp_path: Path
) -> None:
    """A second object imports OpenSSL symbols without declaring a dependency on it --
    its own posture is `unknown`, so `DERIVED_SYSTEM_OPENSSL_ONLY`'s claim that every
    piece of OpenSSL evidence points at the system library would be false. The
    complementary rule carries the wheel's class instead.
    """
    wheel = build_wheel(
        tmp_path / f"demo-1.0-{MANYLINUX}.whl",
        name="demo",
        version="1.0",
        tags=(MANYLINUX,),
        files={
            "demo/__init__.py": b"",
            "demo/_ext.so": extension(needed=("libc.so.6",), dynsyms=(DynSym(EVP, defined=False),)),
            "demo/_ssl.so": extension(needed=("libssl.so.3", "libc.so.6")),
        },
    )
    record = scan(context, wheel)
    rule_ids = set(record["verdict"]["rule_ids"])
    assert record["verdict"]["conditions"]["openssl_linkage"] == "system"
    assert record["verdict"]["class"] == "OPAQUE"
    assert "DERIVED_SYSTEM_OPENSSL_ONLY" not in rule_ids
    assert "DERIVED_OPENSSL_UNRESOLVED_BESIDE_SYSTEM" in rule_ids
    assert record["verdict"]["needs_human_review"] is True
    finding = next(
        f for f in record["findings"] if f["rule_id"] == "DERIVED_OPENSSL_UNRESOLVED_BESIDE_SYSTEM"
    )
    assert finding["locations"][0]["path"] == "demo/_ext.so"


def test_a_static_openssls_legacy_primitives_lead_the_headline_and_keep_the_condition(
    context, tmp_path: Path
) -> None:
    """A version-scripted static OpenSSL defines Blowfish, MD4 and x25519_ alongside EVP.

    `x25519_fe51_mul` is one of OpenSSL 3's own field-arithmetic helpers for Curve25519
    (assembly on x86_64, `crypto/ec`), not a provider entry point and not the 1.1.1-era
    `X25519_*` name -- OpenSSL 3 does not define an uppercase `X25519_*`/`Ed25519_*`
    symbol at all, and its provider entry points are `ossl_x25519`/`ossl_ed25519_*`,
    which this group does not match either.

    Those definitions are OpenSSL's own code, not something the wheel's own logic
    wrote, but they are still definitions: the wheel carries them and the host FIPS
    provider cannot refuse them. The taxonomy has no passing class and no
    co-occurrence-aware precedence, so `NON_APPROVED_CRYPTO` leads the headline the
    same way it would for any other object that defines these entry points. Nothing is
    lost: `BIN_STATIC_OPENSSL` and `BIN_OPENSSL_SYMBOLS_DEFINED` both keep the
    CONDITIONAL class in `verdict.classes`. `verdict.conditions.openssl_linkage` says
    whether the wheel carries its own OpenSSL at all, not which case this is -- and not
    when a wheel carries both -- so telling this apart from a wheel whose own code
    defines a weak primitive is a question for the object's own `matched_symbols`.
    """
    wheel = build_wheel(
        subdir(tmp_path, "static-legacy") / f"fakecrypto-43.0.0-{MANYLINUX}.whl",
        name="fakecrypto",
        version="43.0.0",
        tags=(MANYLINUX,),
        generator="maturin (1.7.0)",
        files={
            "fakecrypto/__init__.py": b"from fakecrypto import _rust\n",
            "fakecrypto/_rust.abi3.so": extension(
                dynsyms=(DynSym("PyInit__rust", defined=True),),
                with_symtab=True,
                symtab_syms=(
                    DynSym("EVP_DigestInit_ex", defined=True),
                    DynSym("BF_encrypt", defined=True, info=(STB_LOCAL << 4) | 2),  # STT_FUNC
                    DynSym("MD4_Init", defined=True, info=(STB_LOCAL << 4) | 2),  # STT_FUNC
                    DynSym("x25519_fe51_mul", defined=True, info=(STB_LOCAL << 4) | 2),  # STT_FUNC
                ),
                rodata=OPENSSL_BANNER,
            ),
        },
    )
    record = scan(context, wheel)
    assert record["verdict"]["conditions"]["openssl_linkage"] == "static"
    assert record["verdict"]["class"] == "NON_APPROVED_CRYPTO"
    assert "CONDITIONAL" in record["verdict"]["classes"]
    assert {
        "BIN_STATIC_OPENSSL",
        "BIN_OPENSSL_SYMBOLS_DEFINED",
        "BIN_BCRYPT_BLOWFISH",
        "BIN_OWN_WEAK_HASH_IMPL",
        "BIN_CURVE25519",
    } <= set(record["verdict"]["rule_ids"])


def test_a_private_weak_hash_kept_local_is_still_found_without_openssl(
    context, tmp_path: Path
) -> None:
    """The reason a narrower `binding` on the legacy rules was rejected.

    A hidden-visibility C extension that compiles its own MD5 has only a `.symtab`
    local definition, no `.dynsym` export and no OpenSSL banner. It must still read
    `NON_APPROVED_CRYPTO`: an "exported only" binding would let exactly this object
    read clean, which is the case the ruleset's own admission test rules out.
    """
    wheel = build_wheel(
        subdir(tmp_path, "private-weak-hash") / f"fakecrypto-1.0.0-{MANYLINUX}.whl",
        name="fakecrypto",
        version="1.0.0",
        tags=(MANYLINUX,),
        files={
            "fakecrypto/__init__.py": b"from fakecrypto import _ext\n",
            "fakecrypto/_ext.abi3.so": extension(
                dynsyms=(DynSym("PyInit__ext", defined=True),),
                with_symtab=True,
                symtab_syms=(
                    DynSym("MD5_Init", defined=True, info=(STB_LOCAL << 4) | 2),  # STT_FUNC
                ),
            ),
        },
    )
    record = scan(context, wheel)
    assert "BIN_OWN_WEAK_HASH_IMPL" in record["verdict"]["rule_ids"]
    assert record["verdict"]["class"] == "NON_APPROVED_CRYPTO"
    assert record["verdict"]["conditions"]["openssl_linkage"] == "none"


def test_a_bundled_openssls_legacy_primitives_lead_the_headline_too(
    context, tmp_path: Path
) -> None:
    """The same drift as the static case, through an auditwheel-bundled libcrypto.

    A bundled `libcrypto` is an ordinary shared object: it exports `BF_encrypt` and
    `MD4_Init` from `.dynsym` the way the host's own `libcrypto.so.3` does, no
    `.symtab` read involved. `BIN_BUNDLED_OPENSSL`'s own `CONDITIONAL` is outranked by
    `BIN_BCRYPT_BLOWFISH`'s and `BIN_OWN_WEAK_HASH_IMPL`'s `NON_APPROVED_CRYPTO` the
    same way `BIN_STATIC_OPENSSL`'s is, so the headline drift this ruleset's `why`
    text describes is not a static-only cost.

    Nothing here spells a Curve25519 name, and none of the exported entry points do
    either, so `BIN_CURVE25519` does not fire: see the paired
    `test_a_bundled_openssls_curve25519_helpers_only_surface_with_symtab` for the
    `.symtab` case that does.
    """
    wheel = build_wheel(
        subdir(tmp_path, "bundled-legacy") / f"fakecrypto-42.0.5-{MANYLINUX}.whl",
        name="fakecrypto",
        version="42.0.5",
        tags=(MANYLINUX,),
        files={
            "fakecrypto/__init__.py": b"from fakecrypto import _openssl\n",
            "fakecrypto/_openssl.abi3.so": extension(
                needed=("libcrypto-3a1f2b4c.so.3", "libc.so.6"),
                runpath=("$ORIGIN/../fakecrypto.libs",),
                dynsyms=(DynSym(EVP, defined=False),),
            ),
            "fakecrypto.libs/libcrypto-3a1f2b4c.so.3": ElfBuilder(
                soname="libcrypto-3a1f2b4c.so.3",
                needed=("libc.so.6",),
                dynsyms=(
                    DynSym(EVP, defined=True),
                    DynSym("BF_encrypt", defined=True),
                    DynSym("MD4_Init", defined=True),
                ),
                rodata=OPENSSL_BANNER,
            ).build(),
        },
    )
    record = scan(context, wheel)
    rule_ids = set(record["verdict"]["rule_ids"])
    assert record["verdict"]["conditions"]["openssl_linkage"] == "bundled"
    assert record["verdict"]["class"] == "NON_APPROVED_CRYPTO"
    assert "CONDITIONAL" in record["verdict"]["classes"]
    assert {
        "BIN_BUNDLED_OPENSSL",
        "BIN_BCRYPT_BLOWFISH",
        "BIN_OWN_WEAK_HASH_IMPL",
    } <= rule_ids
    assert "BIN_CURVE25519" not in rule_ids


def test_a_bundled_openssls_curve25519_helpers_only_surface_with_symtab(
    context, tmp_path: Path
) -> None:
    """The `.symtab` half of the pair above.

    `x25519_fe51_mul` is a field-arithmetic helper, not part of `libcrypto`'s public
    API, so an auditwheel-bundled copy only exports it from `.dynsym` if the packager
    never strips the library. Give the same bundled `libcrypto` a `.symtab` that keeps
    that helper as a local definition and `BIN_CURVE25519` joins the other two.
    """
    wheel = build_wheel(
        subdir(tmp_path, "bundled-legacy-symtab") / f"fakecrypto-42.0.5-{MANYLINUX}.whl",
        name="fakecrypto",
        version="42.0.5",
        tags=(MANYLINUX,),
        files={
            "fakecrypto/__init__.py": b"from fakecrypto import _openssl\n",
            "fakecrypto/_openssl.abi3.so": extension(
                needed=("libcrypto-3a1f2b4c.so.3", "libc.so.6"),
                runpath=("$ORIGIN/../fakecrypto.libs",),
                dynsyms=(DynSym(EVP, defined=False),),
            ),
            "fakecrypto.libs/libcrypto-3a1f2b4c.so.3": ElfBuilder(
                soname="libcrypto-3a1f2b4c.so.3",
                needed=("libc.so.6",),
                dynsyms=(
                    DynSym(EVP, defined=True),
                    DynSym("BF_encrypt", defined=True),
                    DynSym("MD4_Init", defined=True),
                ),
                with_symtab=True,
                symtab_syms=(
                    DynSym(EVP, defined=True),
                    DynSym("BF_encrypt", defined=True),
                    DynSym("MD4_Init", defined=True),
                    DynSym("x25519_fe51_mul", defined=True, info=(STB_LOCAL << 4) | 2),
                ),
                rodata=OPENSSL_BANNER,
            ).build(),
        },
    )
    record = scan(context, wheel)
    rule_ids = set(record["verdict"]["rule_ids"])
    assert record["verdict"]["conditions"]["openssl_linkage"] == "bundled"
    assert record["verdict"]["class"] == "NON_APPROVED_CRYPTO"
    assert {
        "BIN_BUNDLED_OPENSSL",
        "BIN_BCRYPT_BLOWFISH",
        "BIN_OWN_WEAK_HASH_IMPL",
        "BIN_CURVE25519",
    } <= rule_ids


# --------------------------------------------------------------------------
# delocate: bundled without a rename
#
# delocate, the macOS counterpart of auditwheel, copies a dependency into `.dylibs/`
# and rewrites the load command to point there -- but never renames the file the way
# auditwheel and delvewheel do. `mangled` alone therefore cannot tell "system" from
# "bundled" for a plain `libcrypto.3.dylib` dependency.
# --------------------------------------------------------------------------

MACOS_TAG = "cp312-cp312-macosx_11_0_arm64"


def _delocate_extension(needed: tuple[str, ...], rpaths: tuple[str, ...] = ()) -> bytes:
    return MachOBuilder(
        load_dylibs=("/usr/lib/libSystem.B.dylib", *needed),
        rpaths=rpaths,
        symbols=(
            MachOSym("_PyInit__ext", True),
            MachOSym("_EVP_DigestInit_ex", False),
        ),
    ).build()


def _delocate_libcrypto(id_dylib: str) -> bytes:
    return MachOBuilder(
        id_dylib=id_dylib,
        load_dylibs=("/usr/lib/libSystem.B.dylib",),
        symbols=(
            MachOSym("_EVP_DigestInit_ex", True),
            MachOSym("_SSL_new", True),
        ),
    ).build()


@pytest.fixture
def delocate_loader_path_wheel(tmp_path: Path) -> Path:
    """`@loader_path/.dylibs/libcrypto.3.dylib`, delocate's usual load-command form."""
    return build_wheel(
        tmp_path / f"fakecrypto-42.0.5-{MACOS_TAG}.whl",
        name="fakecrypto",
        version="42.0.5",
        tags=(MACOS_TAG,),
        files={
            "fakecrypto/__init__.py": b"from fakecrypto import _ext\n",
            "fakecrypto/_ext.cpython-312-darwin.so": _delocate_extension(
                needed=("@loader_path/.dylibs/libcrypto.3.dylib",)
            ),
            "fakecrypto/.dylibs/libcrypto.3.dylib": _delocate_libcrypto(
                "@loader_path/libcrypto.3.dylib"
            ),
        },
    )


@pytest.fixture
def delocate_rpath_wheel(tmp_path: Path) -> Path:
    """`@rpath/libcrypto.3.dylib` with an `LC_RPATH` pointing at `.dylibs/`."""
    return build_wheel(
        tmp_path / f"fakecrypto-42.0.5-{MACOS_TAG}.whl",
        name="fakecrypto",
        version="42.0.5",
        tags=(MACOS_TAG,),
        files={
            "fakecrypto/__init__.py": b"from fakecrypto import _ext\n",
            "fakecrypto/_ext.cpython-312-darwin.so": _delocate_extension(
                needed=("@rpath/libcrypto.3.dylib",), rpaths=("@loader_path/.dylibs",)
            ),
            "fakecrypto/.dylibs/libcrypto.3.dylib": _delocate_libcrypto(
                "@loader_path/libcrypto.3.dylib"
            ),
        },
    )


@pytest.fixture
def unmangled_vendor_dir_wheel(tmp_path: Path) -> Path:
    """The ELF shape of the same gap: a vendor directory whose library was never
    hash-renamed, resolved through a plain RUNPATH rather than a load-command path."""
    return build_wheel(
        subdir(tmp_path, "unmangled") / f"fakecrypto-42.0.5-{MANYLINUX}.whl",
        name="fakecrypto",
        version="42.0.5",
        tags=(MANYLINUX,),
        files={
            "fakecrypto/__init__.py": b"from fakecrypto import _openssl\n",
            "fakecrypto/_openssl.abi3.so": extension(
                needed=("libcrypto.so.3", "libc.so.6"),
                runpath=("$ORIGIN/../fakecrypto.libs",),
                dynsyms=(DynSym(EVP, defined=False),),
            ),
            "fakecrypto.libs/libcrypto.so.3": ElfBuilder(
                soname="libcrypto.so.3",
                needed=("libc.so.6",),
                dynsyms=(DynSym(EVP, defined=True),),
                rodata=OPENSSL_BANNER,
            ).build(),
        },
    )


@pytest.mark.parametrize(
    "fixture_name",
    ["delocate_loader_path_wheel", "delocate_rpath_wheel", "unmangled_vendor_dir_wheel"],
)
def test_an_unmangled_vendored_dependency_is_bundled_not_mixed(context, request, fixture_name):
    """Keyed on `mangled` alone this reads `mixed`, with `BIN_OPENSSL_LINKAGE_UNKNOWN`
    and `BIN_NEEDED_SYSTEM_OPENSSL` both firing -- an unmangled `needed` entry read as
    the system library even though the wheel plainly ships its own copy right next to
    it.
    """
    wheel = request.getfixturevalue(fixture_name)
    record = scan(context, wheel)
    rule_ids = {f["rule_id"] for f in record["findings"]}
    assert record["verdict"]["conditions"]["openssl_linkage"] == "bundled"
    assert record["verdict"]["class"] == "CONDITIONAL"
    assert "BIN_BUNDLED_OPENSSL" in rule_ids
    assert "BIN_NEEDED_SYSTEM_OPENSSL" not in rule_ids
    assert "BIN_OPENSSL_LINKAGE_UNKNOWN" not in rule_ids
    assert "DERIVED_SYSTEM_OPENSSL_ONLY" not in rule_ids


# --------------------------------------------------------------------------
# A needed entry cannot confirm itself, and vendoring something else is not evidence
# --------------------------------------------------------------------------


@pytest.fixture
def self_colliding_wheel(tmp_path: Path) -> Path:
    """Sharpest repro: one object, no vendor directory, no second file.

    Its own file name happens to reduce to the same stem as an absolute, genuinely
    system dependency it declares, which must not let it answer its own question.
    """
    return build_wheel(
        subdir(tmp_path, "self-collision") / f"fakecrypto-1.0-{MANYLINUX}.whl",
        name="fakecrypto",
        version="1.0",
        tags=(MANYLINUX,),
        files={
            "fakecrypto/__init__.py": b"from fakecrypto import libcrypto\n",
            "fakecrypto/libcrypto.so": extension(
                soname="libcrypto.so",
                needed=("/usr/lib64/libcrypto.so.3", "libc.so.6"),
                dynsyms=(DynSym(EVP, defined=False),),
            ),
        },
    )


@pytest.fixture
def absolute_basename_collision_wheel(tmp_path: Path) -> Path:
    """The self-collision above, but for two genuinely different objects that happen
    to share a basename, rather than one object colliding with itself. An absolute
    `needed` entry is never resolved via search order by a real loader, so this must
    read exactly like `self_colliding_wheel` -- `system`, not `bundled` -- and the
    object count must not change that.
    """
    return build_wheel(
        subdir(tmp_path, "absolute-basename-collision") / f"fakecrypto-1.0-{MANYLINUX}.whl",
        name="fakecrypto",
        version="1.0",
        tags=(MANYLINUX,),
        files={
            "fakecrypto/__init__.py": b"from fakecrypto import libcrypto\n",
            "fakecrypto/libcrypto.so": extension(
                soname="libcrypto.so",
                needed=("/usr/lib64/libcrypto.so.3", "libc.so.6"),
                dynsyms=(DynSym(EVP, defined=False),),
            ),
            "fakecrypto/plugins/libcrypto.so": extension(soname="libcrypto.so"),
        },
    )


@pytest.fixture
def basename_collision_wheel(tmp_path: Path) -> Path:
    """The residual that stays possible beside the own-stem discount and the absolute
    short-circuit, confined to a relative `needed` entry: two genuinely different
    objects that happen to share a basename, where the dependency is a relative name
    that can genuinely be resolved by search order. The `bundled` reading may still be
    an imprecise false positive from the coincidence -- that is the accepted residual
    `DESIGN.md` documents for this shape -- but it must carry a finding.
    """
    return build_wheel(
        subdir(tmp_path, "basename-collision") / f"fakecrypto-1.0-{MANYLINUX}.whl",
        name="fakecrypto",
        version="1.0",
        tags=(MANYLINUX,),
        files={
            "fakecrypto/__init__.py": b"from fakecrypto import libcrypto\n",
            "fakecrypto/_ext.so": extension(needed=("libcrypto.so.3", "libc.so.6")),
            "fakecrypto/plugins/libcrypto.so.3": extension(soname="libcrypto.so.3"),
        },
    )


def test_a_self_referencing_dependency_is_not_manufactured_bundled(context, self_colliding_wheel):
    """Without the own-stem discount: `openssl_linkage: bundled`, `verdict.class:
    NO_CRYPTO_DETECTED`, `rule_ids: []`, `needs_human_review: false` -- a wheel that
    plainly, only links the system OpenSSL, would read as if nothing had been found at all.
    """
    record = scan(context, self_colliding_wheel)
    rule_ids = {f["rule_id"] for f in record["findings"]}
    assert record["verdict"]["conditions"]["openssl_linkage"] == "system"
    assert record["verdict"]["class"] == "CONDITIONAL"
    assert "BIN_NEEDED_SYSTEM_OPENSSL" in rule_ids
    assert "DERIVED_SYSTEM_OPENSSL_ONLY" in rule_ids
    assert "BIN_NEEDED_VENDORED_CRYPTO" not in rule_ids
    assert "BIN_BUNDLED_OPENSSL" not in rule_ids
    assert record["verdict"]["needs_human_review"] is True


def test_an_absolute_basename_collision_is_not_manufactured_bundled(
    context, absolute_basename_collision_wheel
):
    """Without the absolute short-circuit this reads `openssl_linkage: bundled` via
    `BIN_NEEDED_VENDORED_CRYPTO`, the same wrong answer `self_colliding_wheel` gets
    without the own-stem discount -- but an absolute path is never resolved via
    search order by a real loader, whatever else in the wheel happens to share its
    basename.
    """
    record = scan(context, absolute_basename_collision_wheel)
    rule_ids = {f["rule_id"] for f in record["findings"]}
    assert record["verdict"]["conditions"]["openssl_linkage"] == "system"
    assert "BIN_NEEDED_SYSTEM_OPENSSL" in rule_ids
    assert "DERIVED_SYSTEM_OPENSSL_ONLY" in rule_ids
    assert "BIN_NEEDED_VENDORED_CRYPTO" not in rule_ids
    assert "BIN_BUNDLED_OPENSSL" not in rule_ids


def test_an_absolute_needed_entry_beside_an_unreadable_basename_collision_stays_system(
    context, tmp_path: Path
) -> None:
    """The sharpest variant: the object that happens to share a basename with the
    absolute `needed` entry is not just unrelated, it is itself unreadable -- a
    truncated member, the same shape `test_a_truncated_extension_is_recorded_
    not_ignored` uses. An unreadable colliding object cannot rule out
    `_resolves_within_wheel`'s basename match either way, so this combination is the
    one most likely to read `bundled` through the `incomplete` path under any
    narrower rule. It must not: the absolute entry answers `system`
    on its own, unconditionally, and the unreadable member still gets its own
    `OPAQUE`-headline finding rather than being folded into, or silencing, the
    `openssl` answer -- `needs_human_review` stays `true` and the record never reads
    `NO_CRYPTO_DETECTED`.
    """
    good = extension(soname="libcrypto.so.3", needed=("libc.so.6",))
    wheel = build_wheel(
        tmp_path / f"fakecrypto-1.0-{MANYLINUX}.whl",
        name="fakecrypto",
        version="1.0",
        tags=(MANYLINUX,),
        files={
            "fakecrypto/__init__.py": b"from fakecrypto import libcrypto\n",
            "fakecrypto/_ext.so": extension(
                needed=("/usr/lib64/libcrypto.so.3", "libssl.so.3", "libc.so.6"),
                dynsyms=(DynSym(EVP, defined=False),),
            ),
            "fakecrypto/plugins/libcrypto.so.3": good[: len(good) // 2],
        },
    )
    record = scan(context, wheel)
    rule_ids = {f["rule_id"] for f in record["findings"]}
    assert record["errors"]
    assert record["verdict"]["conditions"]["openssl_linkage"] == "system"
    assert "DERIVED_SYSTEM_OPENSSL_ONLY" in rule_ids
    assert "BIN_NEEDED_VENDORED_CRYPTO" not in rule_ids
    assert record["verdict"]["class"] == "CONDITIONAL"
    assert "OPAQUE" in record["verdict"]["classes"]
    assert record["verdict"]["needs_human_review"] is True


def test_the_basename_collision_residual_is_never_silent(context, basename_collision_wheel):
    """The classification may still be an imprecise `bundled` from the coincidence --
    that residual imprecision is the accepted trade -- but `rule_ids` must never be
    empty and `needs_human_review` must never be `false` for it.
    """
    record = scan(context, basename_collision_wheel)
    assert record["findings"], "a bundled reading must always carry a finding"
    assert record["verdict"]["needs_human_review"] is True
    assert record["verdict"]["class"] != "NO_CRYPTO_DETECTED"


@pytest.fixture
def elf_system_openssl_with_unrelated_vendoring_wheel(tmp_path: Path) -> Path:
    """A FIPS-conscious build that genuinely links the system OpenSSL
    (auditwheel's `--exclude libcrypto.so.3`) while vendoring an unrelated library,
    libjpeg, in the same wheel. The vendor-shaped `RUNPATH` is about libjpeg, not
    OpenSSL.
    """
    return build_wheel(
        subdir(tmp_path, "elf-unrelated-vendoring") / f"fakecrypto-1.0-{MANYLINUX}.whl",
        name="fakecrypto",
        version="1.0",
        tags=(MANYLINUX,),
        files={
            "fakecrypto/__init__.py": b"from fakecrypto import _openssl\n",
            "fakecrypto/_openssl.abi3.so": extension(
                needed=("libcrypto.so.3", "libc.so.6"),
                runpath=("$ORIGIN/../fakecrypto.libs",),
                dynsyms=(DynSym(EVP, defined=False),),
            ),
            "fakecrypto.libs/libjpeg.so.8": ElfBuilder(
                soname="libjpeg.so.8", needed=("libc.so.6",)
            ).build(),
        },
    )


@pytest.fixture
def macho_system_openssl_with_unrelated_vendoring_wheel(tmp_path: Path) -> Path:
    """The same shape via `LC_RPATH`: the wheel vendors an unrelated libjpeg under
    `.dylibs/`, but the extension's own OpenSSL dependency is an absolute, genuinely
    system path.
    """
    return build_wheel(
        tmp_path / f"fakecrypto-1.0-{MACOS_TAG}.whl",
        name="fakecrypto",
        version="1.0",
        tags=(MACOS_TAG,),
        files={
            "fakecrypto/__init__.py": b"from fakecrypto import _ext\n",
            "fakecrypto/_ext.cpython-312-darwin.so": MachOBuilder(
                load_dylibs=("/usr/lib/libSystem.B.dylib", "/usr/lib/libcrypto.3.dylib"),
                rpaths=("@loader_path/.dylibs",),
                symbols=(
                    MachOSym("_PyInit__ext", True),
                    MachOSym("_EVP_DigestInit_ex", False),
                ),
            ).build(),
            "fakecrypto/.dylibs/libjpeg.9.dylib": MachOBuilder(
                id_dylib="@loader_path/libjpeg.9.dylib",
                load_dylibs=("/usr/lib/libSystem.B.dylib",),
            ).build(),
        },
    )


@pytest.mark.parametrize(
    "fixture_name",
    [
        "elf_system_openssl_with_unrelated_vendoring_wheel",
        "macho_system_openssl_with_unrelated_vendoring_wheel",
    ],
)
def test_vendoring_something_else_does_not_downgrade_a_genuine_system_link(
    context, request, fixture_name
):
    """Without the `wheel_incompletely_read` gate: `openssl_linkage: unknown`,
    `verdict.class: OPAQUE`, `BIN_OPENSSL_LINKAGE_UNKNOWN` -- a vendor-shaped
    `RPATH`/`RUNPATH` alone would be enough to downgrade a plain, genuine system
    dependency, even though nothing the wheel ships could possibly be what it names.
    """
    wheel = request.getfixturevalue(fixture_name)
    record = scan(context, wheel)
    rule_ids = {f["rule_id"] for f in record["findings"]}
    assert record["verdict"]["conditions"]["openssl_linkage"] == "system"
    assert record["verdict"]["class"] == "CONDITIONAL"
    assert "BIN_NEEDED_SYSTEM_OPENSSL" in rule_ids
    assert "DERIVED_SYSTEM_OPENSSL_ONLY" in rule_ids
    assert "BIN_OPENSSL_LINKAGE_UNKNOWN" not in rule_ids


# --------------------------------------------------------------------------
# The rest of the corpus
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["bcrypt", "pycryptodome", "pycryptodomex", "PyNaCl", "libnacl", "rsa", "ecdsa"],
)
def test_known_non_approved_distributions(context, tmp_path: Path, name: str) -> None:
    wheel = build_wheel(
        tmp_path / f"{name}-1.0-py3-none-any.whl",
        name=name,
        version="1.0",
        files={f"{name.lower()}/__init__.py": b"VALUE = 1\n"},
    )
    assert scan(context, wheel)["verdict"]["class"] == "NON_APPROVED_CRYPTO"


@pytest.mark.parametrize("name", ["cryptography", "pyOpenSSL", "M2Crypto"])
def test_known_system_crypto_wrappers(context, tmp_path: Path, name: str) -> None:
    wheel = build_wheel(
        tmp_path / f"{name}-1.0-py3-none-any.whl",
        name=name,
        version="1.0",
        files={"pkg/__init__.py": b"VALUE = 1\n"},
    )
    record = scan(context, wheel)
    assert record["verdict"]["class"] == "CONDITIONAL"
    assert record["verdict"]["needs_human_review"] is True


@pytest.mark.parametrize("name", ["blake3", "xxhash", "murmurhash"])
def test_known_context_dependent_hashes(context, tmp_path: Path, name: str) -> None:
    wheel = build_wheel(
        tmp_path / f"{name}-1.0-py3-none-any.whl",
        name=name,
        version="1.0",
        files={name + "/__init__.py": b"VALUE = 1\n"},
    )
    assert scan(context, wheel)["verdict"]["class"] == "CONTEXT_DEPENDENT"


def test_a_pure_data_wheel_finds_nothing(context, tmp_path: Path) -> None:
    wheel = build_wheel(
        tmp_path / "puredata-1.0-py3-none-any.whl",
        name="puredata",
        version="1.0",
        files={"puredata/table.py": b"ROWS = [1, 2, 3]\n"},
    )
    record = scan(context, wheel)
    assert record["verdict"]["class"] == "NO_CRYPTO_DETECTED"
    assert record["verdict"]["needs_human_review"] is False


def test_a_bundled_libsodium_is_non_approved(context, tmp_path: Path) -> None:
    wheel = build_wheel(
        tmp_path / f"fakenacl-1.5.0-{MANYLINUX}.whl",
        name="fakenacl",
        version="1.5.0",
        tags=(MANYLINUX,),
        files={
            "fakenacl/__init__.py": b"from fakenacl import _sodium\n",
            "fakenacl/_sodium.abi3.so": extension(
                needed=("libsodium-9f2c1e3a.so.23", "libc.so.6"),
                dynsyms=(DynSym("crypto_box_easy", defined=False),),
            ),
            "fakenacl.libs/libsodium-9f2c1e3a.so.23": ElfBuilder(
                soname="libsodium-9f2c1e3a.so.23",
                dynsyms=(DynSym("crypto_box_easy", defined=True), DynSym("sodium_init", True)),
                rodata=b"libsodium 1.0.19\x00",
            ).build(),
        },
    )
    record = scan(context, wheel)
    assert record["verdict"]["class"] == "NON_APPROVED_CRYPTO"
    assert record["verdict"]["conditions"]["libsodium_linkage"] == "bundled"


def test_a_rust_extension_reports_its_crates(context, tmp_path: Path) -> None:
    wheel = build_wheel(
        tmp_path / f"fakerust-1.0-{MANYLINUX}.whl",
        name="fakerust",
        version="1.0",
        tags=(MANYLINUX,),
        generator="maturin (1.7.0)",
        files={
            "fakerust/__init__.py": b"from fakerust import _rust\n",
            "fakerust/_rust.abi3.so": extension(rodata=CARGO_RING + CARGO_BLAKE3),
        },
    )
    record = scan(context, wheel)
    crates = {
        finding["subject"]
        for finding in record["findings"]
        if finding["rule_id"] == "BIN_RUST_CRYPTO_CRATE"
    }
    assert crates == {"ring", "blake3"}
    assert record["verdict"]["class"] == "NON_APPROVED_CRYPTO"


def test_a_pep_770_sbom_is_read(context, tmp_path: Path) -> None:
    sbom = json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {"name": "ring", "version": "0.17.8", "purl": "pkg:cargo/ring@0.17.8"},
                {"name": "openssl", "version": "3.0.14", "purl": "pkg:generic/openssl@3.0.14"},
            ],
        }
    ).encode()
    wheel = build_wheel(
        tmp_path / "fakesbom-1.0-py3-none-any.whl",
        name="fakesbom",
        version="1.0",
        generator="maturin (1.7.0)",
        files={"fakesbom/__init__.py": b"VALUE = 1\n"},
        sboms={"rust.cdx.json": sbom},
    )
    record = scan(context, wheel)
    subjects = {
        finding["subject"]
        for finding in record["findings"]
        if finding["rule_id"] == "SBOM_CRYPTO_COMPONENT"
    }
    assert subjects == {"ring", "openssl"}
    assert record["verdict"]["conditions"]["openssl_linkage"] == "unknown"
    assert "OPAQUE" in record["verdict"]["classes"]


# --------------------------------------------------------------------------
# Opacity: never clean merely because we could not look
# --------------------------------------------------------------------------


def test_a_bytecode_only_wheel_is_opaque(context, tmp_path: Path) -> None:
    wheel = build_wheel(
        tmp_path / "fakepyc-1.0-py3-none-any.whl",
        name="fakepyc",
        version="1.0",
        files={"fakepyc/__pycache__/__init__.cpython-311.pyc": b"\x00" * 64},
    )
    record = scan(context, wheel)
    assert record["verdict"]["class"] == "OPAQUE"
    assert record["artifacts"]["source_available"] is False


def test_a_binary_that_yields_nothing_is_opaque(context, tmp_path: Path) -> None:
    wheel = build_wheel(
        tmp_path / f"fakestripped-1.0-{MANYLINUX}.whl",
        name="fakestripped",
        version="1.0",
        tags=(MANYLINUX,),
        files={
            "fakestripped/__init__.py": b"VALUE = 1\n",
            "fakestripped/_ext.abi3.so": ElfBuilder(include_dynamic=False).build(),
        },
    )
    record = scan(context, wheel)
    assert record["verdict"]["class"] == "OPAQUE"
    assert "BIN_OPAQUE" in record["verdict"]["rule_ids"]


def test_an_unopenable_wheel_is_opaque_not_clean(context, tmp_path: Path) -> None:
    wheel = tmp_path / "fakebroken-1.0-py3-none-any.whl"
    wheel.write_bytes(b"this is not a zip file")
    record = scan(context, wheel)
    assert record["verdict"]["class"] == "OPAQUE"
    assert record["verdict"]["needs_human_review"] is True


def test_a_truncated_extension_is_recorded_not_ignored(context, tmp_path: Path) -> None:
    good = extension(dynsyms=(DynSym(EVP, defined=True),))
    wheel = build_wheel(
        tmp_path / f"faketrunc-1.0-{MANYLINUX}.whl",
        name="faketrunc",
        version="1.0",
        tags=(MANYLINUX,),
        files={"faketrunc/_ext.abi3.so": good[: len(good) // 2]},
    )
    record = scan(context, wheel)
    assert record["errors"]
    assert record["verdict"]["class"] == "OPAQUE"


# --------------------------------------------------------------------------
# Determinism over the whole corpus
# --------------------------------------------------------------------------


def test_scanning_the_same_wheel_twice_is_byte_identical(context, bundled_wheel) -> None:
    from wheel_crypto_scan.record import to_json_line

    assert to_json_line(scan(context, bundled_wheel)) == to_json_line(scan(context, bundled_wheel))


def test_a_rebuilt_fixture_produces_the_same_record(context, tmp_path: Path) -> None:
    """The builder is deterministic, so the record must be too."""
    from wheel_crypto_scan.record import to_json_line

    def build(directory: Path) -> Path:
        directory.mkdir()
        return build_wheel(
            directory / f"fakecrypto-42.0.5-{MANYLINUX}.whl",
            name="fakecrypto",
            version="42.0.5",
            tags=(MANYLINUX,),
            files={
                "fakecrypto/_openssl.abi3.so": extension(
                    needed=("libcrypto.so.3", "libc.so.6"),
                    dynsyms=(DynSym(EVP, defined=False),),
                )
            },
        )

    first = to_json_line(scan(context, build(tmp_path / "a")))
    second = to_json_line(scan(context, build(tmp_path / "b")))
    assert first == second


def test_a_macho_that_declares_no_dependency_is_not_opaque(context, tmp_path: Path) -> None:
    """Every slice parsed, two symbols were read, nothing crypto-related was found.

    `needed` is tested before the symbol count, so a dylib that links `libSystem` is
    never opaque. This is the shape that can be: no dependency to fall back on, and a
    symbol count in a field `is_opaque` has to know to look at, or the object reports
    having told us nothing while carrying the symbols it told us.
    """
    slices = [
        MachOBuilder(id_dylib="_ext.so", symbols=(MachOSym("_PyInit__ext", defined=True),)).build(),
        MachOBuilder(
            is64=False,
            big_endian=True,
            id_dylib="_ext.so",
            symbols=(MachOSym("_PyInit__ext", defined=True),),
        ).build(),
    ]
    tag = "cp312-cp312-macosx_11_0_universal2"
    wheel = build_wheel(
        tmp_path / f"universal-1.0-{tag}.whl",
        name="universal",
        version="1.0",
        tags=(tag,),
        files={
            "universal/__init__.py": "def add(a, b):\n    return a + b\n",
            "universal/_ext.so": build_fat(slices),
        },
    )
    record = scan_wheel(wheel, context)
    binary = record["binaries"][0]
    assert binary["partial_analysis"] is False
    assert binary["partial_reasons"] == []
    assert binary["symbol_counts"]["symtab"] == 2
    assert record["verdict"]["class"] == "NO_CRYPTO_DETECTED"


def test_a_universal_binary_whose_slices_disagree_between_bundled_and_system_is_mixed(
    context, tmp_path: Path
) -> None:
    """Through the real Mach-O reader and the whole scan pipeline, not just a
    hand-built `BinaryEvidence`: one slice's `LC_LOAD_DYLIB` names a hash-renamed
    vendored copy (`bundled`), the other slice's names the host library outright
    (`system`). `binfmt.macho` merges both slices' `needed` into the union on one
    `BinaryEvidence` (`test_load_dylibs_merge_across_slices` in `test_binfmt_macho.py`
    pins that merge itself), so this object carries both signals at once, the same as
    if the two slices had been read as separate objects and combined by `_aggregate`.

    A `needed` loop in `linkage._binary_posture` that returned `LINKAGE_BUNDLED` on
    the first entry that resolved that way, before the second, disagreeing entry was
    ever looked at, would read this `bundled` instead of `mixed`.
    """
    slices = [
        MachOBuilder(id_dylib="_ext.so", load_dylibs=("libcrypto-3a1f2b4c.3.dylib",)).build(),
        MachOBuilder(
            is64=False,
            big_endian=True,
            id_dylib="_ext.so",
            load_dylibs=("/usr/lib/libcrypto.3.dylib",),
        ).build(),
    ]
    tag = "cp312-cp312-macosx_11_0_universal2"
    wheel = build_wheel(
        tmp_path / f"universal-1.0-{tag}.whl",
        name="universal",
        version="1.0",
        tags=(tag,),
        files={
            "universal/__init__.py": "def add(a, b):\n    return a + b\n",
            "universal/_ext.so": build_fat(slices),
        },
    )
    record = scan_wheel(wheel, context)
    # `binfmt.macho` merges and sorts `needed` across slices, so the wheel-internal
    # entry sorts ahead of the absolute path.
    assert record["binaries"][0]["needed"] == [
        "/usr/lib/libcrypto.3.dylib",
        "libcrypto-3a1f2b4c.3.dylib",
    ]
    assert record["verdict"]["conditions"]["openssl_linkage"] == "mixed"


def test_a_stripped_macho_wheel_does_not_claim_there_is_no_openssl(context, tmp_path: Path):
    """The whole chain for the partial-cause linkage split, which every other test for
    it drives from the middle.

    Reader to `partial_reasons` to the linkage policy to the rule to the record. The
    unit tests hand `resolve_linkage` a `BinaryEvidence` built by hand, so a reader
    that stopped emitting `macho_symtab_incomplete` would leave all of them green and
    put `openssl_linkage: none` on every stripped macOS wheel.

    A stripped dylib is what `strip` leaves and what every release macOS wheel is, so
    this is the ordinary object rather than a crafted one.
    """
    tag = "cp312-cp312-macosx_11_0_arm64"
    wheel = build_wheel(
        tmp_path / f"stripped-1.0-{tag}.whl",
        name="stripped",
        version="1.0",
        tags=(tag,),
        files={
            "stripped/__init__.py": "def add(a, b):\n    return a + b\n",
            "stripped/_ext.so": MachOBuilder(
                id_dylib="_ext.so", load_dylibs=("/usr/lib/libSystem.B.dylib",)
            ).build(),
        },
    )
    record = scan_wheel(wheel, context)
    binary = record["binaries"][0]
    assert binary["partial_analysis"] is True
    assert binary["partial_reasons"] == ["macho_symtab_incomplete"]
    # `needed` is non-empty, so the object is not opaque and nothing else would have
    # stopped it answering definitely.
    assert binary["needed"] == ["/usr/lib/libSystem.B.dylib"]
    assert record["verdict"]["conditions"]["openssl_linkage"] == "unknown"
    assert "BIN_OPENSSL_LINKAGE_UNKNOWN" in {f["rule_id"] for f in record["findings"]}


def test_a_pe_that_declares_no_import_is_not_opaque(context, tmp_path: Path) -> None:
    """The PE half of the same shape: its named entries land in `symtab_count` too.

    A resource-only or statically linked DLL imports nothing, so `needed` cannot
    rescue it either, and the export it does declare has to be visible to `is_opaque`.
    """
    tag = "cp312-cp312-win_amd64"
    wheel = build_wheel(
        tmp_path / f"winext-1.0-{tag}.whl",
        name="winext",
        version="1.0",
        tags=(tag,),
        files={
            "winext/__init__.py": "def add(a, b):\n    return a + b\n",
            "winext/_ext.pyd": PEBuilder(
                dll_name="_ext.pyd", exports=(PEExport("PyInit__ext"),)
            ).build(),
        },
    )
    record = scan_wheel(wheel, context)
    assert record["binaries"][0]["symbol_counts"]["symtab"] == 1
    assert "BIN_OPAQUE" not in {f["rule_id"] for f in record["findings"]}
    assert record["verdict"]["conditions"]["openssl_linkage"] == "none"


# --------------------------------------------------------------------------
# .exe members are sniffed too
#
# `is_binary_member` accepts a member by suffix, by vendor path, by living in a sniff
# directory with no dot in its name, or by the executable bit with no dot in its name.
# Without `.exe` among the suffixes, a Windows executable fails every route: the wrong
# suffix, and the dot disqualifies it from both "no dot" fallbacks. The same PE,
# shipped as `bin/openssl` on manylinux and `openssl.exe` on win_amd64, would be read
# on one platform and not the other.
# --------------------------------------------------------------------------

WIN_TAG = "cp312-cp312-win_amd64"


def _openssl_pe() -> bytes:
    """A minimal reproduction: imports `KERNEL32.dll`, exports
    `EVP_DigestInit_ex`, carries the OpenSSL banner in `.text`."""
    return PEBuilder(
        dll_name="openssl.exe",
        imports=(PEImport("KERNEL32.dll", names=("ExitProcess",)),),
        exports=(PEExport(EVP),),
        text=OPENSSL_BANNER,
    ).build()


@pytest.mark.parametrize("suffix", ["", ".exe"])
def test_an_exe_member_is_read_like_its_suffixless_equivalent(
    context, tmp_path: Path, suffix: str
) -> None:
    wheel = build_wheel(
        tmp_path / f"pkg-1.0-{WIN_TAG}.whl",
        name="pkg",
        version="1.0",
        tags=(WIN_TAG,),
        files={f"pkg-1.0.data/scripts/openssl{suffix}": _openssl_pe()},
    )
    record = scan(context, wheel)
    assert record["verdict"]["class"] == "CONDITIONAL"
    assert record["verdict"]["conditions"]["openssl_linkage"] == "static"
    assert "BIN_STATIC_OPENSSL" in record["verdict"]["rule_ids"]
    assert len(record["artifacts"]["extensions"]) == 1


def test_the_exe_and_suffixless_forms_produce_the_same_record_but_for_the_path(
    context, tmp_path: Path
) -> None:
    """The direct pin of the `.exe`/suffixless reproduction pair above: same bytes, same verdict,
    same linkage, same extension count, differing only in the path each was shipped
    at."""
    plain = build_wheel(
        subdir(tmp_path, "plain") / f"pkg-1.0-{WIN_TAG}.whl",
        name="pkg",
        version="1.0",
        tags=(WIN_TAG,),
        files={"pkg-1.0.data/scripts/openssl": _openssl_pe()},
    )
    exe = build_wheel(
        subdir(tmp_path, "exe") / f"pkg-1.0-{WIN_TAG}.whl",
        name="pkg",
        version="1.0",
        tags=(WIN_TAG,),
        files={"pkg-1.0.data/scripts/openssl.exe": _openssl_pe()},
    )
    plain_record = scan(context, plain)
    exe_record = scan(context, exe)
    assert plain_record["verdict"] == exe_record["verdict"]
    assert plain_record["artifacts"]["extensions"] == [
        {"path": "pkg-1.0.data/scripts/openssl", "format": "pe"}
    ]
    assert exe_record["artifacts"]["extensions"] == [
        {"path": "pkg-1.0.data/scripts/openssl.exe", "format": "pe"}
    ]


def test_a_malformed_exe_member_degrades_like_any_other_unreadable_binary(
    context, tmp_path: Path
) -> None:
    """Garbage bytes named `.exe` (no `MZ` magic, so `FORMAT_UNKNOWN`) are sniffed and
    read for strings, the same as garbage bytes named `.dll` always were: never a
    crash, never silently dropped, and `OPAQUE` when nothing crypto-relevant turns up
    -- the same shape `test_a_binary_that_yields_nothing_is_opaque` pins for ELF.
    """
    wheel = build_wheel(
        tmp_path / f"pkg-1.0-{WIN_TAG}.whl",
        name="pkg",
        version="1.0",
        tags=(WIN_TAG,),
        files={"pkg-1.0.data/scripts/broken.exe": b"\x00" * 128},
    )
    record = scan(context, wheel)
    assert record["verdict"]["class"] == "OPAQUE"
    assert "BIN_OPAQUE" in record["verdict"]["rule_ids"]


def test_a_pyd_member_is_read_beside_exe_members(context, tmp_path: Path) -> None:
    """`.pyd`/`.dll` members are read the same way regardless of `.exe` recognition."""
    wheel = build_wheel(
        tmp_path / f"winext-1.0-{WIN_TAG}.whl",
        name="winext",
        version="1.0",
        tags=(WIN_TAG,),
        files={
            "winext/__init__.py": b"from winext import _ext\n",
            "winext/_ext.pyd": _openssl_pe(),
        },
    )
    record = scan(context, wheel)
    assert record["verdict"]["conditions"]["openssl_linkage"] == "static"
    assert len(record["artifacts"]["extensions"]) == 1


# --------------------------------------------------------------------------
# a `.a`/`.lib` static archive is visible to the scanner
# --------------------------------------------------------------------------


def test_a_vendored_static_archive_is_visible(context, tmp_path: Path) -> None:
    """Without an archive reader and a route for `.a` into `is_binary_member`, a wheel
    whose only crypto evidence is a version banner inside an archive member -- a
    vendored `libcrypto.a` bundled for downstream linking -- would read
    `NO_CRYPTO_DETECTED` with nothing recorded at all. The archive's member is a real,
    separate object in `binaries[]`, and its banner (a `.o` file's `.rodata`, findable
    regardless of `.dynsym`/`.symtab`) is found.
    """
    archive = build_ar([ArMember("libcrypto.o", ElfBuilder(rodata=OPENSSL_BANNER).build())])
    wheel = build_wheel(
        tmp_path / f"fakecrypto-1.0-{MANYLINUX}.whl",
        name="fakecrypto",
        version="1.0",
        tags=(MANYLINUX,),
        files={
            "fakecrypto/__init__.py": b"VALUES = [1, 2, 3]\n",
            "fakecrypto/vendor/libcrypto.a": archive,
        },
    )
    record = scan(context, wheel)
    paths = [b["path"] for b in record["binaries"]]
    assert paths == ["fakecrypto/vendor/libcrypto.a(libcrypto.o)"]
    assert record["verdict"]["class"] != "NO_CRYPTO_DETECTED"
    assert any(m["group"] == "openssl_banner" for m in record["binaries"][0]["matched_strings"])


def test_a_malformed_dot_a_member_still_falls_back_to_strings(context, tmp_path: Path) -> None:
    """A `.a` suffix whose bytes are not actually `ar`-format (an older MSVC import
    library, say) is opened -- the suffix says it is worth trying -- and falls
    through to the same strings-only fallback any other unrecognised format gets,
    rather than being misread as a broken archive.
    """
    wheel = build_wheel(
        tmp_path / f"fakecrypto-1.0-{MANYLINUX}.whl",
        name="fakecrypto",
        version="1.0",
        tags=(MANYLINUX,),
        files={
            "fakecrypto/__init__.py": b"VALUES = [1, 2, 3]\n",
            "fakecrypto/vendor/legacy.lib": b"\x00\x00not-ar-format"
            + b"\x00" * 64
            + OPENSSL_BANNER,
        },
    )
    record = scan(context, wheel)
    assert record["errors"] == []
    assert record["binaries"][0]["format"] == "unknown"
    assert any(m["group"] == "openssl_banner" for m in record["binaries"][0]["matched_strings"])


# --------------------------------------------------------------------------
# A linked crypto library is never "nothing found"
# --------------------------------------------------------------------------


def test_a_wheel_linking_system_libsodium_is_not_reported_as_clean(context, tmp_path: Path) -> None:
    """The linkage was resolved and sits in the same record; the class must reflect it."""
    wheel = build_wheel(
        tmp_path / f"fakesodium-1.0-{MANYLINUX}.whl",
        name="fakesodium",
        version="1.0",
        tags=(MANYLINUX,),
        files={
            "fakesodium/_ext.abi3.so": ElfBuilder(
                needed=("libsodium.so.23", "libc.so.6"),
                dynsyms=(DynSym("some_internal_symbol", defined=True),),
            ).build()
        },
    )
    record = scan(context, wheel)
    assert record["verdict"]["conditions"]["libsodium_linkage"] == "system"
    assert record["verdict"]["class"] != "NO_CRYPTO_DETECTED"


def test_a_wheel_bundling_libgcrypt_is_not_reported_as_clean(context, tmp_path: Path) -> None:
    wheel = build_wheel(
        tmp_path / f"fakegcrypt-1.0-{MANYLINUX}.whl",
        name="fakegcrypt",
        version="1.0",
        tags=(MANYLINUX,),
        files={
            "fakegcrypt.libs/libgcrypt-1a2b3c4d.so.20": ElfBuilder(
                soname="libgcrypt-1a2b3c4d.so.20",
                dynsyms=(DynSym("gcry_check_version", defined=True),),
            ).build()
        },
    )
    record = scan(context, wheel)
    assert record["verdict"]["class"] == "CONDITIONAL"
    assert record["verdict"]["conditions"]["libgcrypt_linkage"] == "bundled"


# --------------------------------------------------------------------------
# A vendored Windows DLL is recognised as bundled
# --------------------------------------------------------------------------


def test_a_vendored_dll_is_recognised_as_bundled(context, tmp_path: Path) -> None:
    """A vendored libcrypto must not classify differently because of its extension."""
    wheel = build_wheel(
        tmp_path / f"fakewin-1.0-{WINDOWS}.whl",
        name="fakewin",
        version="1.0",
        tags=(WINDOWS,),
        files={
            "fakewin.libs/libcrypto-3a1f2b4c.dll": ElfBuilder(
                soname="libcrypto-3a1f2b4c.dll",
                dynsyms=(DynSym("EVP_DigestInit_ex", defined=True),),
                rodata=b"OpenSSL 3.0.14 4 Jun 2024\x00",
            ).build()
        },
    )
    record = scan(context, wheel)
    assert record["verdict"]["conditions"]["openssl_linkage"] == "bundled"
    assert "BIN_BUNDLED_OPENSSL" in record["verdict"]["rule_ids"]


# --------------------------------------------------------------------------
# A finding names what kind of thing its subject is
# --------------------------------------------------------------------------


def test_findings_say_what_kind_of_thing_the_subject_is(context, tmp_path: Path) -> None:
    """Without this a consumer needs a private rule-id lookup table to read `subject`."""
    wheel = build_wheel(
        tmp_path / f"fakerust-1.0-{MANYLINUX}.whl",
        name="fakerust",
        version="1.0",
        tags=(MANYLINUX,),
        files={
            "fakerust/_rust.abi3.so": ElfBuilder(
                needed=("libc.so.6",),
                rodata=b"/root/.cargo/registry/src/index.crates.io-1/ring-0.17.8/src/lib.rs\x00",
            ).build()
        },
    )
    record = scan(context, wheel)
    kinds = {
        finding["rule_id"]: finding["subject_kind"]
        for finding in record["findings"]
        if finding["subject"] is not None
    }
    assert kinds["BIN_RUST_CRYPTO_CRATE"] == "crate"
    assert all(
        finding["subject_kind"] is not None
        for finding in record["findings"]
        if finding["subject"] is not None
    )


def test_a_finding_without_a_subject_has_no_subject_kind(context, tmp_path: Path) -> None:
    wheel = build_wheel(
        tmp_path / "demo-1.0-py3-none-any.whl",
        name="demo",
        version="1.0",
        files={"demo/__init__.py": b"import hashlib\nh = hashlib.md5()\n"},
    )
    record = scan(context, wheel)
    finding = next(f for f in record["findings"] if f["rule_id"] == "PY_WEAK_HASH_CALL")
    assert finding["subject"] is None
    assert finding["subject_kind"] is None


# --------------------------------------------------------------------------
# usedforsecurity: an explicit flag is at least as confident as no keyword,
# and a non-constant flag on a weak hash is context-dependent
#
# The AST extractor records "true", "false", "unresolved" and "absent"
# directly; what the ruleset's match tables do with each value is the whole
# of the policy question here.
# --------------------------------------------------------------------------


def _hashlib_wheel(tmp_path: Path, name: str, source: bytes):
    return build_wheel(
        tmp_path / f"{name}-1.0-py3-none-any.whl",
        name=name,
        version="1.0",
        files={f"{name}/__init__.py": source},
    )


def test_a_bare_weak_hash_call_is_fips_breaking(context, tmp_path: Path) -> None:
    """No usedforsecurity keyword at all: the ordinary case."""
    wheel = _hashlib_wheel(tmp_path, "bare", b"import hashlib\nhashlib.md5(b'x')\n")
    record = scan(context, wheel)
    assert record["verdict"]["class"] == "FIPS_BREAKING"
    assert "PY_WEAK_HASH_CALL" in record["verdict"]["rule_ids"]


def test_an_explicit_usedforsecurity_true_is_fips_breaking(context, tmp_path: Path) -> None:
    """The code declares itself security use; that is at least as confident a signal
    as no keyword at all."""
    wheel = _hashlib_wheel(
        tmp_path, "explicittrue", b"import hashlib\nhashlib.md5(b'x', usedforsecurity=True)\n"
    )
    record = scan(context, wheel)
    assert record["verdict"]["class"] == "FIPS_BREAKING"
    assert "PY_WEAK_HASH_CALL" in record["verdict"]["rule_ids"]


def test_a_non_constant_usedforsecurity_on_md5_is_context_dependent(
    context, tmp_path: Path
) -> None:
    wheel = _hashlib_wheel(
        tmp_path,
        "nonconstflag",
        b"import hashlib\nflag = True\nhashlib.md5(b'x', usedforsecurity=flag)\n",
    )
    record = scan(context, wheel)
    assert record["verdict"]["class"] == "CONTEXT_DEPENDENT"
    assert "PY_WEAK_HASH_UNRESOLVED" in record["verdict"]["rule_ids"]
    assert "PY_WEAK_HASH_CALL" not in record["verdict"]["rule_ids"]


def test_a_non_constant_usedforsecurity_on_hashlib_new_weak_is_context_dependent(
    context, tmp_path: Path
) -> None:
    wheel = _hashlib_wheel(
        tmp_path,
        "nonconstflagnew",
        b"import hashlib\nflag = True\nhashlib.new('md5', usedforsecurity=flag)\n",
    )
    record = scan(context, wheel)
    assert record["verdict"]["class"] == "CONTEXT_DEPENDENT"
    assert "PY_WEAK_HASH_UNRESOLVED" in record["verdict"]["rule_ids"]
    assert "PY_WEAK_HASH_CALL" not in record["verdict"]["rule_ids"]


def test_a_variable_algorithm_name_is_context_dependent(context, tmp_path: Path) -> None:
    """hashlib.new(name): the algorithm itself is unresolved, independent of
    usedforsecurity."""
    wheel = _hashlib_wheel(
        tmp_path, "varalgo", b"import hashlib\nname = 'md5'\nhashlib.new(name)\n"
    )
    record = scan(context, wheel)
    assert record["verdict"]["class"] == "CONTEXT_DEPENDENT"
    assert "PY_WEAK_HASH_UNRESOLVED" in record["verdict"]["rule_ids"]


def test_an_explicit_usedforsecurity_false_is_marked_context_dependent(
    context, tmp_path: Path
) -> None:
    """An explicit usedforsecurity=False pins a marked, context-dependent finding,
    never the plain weak-hash-call one."""
    wheel = _hashlib_wheel(
        tmp_path, "explicitfalse", b"import hashlib\nhashlib.md5(b'x', usedforsecurity=False)\n"
    )
    record = scan(context, wheel)
    assert record["verdict"]["class"] == "CONTEXT_DEPENDENT"
    assert "PY_WEAK_HASH_CALL_MARKED" in record["verdict"]["rule_ids"]
    assert "PY_WEAK_HASH_CALL" not in record["verdict"]["rule_ids"]


def test_a_non_constant_usedforsecurity_on_a_strong_hash_is_not_flagged(
    context, tmp_path: Path
) -> None:
    """sha256 stays approved regardless of usedforsecurity: a non-constant flag on it
    is a different, less alarming shape than the same flag on a weak hash, and must
    not borrow PY_WEAK_HASH_UNRESOLVED's finding."""
    wheel = _hashlib_wheel(
        tmp_path,
        "strongnonconst",
        b"import hashlib\nflag = True\nhashlib.new('sha256', usedforsecurity=flag)\n",
    )
    record = scan(context, wheel)
    assert record["verdict"]["class"] == "NO_CRYPTO_DETECTED"
    assert not {"PY_WEAK_HASH_CALL", "PY_WEAK_HASH_CALL_MARKED", "PY_WEAK_HASH_UNRESOLVED"} & set(
        record["verdict"]["rule_ids"]
    )


# --------------------------------------------------------------------------
# A statically linked OpenSSL is not reported as clean
# --------------------------------------------------------------------------


def test_a_statically_linked_openssl_4_is_not_reported_as_clean(context, tmp_path: Path) -> None:
    """An object whose only OpenSSL evidence is its banner must read `static`.

    `cryptography` 50.0.1's `_rust.abi3.so` compiles OpenSSL 4.0.2 in, declares no
    dependency on libcrypto, and exports no OpenSSL symbol: the banner is the whole of
    the evidence. The banner group names every major digit, because a major it did not
    name would read as `openssl_linkage: none`. `tests/test_ruleset.py` pins that
    directly.
    """
    wheel = build_wheel(
        tmp_path / f"staticssl-1.0-{MANYLINUX}.whl",
        name="staticssl",
        version="1.0",
        tags=(MANYLINUX,),
        files={
            "staticssl/_rust.abi3.so": ElfBuilder(
                needed=("libc.so.6",),
                rodata=b"\x00OpenSSL 4.0.2 25 Aug 2026\x00",
            ).build()
        },
    )
    record = scan(context, wheel)
    assert record["verdict"]["conditions"]["openssl_linkage"] == "static"
    assert record["verdict"]["class"] != "NO_CRYPTO_DETECTED"


# --------------------------------------------------------------------------
# A vendored-OpenSSL Rust build names itself, and must be read
# --------------------------------------------------------------------------


def test_a_vendored_openssl_crate_path_is_not_reported_as_clean(context, tmp_path: Path) -> None:
    """`openssl-src` is what `openssl-sys`'s vendored feature builds OpenSSL with.

    An extension that went that way carries no libcrypto dependency and no vendor
    directory, and a stripped build may not carry the banner either, so the crate path
    can be all that is left. It names the crate, not the posture: `openssl-sys` links
    the host's OpenSSL under `OPENSSL_NO_VENDOR` even with the feature on, so the
    object reads `unknown` rather than `static`.
    """
    cargo_path = b"/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/openssl-src-300.5.2/"
    wheel = build_wheel(
        tmp_path / f"vendoredssl-1.0-{MANYLINUX}.whl",
        name="vendoredssl",
        version="1.0",
        tags=(MANYLINUX,),
        files={
            "vendoredssl/_rust.abi3.so": ElfBuilder(
                needed=("libc.so.6",), rodata=b"\x00" + cargo_path + b"\x00"
            ).build()
        },
    )
    record = scan(context, wheel)
    # Not `"openssl-src" in crates`: the extractor records every cargo path it finds
    # whether or not the ruleset knows the name, so that assertion passes with the
    # entry deleted. What this test is about is the finding the entry produces.
    finding = next(
        f
        for f in record["findings"]
        if f["rule_id"] == "BIN_RUST_CRYPTO_CRATE" and f["subject"] == "openssl-src"
    )
    assert finding["verdict"] == "CONDITIONAL"
    assert record["verdict"]["class"] == "CONDITIONAL"
    assert record["verdict"]["conditions"]["openssl_linkage"] == "unknown"
    assert "OPAQUE" in record["verdict"]["classes"]


@pytest.mark.parametrize("sep", ["/", "\\"])
def test_cargo_paths_are_read_whichever_separator_built_the_wheel(
    context, tmp_path: Path, sep: str
) -> None:
    """A wheel built on Windows spells its cargo paths with backslashes.

    `cargo_path_regex` accepts both separators: a forward-slash-only pattern reads
    cryptography 50.0.1's win_amd64 `.pyd`, which holds 153 `cargo\\registry` paths and
    no `cargo/registry` path, as carrying no crates.
    """
    path = sep.join(("/root/.cargo", "registry", "src", "index.crates.io-1", "ring-0.17.8", ""))
    wheel = build_wheel(
        tmp_path / f"winrust-1.0-{WINDOWS}.whl",
        name="winrust",
        version="1.0",
        tags=(WINDOWS,),
        files={
            "winrust/_rust.pyd": ElfBuilder(
                needed=("libc.so.6",), rodata=b"\x00" + path.encode() + b"src/lib.rs\x00"
            ).build()
        },
    )
    record = scan(context, wheel)
    crates = [crate["name"] for binary in record["binaries"] for crate in binary["rust_crates"]]
    assert crates == ["ring"]


@pytest.mark.parametrize(
    ("rodata", "expected_version"),
    [
        pytest.param(
            b"\x00/usr/share/cargo/registry/openssl-sys-0.9.117/src/lib.rs\x00",
            "0.9.117",
            id="distro-registry-layout",
        ),
        pytest.param(
            b"\x00/build/pkg/vendor/openssl-sys/src/lib.rs\x00",
            None,
            id="cargo-vendor-layout",
        ),
    ],
)
def test_a_crate_from_every_recognised_cargo_layout_produces_a_finding(
    context, tmp_path: Path, rodata: bytes, expected_version: str | None
) -> None:
    """Distro packaging (Fedora's RPM Rust macros) and `cargo vendor` without
    `--versioned-dirs` -- what fromager configures -- both embed a cargo source path
    with no `cargo/registry/src/<index>/` segment. Both must yield the crate and its
    finding."""
    wheel = build_wheel(
        tmp_path / f"cargolayout-1.0-{MANYLINUX}.whl",
        name="cargolayout",
        version="1.0",
        tags=(MANYLINUX,),
        files={
            "cargolayout/_rust.abi3.so": ElfBuilder(needed=("libc.so.6",), rodata=rodata).build()
        },
    )
    record = scan(context, wheel)
    crates = [crate for binary in record["binaries"] for crate in binary["rust_crates"]]
    assert crates == [{"name": "openssl-sys", "version": expected_version}]
    assert any(f["rule_id"] == "BIN_RUST_CRYPTO_CRATE" for f in record["findings"])


def test_a_vendored_aws_lc_fips_sys_path_with_no_version_reads_conditional(
    context, tmp_path: Path
) -> None:
    """A fromager-style `cargo vendor` build carries no version in its crate paths.
    The FIPS build of AWS-LC must still be recognised and routed to its own verdict
    even though the version the layout would normally carry is missing."""
    wheel = build_wheel(
        tmp_path / f"awslcfips-1.0-{MANYLINUX}.whl",
        name="awslcfips",
        version="1.0",
        tags=(MANYLINUX,),
        files={
            "awslcfips/_rust.abi3.so": ElfBuilder(
                needed=("libc.so.6",),
                rodata=b"\x00/build/pkg/vendor/aws-lc-fips-sys/src/lib.rs\x00",
            ).build()
        },
    )
    record = scan(context, wheel)
    crates = [crate for binary in record["binaries"] for crate in binary["rust_crates"]]
    assert crates == [{"name": "aws-lc-fips-sys", "version": None}]
    finding = next(
        f
        for f in record["findings"]
        if f["rule_id"] == "BIN_AWS_LC_FIPS" and f["subject"] == "aws-lc-fips-sys"
    )
    assert finding["verdict"] == "CONDITIONAL"


# --------------------------------------------------------------------------
# A Go binary built against the FIPS module is a condition, not a
# non-approved primitive
# --------------------------------------------------------------------------


def _go_buildinfo(version: str, settings: str) -> bytes:
    """A Go 1.18+ buildinfo section: header, inline version, then modinfo.

    The modinfo string is where `go version -m` reads its `build KEY=VALUE` lines
    from, and it is what a FIPS build differs from a stock one by. Shaped after a real
    go1.27.1 section rather than invented: 32-byte header with the inline-strings flag,
    a uvarint-prefixed version, then a uvarint-prefixed blob the toolchain wraps in
    16-byte sentinels.
    """

    def uvarint(value: int) -> bytes:
        out = bytearray()
        while True:
            byte = value & 0x7F
            value >>= 7
            out.append(byte | 0x80 if value else byte)
            if not value:
                return bytes(out)

    header = b"\xff Go buildinf:" + bytes([8, 0x2]) + b"\x00" * 16
    modinfo = b"\xf9\xff\xff\xff\xff\xff\xff\xff" * 2 + settings.encode() + b"\xf9" * 16
    return header + uvarint(len(version)) + version.encode() + uvarint(len(modinfo)) + modinfo


# A real go1.24+ stock binary carries the fips140 package paths too -- 381 of them,
# measured -- because the standard library implements its crypto on top of them. The
# fixture carries one for the same reason: without it, widening `go_fips140` to a
# bare "fips140" flips every Go wheel in an index to CONDITIONAL and no test moves.
_GO_STOCK_RODATA = (
    b"\x00crypto/sha256.block\x00crypto/aes.NewCipher"
    b"\x00crypto/internal/fips140/sha256.blockGeneric\x00"
)
_GO_FIPS_SETTINGS = (
    "build\t-tags=fips140v1.0\nbuild\tDefaultGODEBUG=fips140=on\nbuild\tGOFIPS140=v1.0.0-c2097c7c\n"
)


def _go_wheel(tmp_path: Path, name: str, buildinfo: bytes) -> Path:
    return build_wheel(
        tmp_path / f"{name}-1.0-{MANYLINUX}.whl",
        name=name,
        version="1.0",
        tags=(MANYLINUX,),
        files={
            f"{name}/_ext.abi3.so": ElfBuilder(
                needed=("libc.so.6",), rodata=_GO_STOCK_RODATA, go_buildinfo=buildinfo
            ).build()
        },
    )


@pytest.mark.parametrize(
    ("label", "settings"),
    [
        # go1.27.1 with GOFIPS140=v1.0.0 records both of these, but they are
        # independent signals and each is pinned on its own: a build can name the
        # module version while a //go:debug directive turns enforcement off, and a
        # build can enforce the in-tree module without GOFIPS140 naming a version.
        ("both", _GO_FIPS_SETTINGS),
        ("module version only", "build\tGOFIPS140=v1.0.0-c2097c7c\n"),
        ("godebug default only", "build\tDefaultGODEBUG=fips140=on\n"),
        # DefaultGODEBUG is a comma-joined list and fips140 need not be first, which
        # is why the substring is matched without its key. Tightening it to
        # "DefaultGODEBUG=fips140=on" passes every case above and silently stops
        # matching this one.
        (
            "godebug among others",
            "build\tDefaultGODEBUG=asynctimerchan=1,fips140=on,httplaxcontentlength=1\n",
        ),
    ],
)
def test_a_go_fips140_build_is_a_condition_not_a_non_approved_primitive(
    context, tmp_path: Path, label: str, settings: str
) -> None:
    """Since Go 1.24 the standard library runs its crypto through the fips140
    packages, so a GOFIPS140 build carries the stock package paths exactly as a stock
    build does: measured on go1.27.1, `crypto/sha256.` appears 9 times in both. Keying
    on the paths alone would report a binary whose crypto goes through the validated
    module as NON_APPROVED_CRYPTO, with nothing to suppress it.
    """
    wheel = _go_wheel(tmp_path, "gofips", _go_buildinfo("go1.27.1", settings))
    record = scan(context, wheel)
    assert record["verdict"]["class"] == "CONDITIONAL"
    assert "BIN_GO_FIPS140" in record["verdict"]["rule_ids"]
    assert "BIN_GO_STOCK_CRYPTO" not in record["verdict"]["rule_ids"]


def test_the_go_block_and_the_verdict_never_disagree(context, tmp_path: Path) -> None:
    """`binaries[].go.markers` is the structured summary a consumer reads instead of
    the findings, and it is built in the reader from the group names `[conventions]`
    lists. A rule on a Go group the reader does not list makes the same record say two
    things: `markers: ["go_stock_crypto"]` beside a verdict of BIN_GO_FIPS140, from the
    identical strings. The same shape as "partial_analysis and partial_reasons never
    disagree", held here by a test of its own.
    """
    wheel = _go_wheel(tmp_path, "gofips", _go_buildinfo("go1.27.1", _GO_FIPS_SETTINGS))
    record = scan(context, wheel)
    markers = record["binaries"][0]["go"]["markers"]
    assert "go_fips140" in markers
    assert record["verdict"]["class"] == "CONDITIONAL"
    # Every Go group the ruleset names is a marker the reader knows: a group a rule
    # can fire on but the reader cannot report makes the two disagree.
    ruleset = load_ruleset()
    named = {
        ruleset.conventions.go_boring_group,
        ruleset.conventions.go_stock_group,
        ruleset.conventions.go_fips140_group,
    }
    go_groups = {name for name in ruleset.string_groups if name.startswith("go_")}
    assert go_groups == named


def test_a_stock_go_build_is_non_approved(context, tmp_path: Path) -> None:
    """The other half of the pair: suppression must not reach a build that never
    named the module."""
    settings = "build\t-buildmode=exe\nbuild\tGOARCH=amd64\n"
    wheel = _go_wheel(tmp_path, "gostock", _go_buildinfo("go1.27.1", settings))
    record = scan(context, wheel)
    assert record["verdict"]["class"] == "NON_APPROVED_CRYPTO"
    assert "BIN_GO_STOCK_CRYPTO" in record["verdict"]["rule_ids"]
    assert "BIN_GO_FIPS140" not in record["verdict"]["rule_ids"]


# --------------------------------------------------------------------------
# An AWS-LC FIPS build is a condition, not a non-approved stack
# --------------------------------------------------------------------------

_LOCAL_FUNC = (STB_LOCAL << 4) | STT_FUNC

# The measured shapes: a FIPS object carries the aws-lc-rs cargo path (both builds do),
# the FIPS symbol prefix as a local .symtab definition, and the version string plus the
# "failure caused by" message in .text, exactly where the real build puts them (measured
# offset 0xd0888 in .text on aws-lc-fips-sys 0.14.2). The real stock build drops the
# message entirely -- gc-sections removes it, since nothing in the non-FIPS build path
# references it. The stock fixture below puts the message in .rodata anyway, on purpose:
# it is not what a real stock build carries, but it is the worst case the ELF strings
# pass can read -- a stock build is not delocated, so .rodata is where the message would
# land if a future stock build kept it. Without a version digit after `FIPS `, that
# placement would make a bare `AWS-LC FIPS` substring false-positive on a stock object
# read end to end through this fixture, not only in the direct group test in
# `test_binfmt_strings.py`.
_AWS_LC_RODATA = (
    b"\x00/aws-lc/crypto/mem.c\x00"
    b"/root/.cargo/registry/src/index.crates.io-x/aws-lc-rs-1.18.1/src/lib.rs\x00"
)
_AWS_LC_FIPS_TEXT = b"\x00AWS-LC FIPS 4.2.0\x00AWS-LC FIPS failure caused by:\n\x00"
_AWS_LC_STOCK_RODATA = _AWS_LC_RODATA + b"AWS-LC FIPS failure caused by:\n\x00"


def _aws_lc_binary(*, symtab_name: str, rodata: bytes, text: bytes = b"") -> bytes:
    return ElfBuilder(
        needed=("libc.so.6",),
        dynsyms=(DynSym("PyInit__ext", defined=True),),
        with_symtab=True,
        symtab_syms=(DynSym(symtab_name, defined=True, info=_LOCAL_FUNC),),
        rodata=rodata,
        text=text,
    ).build()


def test_the_aws_lc_fips_sys_crate_alone_reads_as_a_condition(context, tmp_path: Path) -> None:
    """An object whose only evidence is the aws-lc-fips-sys cargo path."""
    wheel = build_wheel(
        tmp_path / f"awslcrepro-1.0-{MANYLINUX}.whl",
        name="awslcrepro",
        version="1.0",
        tags=(MANYLINUX,),
        files={
            "awslcrepro/_ext.abi3.so": ElfBuilder(
                needed=("libc.so.6",),
                rodata=(
                    b"\x00/root/.cargo/registry/src/index.crates.io-1/"
                    b"aws-lc-fips-sys-0.13.7/src/lib.rs\x00"
                ),
            ).build(),
        },
    )
    record = scan_wheel(wheel, context)
    assert record["verdict"]["class"] == "CONDITIONAL"
    assert "BIN_AWS_LC_FIPS" in record["verdict"]["rule_ids"]
    assert "BIN_AWS_LC" not in record["verdict"]["rule_ids"]


def test_an_aws_lc_fips_build_is_told_apart_by_its_symbol_prefix(context, tmp_path: Path) -> None:
    """The measured FIPS object. Its version string sits in `.text`, which the ELF
    strings pass does not read, so this test relies on the symbol prefix alone, not on
    the version string.
    """
    wheel = build_wheel(
        tmp_path / f"awslcfips-1.0-{MANYLINUX}.whl",
        name="awslcfips",
        version="1.0",
        tags=(MANYLINUX,),
        files={
            "awslcfips/_ext.abi3.so": _aws_lc_binary(
                symtab_name="aws_lc_fips_0_14_2_SHA256_Init",
                rodata=_AWS_LC_RODATA,
                text=_AWS_LC_FIPS_TEXT,
            ),
        },
    )
    record = scan_wheel(wheel, context)
    assert record["verdict"]["class"] == "CONDITIONAL"
    assert "BIN_AWS_LC_FIPS" in record["verdict"]["rule_ids"]
    assert "BIN_AWS_LC" not in record["verdict"]["rule_ids"]
    assert "BIN_AWS_LC_RS_CRATE" not in record["verdict"]["rule_ids"]


def test_a_stock_aws_lc_build_is_non_approved(context, tmp_path: Path) -> None:
    """The other half of the pair: the stock object carries the same aws-lc-rs cargo
    path, but never the FIPS symbol prefix.

    A real stock build drops the "failure caused by" message entirely. This fixture puts
    it in `.rodata` on purpose anyway -- the worst case the ELF strings pass can read, and
    the one place a stock build could plausibly still carry it -- so that widening the
    string group to a bare "AWS-LC FIPS" (dropping the digit) breaks this test directly:
    `.rodata` is part of the strings pass, unlike `.text`. `test_aws_lc_fips_group_needs_
    a_version_after_fips` in `test_binfmt_strings.py` pins the same mutation at the group
    level.
    """
    wheel = build_wheel(
        tmp_path / f"awslcstock-1.0-{MANYLINUX}.whl",
        name="awslcstock",
        version="1.0",
        tags=(MANYLINUX,),
        files={
            "awslcstock/_ext.abi3.so": _aws_lc_binary(
                symtab_name="aws_lc_0_45_0_SHA256_Init",
                rodata=_AWS_LC_STOCK_RODATA,
            ),
        },
    )
    record = scan_wheel(wheel, context)
    assert record["verdict"]["class"] == "NON_APPROVED_CRYPTO"
    assert "BIN_AWS_LC" in record["verdict"]["rule_ids"]
    assert "BIN_AWS_LC_RS_CRATE" in record["verdict"]["rule_ids"]
    assert "BIN_AWS_LC_FIPS" not in record["verdict"]["rule_ids"]


def test_a_stock_aws_lc_sys_crate_beside_the_fips_one_is_still_reported(
    context, tmp_path: Path
) -> None:
    """A wheel carrying both crates' cargo paths on the same object still reports the
    stock one: aws-lc-sys names the non-FIPS variant and is never suppressed.
    """
    rodata = (
        b"\x00/root/.cargo/registry/src/index.crates.io-1/aws-lc-fips-sys-0.14.2/src/lib.rs\x00"
        b"/root/.cargo/registry/src/index.crates.io-1/aws-lc-sys-0.45.0/src/lib.rs\x00"
    )
    wheel = build_wheel(
        tmp_path / f"awslcboth-1.0-{MANYLINUX}.whl",
        name="awslcboth",
        version="1.0",
        tags=(MANYLINUX,),
        files={
            "awslcboth/_ext.abi3.so": ElfBuilder(needed=("libc.so.6",), rodata=rodata).build(),
        },
    )
    record = scan_wheel(wheel, context)
    assert "NON_APPROVED_CRYPTO" in record["verdict"]["classes"]
    assert "BIN_AWS_LC_FIPS" in record["verdict"]["rule_ids"]
    crate_finding = next(
        finding for finding in record["findings"] if finding["rule_id"] == "BIN_RUST_CRYPTO_CRATE"
    )
    assert crate_finding["subject"] == "aws-lc-sys"


def test_a_fips_object_does_not_suppress_a_stock_aws_lc_object_elsewhere_in_the_wheel(
    context, tmp_path: Path
) -> None:
    """Suppression is per object, not per wheel: a wheel with one FIPS object and one
    separate stock AWS-LC object keeps `BIN_AWS_LC` and `BIN_AWS_LC_RS_CRATE` for the
    stock object, since a suppressing hit only drops a finding on the same object
    (`Location.path`). `NON_APPROVED_CRYPTO` stays in `classes` alongside `CONDITIONAL`
    rather than leaving it entirely.
    """
    wheel = build_wheel(
        tmp_path / f"awslctwo-1.0-{MANYLINUX}.whl",
        name="awslctwo",
        version="1.0",
        tags=(MANYLINUX,),
        files={
            "two/_fips.abi3.so": ElfBuilder(
                needed=("libc.so.6",),
                rodata=(
                    b"\x00/root/.cargo/registry/src/index.crates.io-1/"
                    b"aws-lc-fips-sys-0.13.7/src/lib.rs\x00"
                ),
            ).build(),
            "two/_stock.abi3.so": _aws_lc_binary(
                symtab_name="aws_lc_0_45_0_SHA256_Init",
                rodata=_AWS_LC_RODATA,
            ),
        },
    )
    record = scan_wheel(wheel, context)
    assert set(record["verdict"]["classes"]) == {"CONDITIONAL", "NON_APPROVED_CRYPTO"}
    rule_ids = record["verdict"]["rule_ids"]
    assert "BIN_AWS_LC_FIPS" in rule_ids
    assert "BIN_AWS_LC" in rule_ids
    assert "BIN_AWS_LC_RS_CRATE" in rule_ids
