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
    DynSym,
    ElfBuilder,
    MachOBuilder,
    MachOSym,
    PEBuilder,
    PEExport,
    PEImport,
    build_fat,
)
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


# --------------------------------------------------------------------------
# delocate: bundled without a rename (#57)
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
    """Before #57: `mixed`, plus `BIN_OPENSSL_LINKAGE_UNKNOWN` and
    `BIN_NEEDED_SYSTEM_OPENSSL` both fired -- an unmangled `needed` entry read as
    the system library even though the wheel plainly ships its own copy right next
    to it.
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
# Adversarial review of #57, two BLOCKING findings
# --------------------------------------------------------------------------


@pytest.fixture
def self_colliding_wheel(tmp_path: Path) -> Path:
    """BLOCKING 1, sharpest repro: one object, no vendor directory, no second file.

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
def basename_collision_wheel(tmp_path: Path) -> Path:
    """BLOCKING 1, the residual that stays possible after fixing the sharpest repro:
    two genuinely different objects that happen to share a basename. The `bundled`
    reading may still be an imprecise false positive from the coincidence -- that is
    the accepted residual `DECISIONS.md` documents -- but it must carry a finding.
    """
    return build_wheel(
        subdir(tmp_path, "basename-collision") / f"fakecrypto-1.0-{MANYLINUX}.whl",
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


def test_a_self_referencing_dependency_is_not_manufactured_bundled(context, self_colliding_wheel):
    """Before this fix: `openssl_linkage: bundled`, `verdict.class:
    NO_CRYPTO_DETECTED`, `rule_ids: []`, `needs_human_review: false` -- a wheel that
    plainly, only links the system OpenSSL, read as if nothing had been found at all.
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
    """BLOCKING 2: a FIPS-conscious build that genuinely links the system OpenSSL
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
    """Before this fix: `openssl_linkage: unknown`, `verdict.class: OPAQUE`,
    `BIN_OPENSSL_LINKAGE_UNKNOWN` -- a vendor-shaped `RPATH`/`RUNPATH` alone was
    enough to downgrade a plain, genuine system dependency, even though nothing the
    wheel ships could possibly be what it names.
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

    `needed` is tested before the symbol count, so a dylib that links `libSystem` was
    never opaque. This is the shape that was: no dependency to fall back on, and a
    symbol count in the field `is_opaque` did not look at. It reported having told us
    nothing while carrying the symbols it told us.
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
    """The reproduction from #88, through the real Mach-O reader and the whole scan
    pipeline, not just a hand-built `BinaryEvidence`: one slice's `LC_LOAD_DYLIB`
    names a hash-renamed vendored copy (`bundled`), the other slice's names the
    host library outright (`system`). `binfmt.macho` merges both slices' `needed`
    into the union on one `BinaryEvidence`
    (`test_load_dylibs_merge_across_slices` in `test_binfmt_macho.py` pins that
    merge itself), so this object carries both signals at once, the same as if the
    two slices had been read as separate objects and combined by `_aggregate`.

    Before #88, `linkage._binary_posture`'s `needed` loop returned `LINKAGE_BUNDLED`
    on the first entry that resolved that way, before the second, disagreeing entry
    was ever looked at, so this read `bundled` instead of `mixed`.
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
    """The whole chain for #40, which every other test for it drives from the middle.

    Reader to `partial_reasons` to the linkage policy to the rule to the record. The
    unit tests hand `resolve_linkage` a `BinaryEvidence` built by hand, so a reader
    that stopped emitting `macho_symtab_incomplete` would leave all of them green and
    put `openssl_linkage: none` back on every stripped macOS wheel.

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
    """The PE half of the same bug: its named entries land in `symtab_count` too.

    A resource-only or statically linked DLL imports nothing, so `needed` could not
    rescue it either, and the export it does declare was invisible to `is_opaque`.
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
# .exe members are sniffed too (#65)
#
# `is_binary_member` accepted a member by suffix, by vendor path, by living in a
# sniff directory with no dot in its name, or by the executable bit with no dot in
# its name. `.exe` failed every route: the wrong suffix, and the dot disqualified it
# from both "no dot" fallbacks. The same PE, shipped as `bin/openssl` on manylinux and
# `openssl.exe` on win_amd64, used to be read on one platform and not the other.
# --------------------------------------------------------------------------

WIN_TAG = "cp312-cp312-win_amd64"


def _openssl_pe() -> bytes:
    """The issue's own reproduction: imports `KERNEL32.dll`, exports
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
    """The direct pin of the issue's own reproduction pair: same bytes, same verdict,
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


def test_a_pyd_member_is_unaffected_by_the_exe_fix(context, tmp_path: Path) -> None:
    """Regression guard: the pre-existing PE routes (`.pyd`/`.dll`) are untouched."""
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
