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
from helpers.elfbuilder import DynSym, ElfBuilder
from helpers.wheelbuilder import build_wheel

from wheel_crypto_scan.ruleset import load_ruleset
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
