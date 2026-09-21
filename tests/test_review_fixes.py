"""Regressions found by adversarial review. Each names the failure it prevents."""

from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path

import pytest
from helpers.binfmt import DynSym, ElfBuilder
from helpers.wheelbuilder import build_wheel

from wheel_crypto_scan.cli import main
from wheel_crypto_scan.errors import ERROR_KINDS
from wheel_crypto_scan.ruleset_loader import load_ruleset
from wheel_crypto_scan.scan import ScanContext, scan_wheel

MANYLINUX = "cp39-abi3-manylinux_2_28_x86_64"
WINDOWS = "cp39-abi3-win_amd64"


@pytest.fixture(scope="module")
def context() -> ScanContext:
    return ScanContext.build(load_ruleset())


# --- a linked crypto library must never read as "nothing found" -------------


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
    record = scan_wheel(wheel, context)
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
    record = scan_wheel(wheel, context)
    assert record["verdict"]["class"] == "CONDITIONAL"
    assert record["verdict"]["conditions"]["libgcrypt_linkage"] == "bundled"


def test_every_crypto_library_with_a_verdict_is_reachable_by_a_linkage_rule() -> None:
    """Structural guard: a library nobody can match is a silent hole in the taxonomy."""
    ruleset = load_ruleset()
    covered: set[str] = set()
    for _, match in ruleset.matches_for_kind("linkage"):
        if "name" in match:
            covered.add(str(match["name"]))
        elif match.get("table") == "crypto_library":
            excluded = set(match.get("exclude_libraries", ()))
            covered.update(set(ruleset.libraries) - excluded)
    needs_cover = {name for name, lib in ruleset.libraries.items() if lib.verdict}
    assert needs_cover - covered == set()


# --- Windows wheels ----------------------------------------------------------


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
    record = scan_wheel(wheel, context)
    assert record["verdict"]["conditions"]["openssl_linkage"] == "bundled"
    assert "BIN_BUNDLED_OPENSSL" in record["verdict"]["rule_ids"]


@pytest.mark.parametrize(
    ("name", "base", "mangled"),
    [
        ("libcrypto.dll", "libcrypto", False),
        ("libcrypto-3a1f2b4c.dll", "libcrypto", True),
        ("libssl-1_1-x64.dll", "libssl", False),
        ("_ext.pyd", "_ext", False),
    ],
)
def test_windows_library_names_normalise(name: str, base: str, mangled: bool) -> None:
    info = load_ruleset().conventions.normalise_soname(name)
    assert (info.base, info.mangled) == (base, mangled)


# --- resume must not reorder the output --------------------------------------


def test_resume_produces_the_same_bytes_as_a_full_scan(tmp_path: Path) -> None:
    """Parallelism is careful not to reorder output; resume must be too."""
    corpus = tmp_path / "wheels"
    corpus.mkdir()
    for name in ("alpha", "bravo", "charlie", "delta"):
        build_wheel(
            corpus / f"{name}-1.0-py3-none-any.whl",
            name=name,
            version="1.0",
            files={f"{name}/__init__.py": b"import hashlib\nh = hashlib.md5()\n"},
        )
    full = tmp_path / "full.jsonl"
    main(["scan", str(corpus), "-o", str(full), "--no-cache", "-q"])
    expected = full.read_bytes()

    partial = tmp_path / "partial.jsonl"
    lines = expected.decode().splitlines(keepends=True)
    partial.write_text("".join(lines[2:]), encoding="utf-8")
    main(["scan", str(corpus), "-o", str(partial), "--no-cache", "--resume", "-q"])
    assert partial.read_bytes() == expected


# --- contract fields ---------------------------------------------------------


def test_the_record_says_which_evidence_level_produced_it(context, tmp_path: Path) -> None:
    """Empty matched_symbols means "none found" at standard and "not recorded" at minimal."""
    wheel = build_wheel(
        tmp_path / "demo-1.0-py3-none-any.whl", name="demo", version="1.0", files={}
    )
    standard = scan_wheel(wheel, context)
    assert standard["tool"]["evidence_level"] == "standard"
    minimal_context = ScanContext.build(load_ruleset(), evidence_level="minimal")
    assert scan_wheel(wheel, minimal_context)["tool"]["evidence_level"] == "minimal"


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
    record = scan_wheel(wheel, context)
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
    record = scan_wheel(wheel, context)
    finding = next(f for f in record["findings"] if f["rule_id"] == "PY_WEAK_HASH_CALL")
    assert finding["subject"] is None
    assert finding["subject_kind"] is None


# --- usedforsecurity: an explicit flag must never read as clean (#58) --------
#
# The AST extractor already recorded "true", "false", "unresolved" and "absent"
# correctly; the gap was entirely in the ruleset's match tables. An explicit
# usedforsecurity=True fired nothing at all, and a non-constant usedforsecurity on a
# weak hash fired nothing despite PY_WEAK_HASH_UNRESOLVED's own `why` claiming it did.


def _hashlib_wheel(tmp_path: Path, name: str, source: bytes):
    return build_wheel(
        tmp_path / f"{name}-1.0-py3-none-any.whl",
        name=name,
        version="1.0",
        files={f"{name}/__init__.py": source},
    )


def test_a_bare_weak_hash_call_is_unchanged(context, tmp_path: Path) -> None:
    """No usedforsecurity keyword at all: the ordinary, already-working case."""
    wheel = _hashlib_wheel(tmp_path, "bare", b"import hashlib\nhashlib.md5(b'x')\n")
    record = scan_wheel(wheel, context)
    assert record["verdict"]["class"] == "FIPS_BREAKING"
    assert "PY_WEAK_HASH_CALL" in record["verdict"]["rule_ids"]


def test_an_explicit_usedforsecurity_true_is_fips_breaking(context, tmp_path: Path) -> None:
    """The code declares itself security use; that is at least as confident a signal
    as no keyword at all, and used to fire nothing."""
    wheel = _hashlib_wheel(
        tmp_path, "explicittrue", b"import hashlib\nhashlib.md5(b'x', usedforsecurity=True)\n"
    )
    record = scan_wheel(wheel, context)
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
    record = scan_wheel(wheel, context)
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
    record = scan_wheel(wheel, context)
    assert record["verdict"]["class"] == "CONTEXT_DEPENDENT"
    assert "PY_WEAK_HASH_UNRESOLVED" in record["verdict"]["rule_ids"]
    assert "PY_WEAK_HASH_CALL" not in record["verdict"]["rule_ids"]


def test_a_variable_algorithm_name_is_unchanged(context, tmp_path: Path) -> None:
    """hashlib.new(name): already worked before this fix, must still work after."""
    wheel = _hashlib_wheel(
        tmp_path, "varalgo", b"import hashlib\nname = 'md5'\nhashlib.new(name)\n"
    )
    record = scan_wheel(wheel, context)
    assert record["verdict"]["class"] == "CONTEXT_DEPENDENT"
    assert "PY_WEAK_HASH_UNRESOLVED" in record["verdict"]["rule_ids"]


def test_an_explicit_usedforsecurity_false_is_unchanged(context, tmp_path: Path) -> None:
    """Regression check: this fix is additive and must not touch the marked case."""
    wheel = _hashlib_wheel(
        tmp_path, "explicitfalse", b"import hashlib\nhashlib.md5(b'x', usedforsecurity=False)\n"
    )
    record = scan_wheel(wheel, context)
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
    record = scan_wheel(wheel, context)
    assert record["verdict"]["class"] == "NO_CRYPTO_DETECTED"
    assert not {"PY_WEAK_HASH_CALL", "PY_WEAK_HASH_CALL_MARKED", "PY_WEAK_HASH_UNRESOLVED"} & set(
        record["verdict"]["rule_ids"]
    )


# --- the error vocabulary must be live ---------------------------------------


def test_every_error_kind_is_actually_emitted_somewhere() -> None:
    """A kind nothing constructs makes any rule matching it silently dead."""
    source = "\n".join(
        path.read_text(encoding="utf-8") for path in Path("src/wheel_crypto_scan").rglob("*.py")
    )
    constant_names = {kind: kind.upper() for kind in ERROR_KINDS}
    dead = {
        kind
        for kind, constant in constant_names.items()
        if source.count(constant) < 2  # the definition, plus at least one use
    }
    assert dead == set()


def test_the_schema_does_not_close_the_verdict_class_list() -> None:
    """A closed enum turns adding a verdict class into a silent schema break."""
    schema = json.loads(
        files("wheel_crypto_scan").joinpath("data/schema.json").read_text(encoding="utf-8")
    )
    assert "enum" not in schema["$defs"]["verdictClass"]
    for name in load_ruleset().precedence:
        assert name in schema["$defs"]["verdictClass"]["description"]


def test_the_schema_still_forbids_a_passing_class() -> None:
    text = files("wheel_crypto_scan").joinpath("data/schema.json").read_text(encoding="utf-8")
    assert "COMPLIANT" not in json.loads(text)["$defs"]["verdictClass"]["description"].upper()
    assert "COMPATIBLE" not in json.loads(text)["$defs"]["verdictClass"]["description"].upper()


# --- a banner for a major nobody listed reads as no OpenSSL at all -----------


def test_a_statically_linked_openssl_4_is_not_reported_as_clean(context, tmp_path: Path) -> None:
    """An object whose only OpenSSL evidence is its banner must read `static`.

    Found against cryptography 50.0.1 on PyPI, whose `_rust.abi3.so` compiles OpenSSL
    4.0.2 in, declares no dependency on libcrypto, and exports no OpenSSL symbol. The
    banner is the whole of the evidence, and `openssl_banner` stopped at major 3, so
    the wheel the tool exists to catch came out with `openssl_linkage: none`. The
    group now names every major digit; `tests/test_ruleset.py` pins that directly.
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
    record = scan_wheel(wheel, context)
    assert record["verdict"]["conditions"]["openssl_linkage"] == "static"
    assert record["verdict"]["class"] != "NO_CRYPTO_DETECTED"
