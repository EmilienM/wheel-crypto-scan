"""Regressions found by adversarial review. Each names the failure it prevents."""

from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path

import pytest
from helpers.binfmt import DynSym, ElfBuilder
from helpers.binfmt.elf import STT_FUNC
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
        # A vendor spelling nobody enumerated: with the arch written as an alternation
        # of four tokens this resolved to no library at all (#123).
        ("libcrypto-3-aarch64.dll", "libcrypto", False),
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


# --- a vendored-OpenSSL Rust build names itself, and must be read ------------


def test_a_vendored_openssl_crate_path_is_not_reported_as_clean(context, tmp_path: Path) -> None:
    """`openssl-src` is what `openssl-sys`'s vendored feature builds OpenSSL with.

    An extension that went that way carries no libcrypto dependency and no vendor
    directory, and a stripped build may not carry the banner either, so the crate path
    can be all that is left. It names the crate, not the posture: `openssl-sys` links
    the host's OpenSSL under `OPENSSL_NO_VENDOR` even with the feature on, so the
    object reads `unknown` rather than `static`. It was missing from [[rust_crate]]
    (#123), found while fixing the banner list.
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
    record = scan_wheel(wheel, context)
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

    `cargo_path_regex` spelled only the forward slash, so every Rust wheel built on
    Windows read as carrying no crates at all: cryptography 50.0.1's win_amd64 `.pyd`
    holds 153 `cargo\\registry` paths and not one `cargo/registry` path, and its
    record listed no crates. The whole [[rust_crate]] table was dead on that platform,
    which is more evidence than any single entry in it is worth (#123).
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
    record = scan_wheel(wheel, context)
    crates = [crate["name"] for binary in record["binaries"] for crate in binary["rust_crates"]]
    assert crates == ["ring"]


# --- a Go binary built against the FIPS module is not "stock Go crypto" ------


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
    on the paths alone reported a binary whose crypto goes through the validated
    module as NON_APPROVED_CRYPTO, with nothing to suppress it (#126).
    """
    wheel = _go_wheel(tmp_path, "gofips", _go_buildinfo("go1.27.1", settings))
    record = scan_wheel(wheel, context)
    assert record["verdict"]["class"] == "CONDITIONAL"
    assert "BIN_GO_FIPS140" in record["verdict"]["rule_ids"]
    assert "BIN_GO_STOCK_CRYPTO" not in record["verdict"]["rule_ids"]


def test_the_go_block_and_the_verdict_never_disagree(context, tmp_path: Path) -> None:
    """`binaries[].go.markers` is the structured summary a consumer reads instead of
    the findings, and it is built in the reader from the group names `[conventions]`
    lists. Adding a rule on a Go group without adding it there made the same record
    say two things: `markers: ["go_stock_crypto"]` beside a verdict of BIN_GO_FIPS140,
    from the identical strings. The same shape as "partial_analysis and
    partial_reasons never disagree", in a place nothing was checking.
    """
    wheel = _go_wheel(tmp_path, "gofips", _go_buildinfo("go1.27.1", _GO_FIPS_SETTINGS))
    record = scan_wheel(wheel, context)
    markers = record["binaries"][0]["go"]["markers"]
    assert "go_fips140" in markers
    assert record["verdict"]["class"] == "CONDITIONAL"
    # Every Go group the ruleset names is a marker the reader knows: a group a rule
    # can fire on but the reader cannot report is how the two came to disagree.
    ruleset = load_ruleset()
    named = {
        ruleset.conventions.go_boring_group,
        ruleset.conventions.go_stock_group,
        ruleset.conventions.go_fips140_group,
    }
    go_groups = {name for name in ruleset.string_groups if name.startswith("go_")}
    assert go_groups == named


def test_a_stock_go_build_is_unchanged(context, tmp_path: Path) -> None:
    """The other half of the pair: suppression must not reach a build that never
    named the module, or the fix would have bought a false clean."""
    settings = "build\t-buildmode=exe\nbuild\tGOARCH=amd64\n"
    wheel = _go_wheel(tmp_path, "gostock", _go_buildinfo("go1.27.1", settings))
    record = scan_wheel(wheel, context)
    assert record["verdict"]["class"] == "NON_APPROVED_CRYPTO"
    assert "BIN_GO_STOCK_CRYPTO" in record["verdict"]["rule_ids"]
    assert "BIN_GO_FIPS140" not in record["verdict"]["rule_ids"]


# --- an AWS-LC FIPS build is a condition, not a non-approved stack ---------------
#
# `STB_LOCAL` is not exported by `helpers.binfmt.elf`: local bindings are rare enough
# in that module's own tests that it only exports `STB_GLOBAL`.
_STB_LOCAL = 0
_LOCAL_FUNC = (_STB_LOCAL << 4) | STT_FUNC

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


def test_a_stock_aws_lc_build_is_unchanged(context, tmp_path: Path) -> None:
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
