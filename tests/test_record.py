"""The output contract: record shape, canonical serialisation and determinism."""

from __future__ import annotations

import json

import pytest

from wheel_crypto_scan import SCHEMA_VERSION
from wheel_crypto_scan.engine import apply_rules
from wheel_crypto_scan.evidence import (
    BINDING_DEFINED,
    FORMAT_ELF,
    ArtifactInventory,
    BinaryEvidence,
    Evidence,
    MetadataEvidence,
    RustCrate,
    StringMatch,
    SymbolMatch,
)
from wheel_crypto_scan.linkage import resolve_linkage
from wheel_crypto_scan.record import build_record, to_json_line
from wheel_crypto_scan.ruleset_loader import load_ruleset
from wheel_crypto_scan.verdict import classify


@pytest.fixture(scope="module")
def ruleset():
    return load_ruleset()


def bundled_cryptography() -> Evidence:
    return Evidence(
        filename="cryptography-42.0.5-cp39-abi3-manylinux_2_28_x86_64.whl",
        sha256="a" * 64,
        size_bytes=4194304,
        artifacts=ArtifactInventory(
            py_files=142,
            extensions=(("cryptography/hazmat/bindings/_rust.abi3.so", FORMAT_ELF),),
            bundled_libs=("cryptography.libs/libcrypto-3a1f2b4c.so.3",),
            total_uncompressed_bytes=12345678,
            record_entries=312,
        ),
        metadata=MetadataEvidence(
            name="cryptography",
            canonical_name="cryptography",
            version="42.0.5",
            tags=("cp39-abi3-manylinux_2_28_x86_64",),
            platform_tags=("manylinux_2_28_x86_64",),
            generator_raw="maturin (1.7.0)",
            generator_name="maturin",
            generator_version="1.7.0",
            requires_python=">=3.7",
            requires_dist=("cffi>=1.12",),
            dist_info_dir="cryptography-42.0.5.dist-info",
            record_entries=312,
        ),
        binaries=(
            BinaryEvidence(
                path="cryptography.libs/libcrypto-3a1f2b4c.so.3",
                format=FORMAT_ELF,
                vendored_path=True,
                soname="libcrypto-3a1f2b4c.so.3",
                machine="EM_X86_64",
                bits=64,
                endian="little",
                elf_type="ET_DYN",
                needed=("libc.so.6",),
                dynsym_count=4821,
                matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_DEFINED),),
                matched_strings=(StringMatch("openssl_banner", "OpenSSL 3.0.14 4 Jun 2024"),),
                rust_crates=(RustCrate("ring", "0.17.8"),),
            ),
        ),
    )


def record_for(ruleset, evidence: Evidence, **kwargs) -> dict:
    linkage = resolve_linkage(ruleset, evidence)
    findings = apply_rules(ruleset, evidence, linkage)
    verdict = classify(ruleset, findings, linkage)
    return build_record(evidence, findings, verdict, ruleset, **kwargs)


# --- shape ------------------------------------------------------------------


def test_the_record_declares_its_schema_version(ruleset) -> None:
    assert record_for(ruleset, bundled_cryptography())["schema_version"] == SCHEMA_VERSION


def test_the_record_identifies_the_tool_and_the_ruleset(ruleset) -> None:
    tool = record_for(ruleset, bundled_cryptography())["tool"]
    assert tool["name"] == "wheel-crypto-scan"
    assert tool["ruleset_version"] == ruleset.version
    assert "analyzer_version" in tool


def test_the_wheel_block_carries_identity_but_no_host_path(ruleset) -> None:
    wheel = record_for(ruleset, bundled_cryptography())["wheel"]
    assert wheel["filename"] == "cryptography-42.0.5-cp39-abi3-manylinux_2_28_x86_64.whl"
    assert wheel["name"] == "cryptography"
    assert wheel["sha256"] == "a" * 64
    assert "/" not in wheel["filename"]


def test_the_generator_is_structured_not_a_bare_string(ruleset) -> None:
    generator = record_for(ruleset, bundled_cryptography())["wheel"]["generator"]
    assert generator == {"name": "maturin", "version": "1.7.0", "raw": "maturin (1.7.0)"}


def test_a_wheel_without_metadata_still_produces_a_complete_record(ruleset) -> None:
    evidence = Evidence(
        filename="broken-1.0-py3-none-any.whl",
        sha256="b" * 64,
        size_bytes=10,
        artifacts=ArtifactInventory(),
    )
    record = record_for(ruleset, evidence)
    assert record["wheel"]["name"] is None
    assert record["wheel"]["generator"] is None
    assert set(record) >= {"schema_version", "tool", "wheel", "artifacts", "findings", "verdict"}


# --- the field the acceptance gate reads ------------------------------------


def test_openssl_linkage_is_reported_in_the_conditions(ruleset) -> None:
    record = record_for(ruleset, bundled_cryptography())
    assert record["verdict"]["conditions"]["openssl_linkage"] == "bundled"


def test_the_verdict_keeps_every_class_that_fired(ruleset) -> None:
    verdict = record_for(ruleset, bundled_cryptography())["verdict"]
    assert verdict["class"] in verdict["classes"]
    assert verdict["class"] == verdict["classes"][0]


def test_the_verdict_can_never_say_compliant(ruleset) -> None:
    serialised = to_json_line(record_for(ruleset, bundled_cryptography()))
    assert "COMPLIANT" not in serialised
    assert "COMPATIBLE" not in serialised


# --- findings ---------------------------------------------------------------


def test_findings_carry_rule_location_and_literal_evidence(ruleset) -> None:
    findings = record_for(ruleset, bundled_cryptography())["findings"]
    bundled = next(f for f in findings if f["rule_id"] == "BIN_BUNDLED_OPENSSL")
    assert bundled["severity"] == "high"
    assert bundled["locations"][0]["path"] == "cryptography.libs/libcrypto-3a1f2b4c.so.3"
    assert "OpenSSL 3.0.14" in bundled["locations"][0]["evidence"]


def test_every_finding_has_the_same_key_set(ruleset) -> None:
    findings = record_for(ruleset, bundled_cryptography())["findings"]
    assert len({tuple(sorted(finding)) for finding in findings}) == 1


# --- binaries[] cap: what a finding points at is kept first (#75) -----------
#
# `binfmt.caps.cap()` fixed this shape one layer down for the per-binary string,
# symbol and crate caps (DECISIONS.md, "A cap bounds the record, it does not pick the
# evidence", #51): a plain sort-and-cut let a crate list with `ring` sorting behind a
# hundred `anyhow`-class names drop the one crate a rule cared about. `max_binaries`
# had the same bug one level up: a plain path-sorted prefix of `binaries[]` has no
# reason to agree with where the objects a finding actually names happen to sort.


def _evidence_with_capped_binaries(filler_count: int, referenced_count: int) -> Evidence:
    """`filler_count` inert filler objects, sorting first by path, plus
    `referenced_count` objects that each define an OpenSSL symbol -- and so are each
    referenced by `BIN_OPENSSL_SYMBOLS_DEFINED`'s finding -- sorting last."""
    fillers = tuple(
        # `needed` keeps a filler out of `BIN_OPAQUE` -- a filler must trigger no
        # finding of its own, or it would count as "referenced" too and this fixture
        # would not isolate what the fix is about.
        BinaryEvidence(path=f"pkg/_filler{i:04d}.so", format=FORMAT_ELF, needed=("libc.so.6",))
        for i in range(filler_count)
    )
    referenced = tuple(
        BinaryEvidence(
            path=f"pkg/zzz_crypto{i:04d}.so",
            format=FORMAT_ELF,
            matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_DEFINED),),
        )
        for i in range(referenced_count)
    )
    binaries = fillers + referenced
    return Evidence(
        filename="manyobjects-1.0-cp39-abi3-manylinux_2_28_x86_64.whl",
        sha256="c" * 64,
        size_bytes=1024,
        # Mirrors what `build_inventory` would compute: the full, untruncated set, so
        # a test exercising `artifacts.extensions`' own cap sees the same starting
        # point `record.py` would see from a real scan.
        artifacts=ArtifactInventory(
            extensions=tuple(sorted((binary.path, binary.format) for binary in binaries))
        ),
        binaries=binaries,
    )


def test_binaries_under_the_cap_are_unaffected_by_max_binaries(ruleset) -> None:
    """The ordinary case: nothing over the cap, so `max_binaries` must not reorder or
    filter anything, referenced or not."""
    evidence = _evidence_with_capped_binaries(filler_count=2, referenced_count=1)
    uncapped = record_for(ruleset, evidence)["binaries"]
    generously_capped = record_for(ruleset, evidence, max_binaries=100)["binaries"]

    assert uncapped == generously_capped
    assert len(uncapped) == 3


def test_a_referenced_object_sorting_last_survives_the_cap(ruleset) -> None:
    """#75: the object `BIN_OPENSSL_SYMBOLS_DEFINED` names sorts dead last among six
    objects and a cap of three, so a plain path-sorted prefix would have cut it --
    exactly the shape the reproduction in DECISIONS.md and #75 report. It must still
    make it into `binaries[]`, and the remaining room is filled with fillers in path
    order same as before."""
    evidence = _evidence_with_capped_binaries(filler_count=5, referenced_count=1)
    record = record_for(ruleset, evidence, max_binaries=3)
    paths = [b["path"] for b in record["binaries"]]

    # `artifacts.binaries_truncated` is computed by `build_inventory` from the real
    # object count against the real cap, independently of this fixture's hand-built
    # `ArtifactInventory` -- see test_hardening.py for that field end to end. This
    # test is only about which paths `binaries[]` itself lists.
    assert paths == ["pkg/_filler0000.so", "pkg/_filler0001.so", "pkg/zzz_crypto0000.so"]
    finding = next(f for f in record["findings"] if f["rule_id"] == "BIN_OPENSSL_SYMBOLS_DEFINED")
    assert finding["locations"][0]["path"] == "pkg/zzz_crypto0000.so"


def test_more_referenced_objects_than_the_cap_keeps_the_lowest_sorting_paths(ruleset) -> None:
    """When findings alone reference more objects than `max_binaries` allows, there is
    no fixed vocabulary of finding subjects to guarantee room for all of them the way
    `ruleset_loader.parse_ruleset` guarantees room for one of every string, symbol or
    crate group (DECISIONS.md, "A cap bounds the record, it does not pick the
    evidence"): how many distinct objects a wheel's findings reference is data the
    wheel supplies, not policy a ruleset declares. The referenced set is capped the
    same deterministic way the whole list always was: to the lowest-sorting paths."""
    evidence = _evidence_with_capped_binaries(filler_count=0, referenced_count=3)
    record = record_for(ruleset, evidence, max_binaries=2)
    paths = [b["path"] for b in record["binaries"]]

    assert paths == ["pkg/zzz_crypto0000.so", "pkg/zzz_crypto0001.so"]
    finding = next(f for f in record["findings"] if f["rule_id"] == "BIN_OPENSSL_SYMBOLS_DEFINED")
    # All three referenced objects are still named by the finding -- only the
    # *listing* in binaries[] is short one object, never the evaluation. See
    # SCHEMA.md.
    assert [location["path"] for location in finding["locations"]] == [
        "pkg/zzz_crypto0000.so",
        "pkg/zzz_crypto0001.so",
        "pkg/zzz_crypto0002.so",
    ]


def test_binaries_selection_does_not_depend_on_input_order(ruleset) -> None:
    """Determinism guard: `_cap_by_findings` must sort explicitly rather than trust
    `evidence.binaries`' own order, or a hash-seed-dependent set iteration anywhere
    upstream could leak into which objects get kept. Shuffling the input must not
    change which paths are selected or in what order they are listed."""
    evidence = _evidence_with_capped_binaries(filler_count=5, referenced_count=2)
    shuffled = Evidence(
        filename=evidence.filename,
        sha256=evidence.sha256,
        size_bytes=evidence.size_bytes,
        artifacts=evidence.artifacts,
        binaries=tuple(reversed(evidence.binaries)),
    )

    ordered = record_for(ruleset, evidence, max_binaries=4)["binaries"]
    reordered = record_for(ruleset, shuffled, max_binaries=4)["binaries"]

    assert ordered == reordered


def test_a_low_severity_group_does_not_starve_a_high_severity_one(ruleset) -> None:
    """Adversarial review of #75 found that a flat "referenced objects, then the
    rest, in path order" pass just moves the sorting problem: a finding's `subject`
    (here, a crate name) sorts exactly as arbitrarily with respect to severity as an
    object's path does. Ten low-severity `getrandom` objects (`CONTEXT_DEPENDENT`,
    `info`) sort before the one `ring` object (`NON_APPROVED_CRYPTO`, `high`) purely
    alphabetically, so under a cap of five a path-only pass lets getrandom's ten
    objects crowd ring's one object out entirely -- getrandom's finding stays fully
    corroborated while the one finding that actually matters has zero objects in
    `binaries[]` to back it up. `_cap_by_findings` reserves one representative object
    per `(rule_id, subject)` group before filling the rest, so ring's finding is never
    left with none."""
    getrandom_objects = tuple(
        BinaryEvidence(
            path=f"pkg/aaa_getrandom{i:04d}.so",
            format=FORMAT_ELF,
            needed=("libc.so.6",),
            rust_crates=(RustCrate("getrandom", "0.2.10"),),
        )
        for i in range(10)
    )
    ring_object = BinaryEvidence(
        path="pkg/zzz_ring.so",
        format=FORMAT_ELF,
        needed=("libc.so.6",),
        rust_crates=(RustCrate("ring", "0.17.8"),),
    )
    evidence = Evidence(
        filename="crates-1.0-cp39-abi3-manylinux_2_28_x86_64.whl",
        sha256="d" * 64,
        size_bytes=1024,
        artifacts=ArtifactInventory(),
        binaries=getrandom_objects + (ring_object,),
    )

    record = record_for(ruleset, evidence, max_binaries=5)
    paths = [binary["path"] for binary in record["binaries"]]

    assert len(paths) == 5
    assert "pkg/zzz_ring.so" in paths
    ring_finding = next(
        f
        for f in record["findings"]
        if f["rule_id"] == "BIN_RUST_CRYPTO_CRATE" and f["subject"] == "ring"
    )
    assert ring_finding["verdict"] == "NON_APPROVED_CRYPTO"
    getrandom_finding = next(
        f
        for f in record["findings"]
        if f["rule_id"] == "BIN_RUST_CRYPTO_CRATE" and f["subject"] == "getrandom"
    )
    assert getrandom_finding["verdict"] == "CONTEXT_DEPENDENT"


# --- artifacts.extensions agrees with binaries[] on the cap (#75 follow-up) --


def test_extensions_and_binaries_keep_the_same_objects_under_the_cap(ruleset) -> None:
    """Before #75, `binaries[]` and `artifacts.extensions` were always the identical
    plain path-sorted prefix -- same source, same sort, same cap. The finding-aware
    selection could have silently broken that agreement; `_cap_by_findings` is shared
    by both precisely so it does not. A referenced object that survives the cap into
    `binaries[]` must survive into `extensions` too, at the same path."""
    evidence = _evidence_with_capped_binaries(filler_count=5, referenced_count=1)
    record = record_for(ruleset, evidence, max_binaries=3)

    binary_paths = {binary["path"] for binary in record["binaries"]}
    extension_paths = {extension["path"] for extension in record["artifacts"]["extensions"]}

    assert binary_paths == extension_paths
    assert "pkg/zzz_crypto0000.so" in extension_paths


# --- evidence level ---------------------------------------------------------


def test_the_standard_level_includes_binary_evidence(ruleset) -> None:
    record = record_for(ruleset, bundled_cryptography(), evidence_level="standard")
    binary = record["binaries"][0]
    assert binary["matched_symbols"][0]["binding"] == "defined"
    assert binary["rust_crates"] == [{"name": "ring", "version": "0.17.8"}]


def test_the_minimal_level_drops_the_bulky_evidence_but_keeps_the_shape(ruleset) -> None:
    record = record_for(ruleset, bundled_cryptography(), evidence_level="minimal")
    binary = record["binaries"][0]
    assert binary["matched_symbols"] == []
    assert binary["soname"] == "libcrypto-3a1f2b4c.so.3"
    assert binary["needed"] == ["libc.so.6"]


def test_findings_are_unaffected_by_the_evidence_level(ruleset) -> None:
    """The level controls how much raw evidence is echoed, never what was detected."""
    standard = record_for(ruleset, bundled_cryptography(), evidence_level="standard")
    minimal = record_for(ruleset, bundled_cryptography(), evidence_level="minimal")
    assert standard["findings"] == minimal["findings"]
    assert standard["verdict"] == minimal["verdict"]


# --- canonical serialisation ------------------------------------------------


def test_json_keys_are_sorted(ruleset) -> None:
    line = to_json_line(record_for(ruleset, bundled_cryptography()))
    parsed = json.loads(line)
    assert list(parsed) == sorted(parsed)


def test_a_json_line_ends_with_exactly_one_newline(ruleset) -> None:
    line = to_json_line(record_for(ruleset, bundled_cryptography()))
    assert line.endswith("\n")
    assert line.count("\n") == 1


def test_serialisation_is_ascii_only(ruleset) -> None:
    """Locale and terminal encoding must not be able to change the bytes."""
    line = to_json_line(record_for(ruleset, bundled_cryptography()))
    assert line.encode("ascii")


def test_the_same_evidence_serialises_byte_identically(ruleset) -> None:
    first = to_json_line(record_for(ruleset, bundled_cryptography()))
    second = to_json_line(record_for(ruleset, bundled_cryptography()))
    assert first == second


def test_the_record_contains_no_floats(ruleset) -> None:
    """Floats would make byte-identical output depend on repr, so there are none."""

    def walk(node):
        if isinstance(node, float):
            raise AssertionError(f"float in record: {node}")
        if isinstance(node, dict):
            for value in node.values():
                walk(value)
        if isinstance(node, list):
            for value in node:
                walk(value)

    walk(record_for(ruleset, bundled_cryptography()))


def test_the_record_round_trips_through_json(ruleset) -> None:
    record = record_for(ruleset, bundled_cryptography())
    assert json.loads(to_json_line(record)) == json.loads(json.dumps(record))
