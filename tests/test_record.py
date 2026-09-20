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
