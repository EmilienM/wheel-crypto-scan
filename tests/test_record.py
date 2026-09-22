"""The output contract: record shape, canonical serialisation and determinism."""

from __future__ import annotations

import dataclasses
import json
from importlib.resources import files
from pathlib import Path

import pytest
from helpers.wheelbuilder import build_wheel

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
    ScanError,
    StringMatch,
    SymbolMatch,
)
from wheel_crypto_scan.linkage import resolve_linkage
from wheel_crypto_scan.record import build_record, to_json_line
from wheel_crypto_scan.ruleset import FAMILIES, LINKAGE_VALUES, RELATIONS
from wheel_crypto_scan.ruleset_loader import load_ruleset
from wheel_crypto_scan.scan import ScanContext, scan_wheel
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


def test_no_max_binaries_means_no_cap_and_no_truncation_flag(ruleset) -> None:
    """`max_binaries=None` is `build_record`'s own default -- callers besides `scan.py`
    exist (this module's own `record_for` is one), and neither new flag should fire
    just because nothing asked for a cap at all."""
    evidence = Evidence(
        filename="broken-1.0-py3-none-any.whl",
        sha256="c" * 64,
        size_bytes=10,
        artifacts=ArtifactInventory(
            bundled_libs=("pkg.libs/libfoo-deadbeef.so",),
            skipped=(("pkg/huge.bin", "binary_too_large"),),
            symlinks=(("pkg/lib.so", "lib.so.1"),),
        ),
        errors=(ScanError(stage="binary", kind="member_read_error", message="m", path="x"),),
    )
    record = record_for(ruleset, evidence)
    assert record["artifacts"]["bundled_libs"] == ["pkg.libs/libfoo-deadbeef.so"]
    assert record["artifacts"]["bundled_libs_truncated"] is False
    assert len(record["errors"]) == 1
    assert record["errors_truncated"] is False
    assert record["artifacts"]["skipped_truncated"] is False
    assert record["artifacts"]["symlinks_truncated"] is False


def test_skipped_and_symlinks_are_capped_independently_of_bundled_libs(ruleset) -> None:
    """`artifacts.skipped` (`{path, reason}`) and `artifacts.symlinks` (`{path,
    target}`) are the same unbounded shape as `bundled_libs` and `errors[]`, and are
    capped the same way. Both go through `caps.cap`, keyed on `reason`/`target`
    respectively (see DESIGN.md, "`skipped` and `symlinks` reuse `caps.cap`, not a
    plain prefix"); with every entry here sharing one `reason` and one `target`, the
    cap degenerates to a plain sorted prefix, which
    `test_a_rare_skipped_reason_survives_a_flood_of_a_common_one` and
    `test_a_rare_symlink_target_survives_a_flood_of_a_common_one` in
    `test_hardening.py` prove is not the general case."""
    evidence = Evidence(
        filename="broken-1.0-py3-none-any.whl",
        sha256="f" * 64,
        size_bytes=10,
        artifacts=ArtifactInventory(
            skipped=tuple((f"many/_ext{i:05d}.so", "binary_too_large") for i in range(5)),
            symlinks=tuple((f"many/lib{i:05d}.so", "libfoo.so") for i in range(5)),
        ),
    )
    record = record_for(ruleset, evidence, max_binaries=3)
    assert record["artifacts"]["skipped"] == [
        {"path": "many/_ext00000.so", "reason": "binary_too_large"},
        {"path": "many/_ext00001.so", "reason": "binary_too_large"},
        {"path": "many/_ext00002.so", "reason": "binary_too_large"},
    ]
    assert record["artifacts"]["skipped_truncated"] is True
    assert record["artifacts"]["symlinks"] == [
        {"path": "many/lib00000.so", "target": "libfoo.so"},
        {"path": "many/lib00001.so", "target": "libfoo.so"},
        {"path": "many/lib00002.so", "target": "libfoo.so"},
    ]
    assert record["artifacts"]["symlinks_truncated"] is True


def test_exactly_the_cap_worth_of_skipped_and_symlinks_is_not_truncated(ruleset) -> None:
    """The same boundary `bundled_libs_truncated`/`errors_truncated` must get right:
    landing precisely on `max_binaries` must not read as truncated."""
    evidence = Evidence(
        filename="exact-1.0-py3-none-any.whl",
        sha256="g" * 64,
        size_bytes=10,
        artifacts=ArtifactInventory(
            skipped=tuple((f"many/_ext{i:05d}.so", "binary_too_large") for i in range(3)),
            symlinks=tuple((f"many/lib{i:05d}.so", "libfoo.so") for i in range(3)),
        ),
    )
    record = record_for(ruleset, evidence, max_binaries=3)
    assert len(record["artifacts"]["skipped"]) == 3
    assert record["artifacts"]["skipped_truncated"] is False
    assert len(record["artifacts"]["symlinks"]) == 3
    assert record["artifacts"]["symlinks_truncated"] is False


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


def test_a_finding_carries_its_relation_basis_and_family(ruleset) -> None:
    """A bundled OpenSSL resolves through `BIN_BUNDLED_OPENSSL`'s `table = "crypto_library"`
    match, so the finding takes the `openssl` library's own `relation`/`basis`/`family`
    rather than the rule's -- the same override `severity`/`verdict` already take."""
    findings = record_for(ruleset, bundled_cryptography())["findings"]
    bundled = next(f for f in findings if f["rule_id"] == "BIN_BUNDLED_OPENSSL")
    library = ruleset.libraries["openssl"]
    assert bundled["relation"] == library.relation
    assert bundled["basis"] == sorted(library.basis)
    assert bundled["family"] == library.family


def test_basis_is_sorted(ruleset) -> None:
    findings = record_for(ruleset, bundled_cryptography())["findings"]
    for finding in findings:
        assert finding["basis"] == sorted(finding["basis"])


# --- crypto -------------------------------------------------------------------


def test_crypto_lists_every_family_a_finding_was_evidence_of(ruleset) -> None:
    families = record_for(ruleset, bundled_cryptography())["crypto"]["families"]
    assert families == sorted(set(families))
    assert families == ["library"]


def test_crypto_lists_every_library_whose_linkage_is_not_none(ruleset) -> None:
    """Derived from `verdict.conditions`, not threaded through separately: the two can
    never disagree. `openssl` is `always_report = true` and reads `bundled` here, so it
    is included; nothing else has evidence in this fixture."""
    record = record_for(ruleset, bundled_cryptography())
    assert record["crypto"]["libraries"] == [{"name": "openssl", "linkage": "bundled"}]
    conditions = record["verdict"]["conditions"]
    expected = sorted(
        name.removesuffix("_linkage") for name, value in conditions.items() if value != "none"
    )
    assert [library["name"] for library in record["crypto"]["libraries"]] == expected


def test_a_wheel_with_no_crypto_gets_a_genuinely_empty_crypto_block(ruleset) -> None:
    """`openssl` is `always_report = true` and reads `none` on a wheel with no crypto
    evidence at all, so it is correctly excluded rather than listed with `linkage:
    none` -- this is what gives a `NO_CRYPTO_DETECTED` wheel an empty inventory
    instead of a missing or null one."""
    evidence = Evidence(
        filename="plain-1.0-py3-none-any.whl",
        sha256="0" * 64,
        size_bytes=1,
        artifacts=ArtifactInventory(),
    )
    record = record_for(ruleset, evidence)
    assert record["verdict"]["class"] == "NO_CRYPTO_DETECTED"
    assert record["crypto"] == {"families": [], "libraries": []}


# --- binaries[] cap: what a finding points at is kept first ---------------------
#
# `caps.cap()` handles this shape one layer down for the per-binary string, symbol and
# crate caps (DESIGN.md, "A cap bounds the record, it does not pick the evidence"): a
# plain sort-and-cut lets a crate list with `ring` sorting behind a hundred
# `anyhow`-class names drop the one crate a rule cares about. `max_binaries` has the
# same shape one level up: a plain path-sorted prefix of `binaries[]` has no reason to
# agree with where the objects a finding actually names happen to sort.


def _evidence_with_capped_binaries(filler_count: int, referenced_count: int) -> Evidence:
    """`filler_count` inert filler objects, sorting first by path, plus
    `referenced_count` objects that each define an OpenSSL symbol -- and so are each
    referenced by `BIN_OPENSSL_SYMBOLS_DEFINED`'s finding -- sorting last."""
    fillers = tuple(
        # `needed` keeps a filler out of `BIN_OPAQUE` -- a filler must trigger no
        # finding of its own, or it would count as "referenced" too and this fixture
        # would not isolate the finding-aware selection under test.
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
    """The object `BIN_OPENSSL_SYMBOLS_DEFINED` names sorts dead last among six objects
    and a cap of three, so a plain path-sorted prefix would cut it -- exactly the shape
    of the reproduction in DESIGN.md. It must still make it into `binaries[]`, and the
    remaining room is filled with fillers in path order."""
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
    crate group (DESIGN.md, "A cap bounds the record, it does not pick the
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
    """A flat "referenced objects, then the rest, in path order" pass just moves the
    sorting problem: a finding's `subject` (here, a crate name) sorts exactly as
    arbitrarily with respect to severity as an object's path does. Ten low-severity
    `getrandom` objects (`info`, no verdict) sort before the one `ring` object
    (`NON_APPROVED_CRYPTO`, `high`) purely alphabetically, so under a cap of five a
    path-only pass lets getrandom's ten objects crowd ring's one object out entirely --
    getrandom's finding stays fully corroborated while the one finding that actually
    matters has zero objects in `binaries[]` to back it up. `_cap_by_findings` reserves
    one representative object per `(rule_id, subject)` group before filling the rest, so
    ring's finding is never left with none."""
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
    assert getrandom_finding["verdict"] is None


# --- artifacts.extensions agrees with binaries[] on the cap ---------------------


def test_extensions_and_binaries_keep_the_same_objects_under_the_cap(ruleset) -> None:
    """A plain path-sorted prefix keeps `binaries[]` and `artifacts.extensions`
    identical by construction -- same source, same sort, same cap. A finding-aware
    selection can silently break that agreement; `_cap_by_findings` is shared by both
    precisely so it does not. A referenced object that survives the cap into
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


def test_a_rust_crate_with_no_version_serialises_to_a_json_null(ruleset) -> None:
    """`cargo vendor` without `--versioned-dirs` names no version, and the schema's
    `rust_crates[].version` type list carries `null` for exactly this case."""
    evidence = bundled_cryptography()
    binary_evidence = dataclasses.replace(
        evidence.binaries[0], rust_crates=(RustCrate("openssl-sys", None),)
    )
    evidence = dataclasses.replace(evidence, binaries=(binary_evidence,))
    record = record_for(ruleset, evidence, evidence_level="standard")
    binary = record["binaries"][0]
    assert binary["rust_crates"] == [{"name": "openssl-sys", "version": None}]

    schema = json.loads(
        (files("wheel_crypto_scan") / "data" / "schema.json").read_text(encoding="utf-8")
    )
    version_types = schema["properties"]["binaries"]["items"]["properties"]["rust_crates"]["items"][
        "properties"
    ]["version"]["type"]
    assert "null" in version_types


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


def test_the_schema_does_not_close_the_verdict_class_list() -> None:
    """A closed enum turns adding a verdict class into a silent schema break."""
    schema = json.loads(
        files("wheel_crypto_scan").joinpath("data/schema.json").read_text(encoding="utf-8")
    )
    assert "enum" not in schema["$defs"]["verdictClass"]
    for name in load_ruleset().precedence:
        assert name in schema["$defs"]["verdictClass"]["description"]


def test_the_schema_forbids_a_passing_class() -> None:
    text = files("wheel_crypto_scan").joinpath("data/schema.json").read_text(encoding="utf-8")
    assert "COMPLIANT" not in json.loads(text)["$defs"]["verdictClass"]["description"].upper()
    assert "COMPATIBLE" not in json.loads(text)["$defs"]["verdictClass"]["description"].upper()


def _current_values(description: str) -> set[str]:
    """The token set out of a schema description's "Current values: a, b, c." clause.

    A plain `name in description` substring check has a blind spot a token-set
    comparison does not: `"hash"` is itself a substring of `"password_hash"`, so
    dropping the standalone `hash` token from the description would not be caught by
    substring containment alone, only by comparing the parsed set to the vocabulary.
    """
    start = description.index("Current values: ") + len("Current values: ")
    end = description.index(".", start)
    return {token.strip() for token in description[start:end].split(",")}


def test_the_schema_does_not_close_the_relation_or_family_lists() -> None:
    """The same argument as `test_the_schema_does_not_close_the_verdict_class_list`,
    for the two vocabularies this task added: a closed enum turns adding a relation or
    a family to `ruleset.py` into a silent schema break."""
    schema = json.loads(
        files("wheel_crypto_scan").joinpath("data/schema.json").read_text(encoding="utf-8")
    )
    assert "enum" not in schema["$defs"]["relation"]
    assert "enum" not in schema["$defs"]["family"]
    assert _current_values(schema["$defs"]["relation"]["description"]) == set(RELATIONS)
    assert _current_values(schema["$defs"]["family"]["description"]) == set(FAMILIES)


def test_crypto_library_linkage_enum_matches_the_linkage_vocabulary_minus_none() -> None:
    """`crypto.libraries[].linkage` can never report `none` -- a library reading that
    posture is excluded from the array entirely, not listed with it -- so its closed
    enum is `LINKAGE_VALUES` minus that one value, and a value added to or removed from
    `LINKAGE_VALUES` must not drift from this copy silently."""
    schema = json.loads(
        files("wheel_crypto_scan").joinpath("data/schema.json").read_text(encoding="utf-8")
    )
    linkage_enum = schema["properties"]["crypto"]["properties"]["libraries"]["items"]["properties"][
        "linkage"
    ]["enum"]
    assert set(linkage_enum) == LINKAGE_VALUES - {"none"}


def test_the_record_says_which_evidence_level_produced_it(tmp_path: Path) -> None:
    """Empty matched_symbols means "none found" at standard and "not recorded" at minimal."""
    wheel = build_wheel(
        tmp_path / "demo-1.0-py3-none-any.whl", name="demo", version="1.0", files={}
    )
    standard_context = ScanContext.build(load_ruleset())
    standard = scan_wheel(wheel, standard_context)
    assert standard["tool"]["evidence_level"] == "standard"
    minimal_context = ScanContext.build(load_ruleset(), evidence_level="minimal")
    assert scan_wheel(wheel, minimal_context)["tool"]["evidence_level"] == "minimal"
