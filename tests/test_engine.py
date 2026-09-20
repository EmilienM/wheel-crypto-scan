"""How extracted evidence becomes findings.

The engine owns no policy. Every name, symbol and pattern here comes from the shipped
ruleset, so these tests assert the matching machinery rather than the classifications.
"""

from __future__ import annotations

import tomllib
from importlib.resources import files

import pytest

from wheel_crypto_scan.engine import apply_rules
from wheel_crypto_scan.evidence import (
    BINDING_DEFINED,
    BINDING_IMPORTED,
    FORMAT_ELF,
    FORMAT_MACHO,
    FORMAT_PE,
    STAGE_BINARY,
    STAGE_PYTHON,
    ArtifactInventory,
    BinaryEvidence,
    Evidence,
    MetadataEvidence,
    PySite,
    RustCrate,
    SbomComponent,
    ScanError,
    StringMatch,
    SymbolMatch,
)
from wheel_crypto_scan.linkage import resolve_linkage
from wheel_crypto_scan.ruleset_loader import load_ruleset, parse_ruleset


@pytest.fixture(scope="module")
def ruleset():
    return load_ruleset()


def metadata(name: str = "demo", version: str = "1.0", **kwargs) -> MetadataEvidence:
    return MetadataEvidence(
        name=name,
        canonical_name=name.lower().replace("_", "-"),
        version=version,
        dist_info_dir=f"{name}-{version}.dist-info",
        **kwargs,
    )


def wheel(**kwargs) -> Evidence:
    kwargs.setdefault("artifacts", ArtifactInventory())
    kwargs.setdefault("metadata", metadata())
    return Evidence(filename="demo-1.0-py3-none-any.whl", sha256="0" * 64, size_bytes=1, **kwargs)


def run(ruleset, evidence: Evidence):
    return apply_rules(ruleset, evidence, resolve_linkage(ruleset, evidence))


def ids(findings) -> set[str]:
    return {finding.rule_id for finding in findings}


def one(findings, rule_id: str):
    matches = [finding for finding in findings if finding.rule_id == rule_id]
    assert len(matches) == 1, f"expected exactly one {rule_id}, got {len(matches)}"
    return matches[0]


# --- metadata layer ---------------------------------------------------------


def test_a_non_approved_distribution_is_matched_by_name(ruleset) -> None:
    findings = run(ruleset, wheel(metadata=metadata(name="PyNaCl", version="1.5.0")))
    finding = one(findings, "DIST_NON_APPROVED_CRYPTO")
    assert finding.verdict == "NON_APPROVED_CRYPTO"
    assert finding.subject == "pynacl"


def test_a_wrapper_distribution_gets_the_conditional_rule_not_the_non_approved_one(
    ruleset,
) -> None:
    findings = run(ruleset, wheel(metadata=metadata(name="cryptography", version="42.0.5")))
    assert "DIST_SYSTEM_CRYPTO_WRAPPER" in ids(findings)
    assert "DIST_NON_APPROVED_CRYPTO" not in ids(findings)


def test_an_unlisted_distribution_matches_no_name_rule(ruleset) -> None:
    findings = run(ruleset, wheel(metadata=metadata(name="numpy")))
    assert not ids(findings) & {"DIST_NON_APPROVED_CRYPTO", "DIST_SYSTEM_CRYPTO_WRAPPER"}


def test_a_dependency_on_a_crypto_distribution_is_recorded_without_a_verdict(ruleset) -> None:
    """The dependency carries its own risk in its own record; do not double count it."""
    findings = run(ruleset, wheel(metadata=metadata(requires_dist_names=("pynacl", "numpy"))))
    finding = one(findings, "DIST_DEPENDS_ON_CRYPTO")
    assert finding.verdict is None
    assert finding.subject == "pynacl"


def test_bytecode_without_source_is_flagged_opaque(ruleset) -> None:
    artifacts = ArtifactInventory(py_files=0, pyc_files=12, source_available=False)
    assert "WHEEL_NO_PYTHON_SOURCE" in ids(run(ruleset, wheel(artifacts=artifacts)))


def test_a_wheel_with_sources_is_not_flagged_opaque(ruleset) -> None:
    artifacts = ArtifactInventory(py_files=12, pyc_files=0, source_available=True)
    assert "WHEEL_NO_PYTHON_SOURCE" not in ids(run(ruleset, wheel(artifacts=artifacts)))


def test_an_sbom_component_naming_a_crypto_crate_is_matched(ruleset) -> None:
    component = SbomComponent(
        name="ring",
        version="0.17.8",
        purl="pkg:cargo/ring@0.17.8",
        source="d.dist-info/sboms/a.json",
    )
    findings = run(ruleset, wheel(metadata=metadata(sbom_components=(component,))))
    finding = one(findings, "SBOM_CRYPTO_COMPONENT")
    assert finding.subject == "ring"
    assert finding.verdict == "NON_APPROVED_CRYPTO"


def test_scan_errors_become_findings(ruleset) -> None:
    error = ScanError(stage=STAGE_BINARY, kind="elf_parse_error", message="truncated", path="a.so")
    assert "BIN_UNPARSEABLE" in ids(run(ruleset, wheel(errors=(error,))))


# --- binary layer -----------------------------------------------------------


def binary(path: str, **kwargs) -> BinaryEvidence:
    kwargs.setdefault("format", FORMAT_ELF)
    return BinaryEvidence(path=path, **kwargs)


def test_a_vendored_libcrypto_is_the_bundled_openssl_finding(ruleset) -> None:
    evidence = wheel(
        binaries=(
            binary(
                "demo.libs/libcrypto-3a1f2b4c.so.3",
                vendored_path=True,
                soname="libcrypto-3a1f2b4c.so.3",
                matched_strings=(StringMatch("openssl_banner", "OpenSSL 3.0.14 4 Jun 2024"),),
            ),
        )
    )
    finding = one(run(ruleset, evidence), "BIN_BUNDLED_OPENSSL")
    assert finding.locations[0].path == "demo.libs/libcrypto-3a1f2b4c.so.3"
    assert "libcrypto-3a1f2b4c.so.3" in finding.locations[0].evidence


def test_a_vendored_libsodium_uses_the_general_bundled_rule(ruleset) -> None:
    evidence = wheel(
        binaries=(
            binary("demo.libs/libsodium.so.23", vendored_path=True, soname="libsodium.so.23"),
        )
    )
    findings = run(ruleset, evidence)
    assert "BIN_BUNDLED_CRYPTO_LIB" in ids(findings)
    assert "BIN_BUNDLED_OPENSSL" not in ids(findings)
    assert one(findings, "BIN_BUNDLED_CRYPTO_LIB").verdict == "NON_APPROVED_CRYPTO"


def test_a_plain_system_dependency_is_informational(ruleset) -> None:
    evidence = wheel(binaries=(binary("demo/_ext.so", needed=("libcrypto.so.3",)),))
    finding = one(run(ruleset, evidence), "BIN_NEEDED_SYSTEM_OPENSSL")
    assert finding.severity == "info"
    assert finding.verdict is None


def test_a_hash_renamed_dependency_is_treated_as_vendored(ruleset) -> None:
    evidence = wheel(binaries=(binary("demo/_ext.so", needed=("libcrypto-3a1f2b4c.so.3",)),))
    findings = run(ruleset, evidence)
    assert "BIN_NEEDED_MANGLED_CRYPTO" in ids(findings)
    assert "BIN_NEEDED_SYSTEM_OPENSSL" not in ids(findings)


# --- BLOCKING 1 (adversarial review of #57): a resolved-but-unmangled needed entry
# --- must carry its own finding, never a silent `bundled` ---------------------------


def test_an_unmangled_needed_entry_resolving_to_a_shipped_object_gets_its_own_rule(
    ruleset,
) -> None:
    """No vendor directory at all, so `BIN_BUNDLED_OPENSSL` (which reads the shipped
    object's own `vendored_path`) does not fire here: `BIN_NEEDED_VENDORED_CRYPTO` is
    the only thing standing between this `bundled` reading and `verdict.conditions`
    saying `bundled` while `rule_ids` says nothing did -- the contradiction
    `BIN_LINKED_CRYPTO_LIBRARY`'s own `why` says must never happen.
    """
    evidence = wheel(
        binaries=(
            binary("demo/_ext.so", needed=("libcrypto.so.3", "libc.so.6")),
            binary("demo/libcrypto.so.3", soname="libcrypto.so.3", needed=("libc.so.6",)),
        )
    )
    findings = run(ruleset, evidence)
    finding = one(findings, "BIN_NEEDED_VENDORED_CRYPTO")
    assert finding.verdict == "CONDITIONAL"
    assert finding.needs_human_review is True
    assert "BIN_BUNDLED_OPENSSL" not in ids(findings)
    assert "BIN_NEEDED_SYSTEM_OPENSSL" not in ids(findings)


def test_a_self_referencing_absolute_system_dependency_is_not_manufactured_bundled(
    ruleset,
) -> None:
    """The sharpest case the review found: one object, named `libcrypto.so`, declaring
    an absolute, genuinely-system `/usr/lib64/libcrypto.so.3`. Before excluding an
    object's own stem from its own answer, this read `bundled` with no rule behind it
    at all -- `verdict.conditions.openssl_linkage == "bundled"` while `rule_ids` was
    empty and `needs_human_review` was `false`.
    """
    evidence = wheel(
        binaries=(
            binary(
                "fakecrypto/libcrypto.so",
                soname="libcrypto.so",
                needed=("/usr/lib64/libcrypto.so.3", "libc.so.6"),
                matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_IMPORTED),),
            ),
        )
    )
    findings = run(ruleset, evidence)
    assert "BIN_NEEDED_SYSTEM_OPENSSL" in ids(findings)
    assert "DERIVED_SYSTEM_OPENSSL_ONLY" in ids(findings)
    assert "BIN_NEEDED_VENDORED_CRYPTO" not in ids(findings)
    assert "BIN_BUNDLED_OPENSSL" not in ids(findings)


def test_a_self_referencing_relative_dependency_is_not_manufactured_bundled(ruleset) -> None:
    """#80 gives an absolute entry its own short-circuit ahead of the own-stem
    discount above, so the reproduction just above no longer exercises it: one object
    declaring a plain *relative* `libcrypto.so.3` -- its own stem, and one a real
    loader genuinely could resolve via `RUNPATH $ORIGIN` -- must still not answer its
    own question, or `BIN_NEEDED_VENDORED_CRYPTO` would manufacture a `bundled`
    reading with nothing behind it.
    """
    evidence = wheel(
        binaries=(
            binary(
                "fakecrypto/libcrypto.so",
                soname="libcrypto.so",
                needed=("libcrypto.so.3", "libc.so.6"),
                runpath=("$ORIGIN",),
                matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_IMPORTED),),
            ),
        )
    )
    findings = run(ruleset, evidence)
    assert "BIN_NEEDED_SYSTEM_OPENSSL" in ids(findings)
    assert "DERIVED_SYSTEM_OPENSSL_ONLY" in ids(findings)
    assert "BIN_NEEDED_VENDORED_CRYPTO" not in ids(findings)
    assert "BIN_BUNDLED_OPENSSL" not in ids(findings)


def test_an_absolute_basename_collision_no_longer_reads_as_bundled(ruleset) -> None:
    """Closed by #80. This was the documented residual: two different objects that
    happen to share a basename, with the `needed` entry naming the absolute path. An
    absolute path is never resolved via search order by a real loader, so the second
    object's basename is as meaningless here as the declaring object's own name was in
    `test_a_self_referencing_absolute_system_dependency_is_not_manufactured_bundled` --
    the object *count* was never the right test for an absolute path.
    """
    evidence = wheel(
        binaries=(
            binary(
                "demo/libcrypto.so", soname="libcrypto.so", needed=("/usr/lib64/libcrypto.so.3",)
            ),
            binary("demo/plugins/libcrypto.so", soname="libcrypto.so", needed=("libc.so.6",)),
        )
    )
    findings = run(ruleset, evidence)
    assert "BIN_NEEDED_SYSTEM_OPENSSL" in ids(findings)
    assert "DERIVED_SYSTEM_OPENSSL_ONLY" in ids(findings)
    assert "BIN_NEEDED_VENDORED_CRYPTO" not in ids(findings)


def test_the_documented_basename_collision_residual_still_carries_a_finding(ruleset) -> None:
    """#80 narrows the residual to relative entries. Two different objects that happen
    to share a basename, with the `needed` entry a relative name that can genuinely be
    resolved by search order (`DECISIONS.md`'s accepted residual, unchanged for this
    shape): the `bundled` classification may still be an imprecise false positive from
    the coincidence, but it must never be silent about it.
    """
    evidence = wheel(
        binaries=(
            binary("demo/_ext.so", needed=("libcrypto.so.3",)),
            binary("demo/plugins/libcrypto.so.3", soname="libcrypto.so.3", needed=("libc.so.6",)),
        )
    )
    findings = run(ruleset, evidence)
    finding = one(findings, "BIN_NEEDED_VENDORED_CRYPTO")
    assert finding.verdict == "CONDITIONAL"
    assert finding.needs_human_review is True


def test_imported_and_defined_symbols_produce_different_rules(ruleset) -> None:
    imported = wheel(
        binaries=(
            binary(
                "demo/_ext.so",
                matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_IMPORTED),),
            ),
        )
    )
    defined = wheel(
        binaries=(
            binary(
                "demo/_ext.so",
                matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_DEFINED),),
            ),
        )
    )
    assert "BIN_OPENSSL_SYMBOLS_IMPORTED" in ids(run(ruleset, imported))
    assert "BIN_OPENSSL_SYMBOLS_DEFINED" not in ids(run(ruleset, imported))
    assert "BIN_OPENSSL_SYMBOLS_DEFINED" in ids(run(ruleset, defined))
    assert "BIN_OPENSSL_SYMBOLS_IMPORTED" not in ids(run(ruleset, defined))


def test_an_any_binding_rule_matches_both(ruleset) -> None:
    evidence = wheel(
        binaries=(
            binary(
                "demo/_ext.so",
                matched_symbols=(SymbolMatch("sodium_init", "libsodium", BINDING_IMPORTED),),
            ),
        )
    )
    assert "BIN_LIBSODIUM" in ids(run(ruleset, evidence))


def test_a_rust_crate_carries_its_own_verdict(ruleset) -> None:
    evidence = wheel(
        binaries=(
            binary(
                "demo/_rust.abi3.so",
                rust_crates=(RustCrate("ring", "0.17.8"), RustCrate("blake3", "1.5.1")),
            ),
        )
    )
    findings = [f for f in run(ruleset, evidence) if f.rule_id == "BIN_RUST_CRYPTO_CRATE"]
    verdicts = {finding.subject: finding.verdict for finding in findings}
    assert verdicts == {"ring": "NON_APPROVED_CRYPTO", "blake3": "CONTEXT_DEPENDENT"}


def test_a_binary_that_yielded_nothing_is_opaque(ruleset) -> None:
    assert "BIN_OPAQUE" in ids(run(ruleset, wheel(binaries=(binary("demo/_ext.so"),))))


def test_a_partially_readable_format_is_flagged(ruleset) -> None:
    evidence = wheel(
        binaries=(binary("demo/_ext.pyd", format=FORMAT_PE, partial_analysis=True, needed=("a",)),)
    )
    assert "BIN_PARTIAL_FORMAT" in ids(run(ruleset, evidence))


def test_the_partial_finding_does_not_contradict_the_record_that_carries_it(ruleset) -> None:
    """A fat Mach-O is partial *and* has matched symbols, in the same record.

    Wording this finding as "read for strings only" would have the record deny its own
    finding, so the evidence line says which object was partially read and nothing about
    how much of it was read.
    """
    evidence = wheel(
        binaries=(
            binary(
                "demo/_ext.cpython-312-darwin.so",
                format=FORMAT_MACHO,
                partial_analysis=True,
                partial_reasons=("macho_symtab_incomplete",),
                matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_IMPORTED),),
            ),
        )
    )
    finding = one(run(ruleset, evidence), "BIN_PARTIAL_FORMAT")
    assert finding.subject == FORMAT_MACHO
    # Which object, and which cause, but nothing about how much of it was read.
    assert [location.evidence for location in finding.locations] == [
        "macho object was only partially read: macho_symtab_incomplete"
    ]


def test_boringcrypto_suppresses_the_stock_go_crypto_finding(ruleset) -> None:
    """A BoringCrypto build still contains the stock package paths."""
    evidence = wheel(
        binaries=(
            binary(
                "demo/_go.so",
                matched_strings=(
                    StringMatch("go_boring", "crypto/internal/boring"),
                    StringMatch("go_stock_crypto", "crypto/sha256."),
                ),
            ),
        )
    )
    findings = ids(run(ruleset, evidence))
    assert "BIN_GO_BORING_CRYPTO" in findings
    assert "BIN_GO_STOCK_CRYPTO" not in findings


def test_stock_go_crypto_is_reported_when_boringcrypto_is_absent(ruleset) -> None:
    evidence = wheel(
        binaries=(
            binary("demo/_go.so", matched_strings=(StringMatch("go_stock_crypto", "crypto/aes."),)),
        )
    )
    assert "BIN_GO_STOCK_CRYPTO" in ids(run(ruleset, evidence))


# --- linkage-driven rules ---------------------------------------------------


def test_system_only_linkage_states_the_condition_explicitly(ruleset) -> None:
    evidence = wheel(binaries=(binary("demo/_ext.so", needed=("libcrypto.so.3",)),))
    assert "DERIVED_SYSTEM_OPENSSL_ONLY" in ids(run(ruleset, evidence))


def test_static_linkage_produces_its_own_finding(ruleset) -> None:
    evidence = wheel(
        binaries=(
            binary(
                "demo/_rust.abi3.so",
                needed=("libc.so.6",),
                matched_strings=(StringMatch("openssl_banner", "OpenSSL 3.0.14 4 Jun 2024"),),
            ),
        )
    )
    findings = ids(run(ruleset, evidence))
    assert "BIN_STATIC_OPENSSL" in findings
    assert "DERIVED_SYSTEM_OPENSSL_ONLY" not in findings


def test_system_and_static_evidence_in_one_object_never_reads_as_system_only(ruleset) -> None:
    """#60: a `needed` match to the system library used to short-circuit before the
    defined-symbol check ever ran, so a record could carry both
    `DERIVED_SYSTEM_OPENSSL_ONLY` ("every piece of OpenSSL evidence points at the
    system library") and `BIN_OPENSSL_SYMBOLS_DEFINED` ("OpenSSL was compiled into
    it") at once -- a contradiction in the clean direction. The object's own posture
    is `mixed`, not `system`, so the two findings can never appear together again,
    and the `needed`-side finding still fires: neither observation is dropped.
    """
    evidence = wheel(
        binaries=(
            binary(
                "demo/_ext.so",
                needed=("libc.so.6", "libssl.so.3"),
                matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_DEFINED),),
            ),
        )
    )
    findings = ids(run(ruleset, evidence))
    assert resolve_linkage(ruleset, evidence)["openssl"] == "mixed"
    assert "BIN_NEEDED_SYSTEM_OPENSSL" in findings
    assert "BIN_OPENSSL_SYMBOLS_DEFINED" in findings
    assert "DERIVED_SYSTEM_OPENSSL_ONLY" not in findings


# --- python layer -----------------------------------------------------------


def site(kind: str, target: str, line: int = 1, **attrs) -> PySite:
    return PySite(
        path="demo/mod.py",
        line=line,
        kind=kind,
        target=target,
        detail=f"{target} at line {line}",
        attrs=tuple(sorted(attrs.items())),
    )


def test_an_unmarked_weak_hash_call_is_fips_breaking(ruleset) -> None:
    evidence = wheel(
        py_sites=(site("py_call", "hashlib.md5", algorithm="md5", usedforsecurity="absent"),)
    )
    finding = one(run(ruleset, evidence), "PY_WEAK_HASH_CALL")
    assert finding.verdict == "FIPS_BREAKING"
    assert finding.locations[0].line == 1


def test_a_marked_weak_hash_call_is_degraded_not_cleared(ruleset) -> None:
    evidence = wheel(
        py_sites=(site("py_call", "hashlib.md5", algorithm="md5", usedforsecurity="false"),)
    )
    findings = ids(run(ruleset, evidence))
    assert "PY_WEAK_HASH_CALL_MARKED" in findings
    assert "PY_WEAK_HASH_CALL" not in findings


def test_a_strong_hash_call_is_not_flagged(ruleset) -> None:
    evidence = wheel(
        py_sites=(site("py_call", "hashlib.new", algorithm="sha256", usedforsecurity="absent"),)
    )
    assert not ids(run(ruleset, evidence)) & {"PY_WEAK_HASH_CALL", "PY_WEAK_HASH_CALL_MARKED"}


def test_a_runtime_chosen_algorithm_is_unresolved(ruleset) -> None:
    evidence = wheel(
        py_sites=(site("py_call", "hashlib.new", algorithm="unresolved", usedforsecurity="absent"),)
    )
    findings = ids(run(ruleset, evidence))
    assert "PY_WEAK_HASH_UNRESOLVED" in findings
    assert "PY_WEAK_HASH_CALL" not in findings


def test_an_explicit_usedforsecurity_true_is_fips_breaking(ruleset) -> None:
    """#58: usedforsecurity=True is a stronger signal than the no-keyword case, not a
    weaker one, and it fired nothing at all before this rule's match table grew it."""
    evidence = wheel(
        py_sites=(site("py_call", "hashlib.md5", algorithm="md5", usedforsecurity="true"),)
    )
    finding = one(run(ruleset, evidence), "PY_WEAK_HASH_CALL")
    assert finding.verdict == "FIPS_BREAKING"


def test_a_non_constant_usedforsecurity_on_a_weak_hash_is_unresolved(ruleset) -> None:
    """#58: PY_WEAK_HASH_UNRESOLVED's own `why` already claimed this shape; nothing
    matched it until a second [[rule.match]] table was added for it."""
    evidence = wheel(
        py_sites=(site("py_call", "hashlib.md5", algorithm="md5", usedforsecurity="unresolved"),)
    )
    findings = ids(run(ruleset, evidence))
    assert "PY_WEAK_HASH_UNRESOLVED" in findings
    assert "PY_WEAK_HASH_CALL" not in findings


def test_a_non_constant_usedforsecurity_on_a_strong_hash_is_not_flagged(ruleset) -> None:
    """#58: sha256 stays approved regardless of usedforsecurity, so a non-constant flag
    on it must not borrow the weak-hash finding."""
    evidence = wheel(
        py_sites=(site("py_call", "hashlib.new", algorithm="sha256", usedforsecurity="unresolved"),)
    )
    findings = ids(run(ruleset, evidence))
    assert not findings & {
        "PY_WEAK_HASH_CALL",
        "PY_WEAK_HASH_CALL_MARKED",
        "PY_WEAK_HASH_UNRESOLVED",
    }


def test_a_method_call_matches_the_wildcard_target(ruleset) -> None:
    assert "PY_TLS_POLICY_OVERRIDE" in ids(
        run(ruleset, wheel(py_sites=(site("py_call", "ctx.set_ciphers"),)))
    )


def test_disabling_hostname_checking_is_matched_on_its_value(ruleset) -> None:
    disabled = wheel(py_sites=(site("py_attr", "check_hostname", value="False"),))
    enabled = wheel(py_sites=(site("py_attr", "check_hostname", value="True"),))
    assert "PY_TLS_VERIFICATION_DISABLED" in ids(run(ruleset, disabled))
    assert "PY_TLS_VERIFICATION_DISABLED" not in ids(run(ruleset, enabled))


def test_a_legacy_protocol_constant_is_matched(ruleset) -> None:
    assert "PY_LEGACY_TLS_PROTOCOL" in ids(
        run(ruleset, wheel(py_sites=(site("py_constant", "ssl.PROTOCOL_TLSv1"),)))
    )


def test_a_ctypes_crypto_load_is_matched(ruleset) -> None:
    evidence = wheel(py_sites=(site("py_ctypes_load", "libcrypto", library="libcrypto.so.3"),))
    assert "PY_CTYPES_CRYPTO_LOAD" in ids(run(ruleset, evidence))


def test_the_random_module_uses_its_own_rule_not_the_default_import_rule(ruleset) -> None:
    findings = ids(run(ruleset, wheel(py_sites=(site("py_import", "random"),))))
    assert "PY_INSECURE_RNG" in findings
    assert "PY_IMPORT_CRYPTO_MODULE" not in findings


def test_a_crypto_import_uses_the_default_import_rule(ruleset) -> None:
    findings = run(ruleset, wheel(py_sites=(site("py_import", "nacl"),)))
    finding = one(findings, "PY_IMPORT_CRYPTO_MODULE")
    assert finding.subject == "nacl"
    assert finding.verdict == "NON_APPROVED_CRYPTO"


def test_an_unlisted_import_is_ignored(ruleset) -> None:
    assert "PY_IMPORT_CRYPTO_MODULE" not in ids(
        run(ruleset, wheel(py_sites=(site("py_import", "json"),)))
    )


# --- aggregation, caps and determinism --------------------------------------


def test_repeated_call_sites_aggregate_into_one_finding(ruleset) -> None:
    sites = tuple(
        site("py_call", "hashlib.md5", line=n, algorithm="md5", usedforsecurity="absent")
        for n in range(1, 26)
    )
    finding = one(run(ruleset, wheel(py_sites=sites)), "PY_WEAK_HASH_CALL")
    assert finding.occurrences == 25
    assert len(finding.locations) == ruleset.limits.max_locations_per_finding
    assert finding.truncated is True


def test_a_finding_under_the_cap_is_not_marked_truncated(ruleset) -> None:
    sites = (site("py_call", "hashlib.md5", algorithm="md5", usedforsecurity="absent"),)
    finding = one(run(ruleset, wheel(py_sites=sites)), "PY_WEAK_HASH_CALL")
    assert finding.truncated is False
    assert finding.occurrences == 1


def test_evidence_text_is_capped(ruleset) -> None:
    long_site = PySite(
        path="demo/mod.py",
        line=1,
        kind="py_call",
        target="hashlib.md5",
        detail="x" * 5000,
        attrs=(("algorithm", "md5"), ("usedforsecurity", "absent")),
    )
    finding = one(run(ruleset, wheel(py_sites=(long_site,))), "PY_WEAK_HASH_CALL")
    assert len(finding.locations[0].evidence) <= ruleset.limits.max_evidence_chars


def test_findings_are_sorted(ruleset) -> None:
    evidence = wheel(
        metadata=metadata(name="PyNaCl"),
        py_sites=(site("py_import", "nacl"), site("py_call", "hashlib.md5", algorithm="md5")),
        binaries=(binary("demo/_ext.so", needed=("libcrypto.so.3",)),),
    )
    keys = [finding.sort_key() for finding in run(ruleset, evidence)]
    assert keys == sorted(keys)


def test_locations_within_a_finding_are_sorted(ruleset) -> None:
    sites = tuple(
        site("py_call", "hashlib.md5", line=n, algorithm="md5", usedforsecurity="absent")
        for n in (9, 2, 7, 1)
    )
    finding = one(run(ruleset, wheel(py_sites=sites)), "PY_WEAK_HASH_CALL")
    assert [location.line for location in finding.locations] == [1, 2, 7, 9]


def test_the_result_does_not_depend_on_evidence_order(ruleset) -> None:
    sites = (site("py_import", "nacl", line=3), site("py_import", "bcrypt", line=1))
    first = run(ruleset, wheel(py_sites=sites))
    second = run(ruleset, wheel(py_sites=tuple(reversed(sites))))
    assert first == second


def test_duplicate_evidence_does_not_duplicate_a_location(ruleset) -> None:
    duplicate = site("py_import", "nacl")
    finding = one(run(ruleset, wheel(py_sites=(duplicate, duplicate))), "PY_IMPORT_CRYPTO_MODULE")
    assert len(finding.locations) == 1


def test_a_wheel_with_nothing_in_it_produces_no_findings(ruleset) -> None:
    assert run(ruleset, wheel(metadata=metadata(name="puredata"))) == ()


def test_python_errors_are_reported_without_a_verdict(ruleset) -> None:
    error = ScanError(
        stage=STAGE_PYTHON, kind="python_syntax_error", message="line 3", path="demo/bad.py"
    )
    finding = one(run(ruleset, wheel(errors=(error,))), "PY_UNREADABLE")
    assert finding.verdict is None


# --- rule shape: several matches, and entries that pick their rule -----------


def shipped_data() -> dict:
    """The shipped ruleset as data, so a test can add a rule without editing policy."""
    return tomllib.loads(
        files("wheel_crypto_scan").joinpath("data/ruleset.toml").read_text(encoding="utf-8")
    )


def rule_entry(rule_id: str, match, **overrides) -> dict:
    entry = {
        "id": rule_id,
        "layer": "binary",
        "category": "test",
        "severity": "high",
        "confidence": "high",
        "needs_human_review": True,
        "title": "t",
        "why": "w",
        "match": match,
    }
    entry.update(overrides)
    return entry


def test_one_rule_can_match_through_two_matcher_kinds() -> None:
    """Why `match` may be a list: one concern, two matchers, still one rule id."""
    data = shipped_data()
    data["rule"].append(
        rule_entry(
            "PY_TLS_EITHER_WAY",
            [
                {"kind": "py_attr", "attributes": ["check_hostname"], "values": ["False"]},
                {"kind": "py_constant", "constants": ["ssl._create_unverified_context"]},
            ],
            layer="python",
        )
    )
    evidence = wheel(
        py_sites=(
            site("py_attr", "check_hostname", line=3, value="False"),
            site("py_constant", "ssl._create_unverified_context", line=7),
        )
    )
    findings = [f for f in run(parse_ruleset(data), evidence) if f.rule_id == "PY_TLS_EITHER_WAY"]
    assert {finding.subject for finding in findings} == {
        "check_hostname",
        "ssl._create_unverified_context",
    }


def test_a_crate_entry_routes_to_the_rule_it_names() -> None:
    """Without routing a second rule of the same kind would fire on every crate too."""
    data = shipped_data()
    data["rule"].append(rule_entry("BIN_RING_ONLY", {"kind": "rust_crate", "table": "rust_crate"}))
    for entry in data["rust_crate"]:
        if entry["name"] == "ring":
            entry["rule"] = "BIN_RING_ONLY"
    evidence = wheel(
        binaries=(
            binary(
                "demo/_rust.abi3.so",
                rust_crates=(RustCrate("ring", "0.17.8"), RustCrate("blake3", "1.5.1")),
            ),
        )
    )
    # Pairs, not a dict keyed by subject: a dict is last-wins, so a rule that wrongly
    # fired on both crates would be overwritten by the default rule and pass unnoticed.
    owners = {
        (finding.rule_id, finding.subject)
        for finding in run(parse_ruleset(data), evidence)
        if finding.rule_id in {"BIN_RING_ONLY", "BIN_RUST_CRYPTO_CRATE"}
    }
    assert owners == {("BIN_RING_ONLY", "ring"), ("BIN_RUST_CRYPTO_CRATE", "blake3")}


def test_a_library_entry_routes_to_the_rule_it_names() -> None:
    data = shipped_data()
    data["rule"].append(
        rule_entry("BIN_BUNDLED_SODIUM", {"kind": "bundled_library", "table": "crypto_library"})
    )
    for entry in data["crypto_library"]:
        if entry["name"] == "libsodium":
            entry["rule"] = "BIN_BUNDLED_SODIUM"
    evidence = wheel(
        binaries=(
            binary(
                "demo.libs/libsodium-9f2c1e3a.so.23",
                vendored_path=True,
                soname="libsodium-9f2c1e3a.so.23",
            ),
        )
    )
    fired = ids(run(parse_ruleset(data), evidence))
    assert "BIN_BUNDLED_SODIUM" in fired
    assert "BIN_BUNDLED_CRYPTO_LIB" not in fired


def test_a_module_entry_no_rule_claims_fires_nothing() -> None:
    """py_import routing is strict: no `rule` and no default means no finding.

    Reproduced by deleting `default = true` from PY_IMPORT_CRYPTO_MODULE, which leaves
    two py_import rules and a table full of entries neither of them claims. Matching
    those leniently would report the Mersenne Twister rule against `import ssl`.
    """
    data = shipped_data()
    for rule in data["rule"]:
        if rule["id"] == "PY_IMPORT_CRYPTO_MODULE":
            del rule["match"]["default"]
    findings = run(parse_ruleset(data), wheel(py_sites=(site("py_import", "ssl"),)))
    assert ids(findings) & {"PY_IMPORT_CRYPTO_MODULE", "PY_INSECURE_RNG"} == set()


def test_a_module_entry_that_names_its_rule_still_fires_without_a_default() -> None:
    """The other half of strictness: routing works, it is only the unclaimed that drop."""
    data = shipped_data()
    for rule in data["rule"]:
        if rule["id"] == "PY_IMPORT_CRYPTO_MODULE":
            del rule["match"]["default"]
    findings = run(parse_ruleset(data), wheel(py_sites=(site("py_import", "random"),)))
    assert one(findings, "PY_INSECURE_RNG").subject == "random"
    assert "PY_IMPORT_CRYPTO_MODULE" not in ids(findings)
