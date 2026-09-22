"""How extracted evidence becomes findings.

The engine owns no policy. Every name, symbol and pattern here comes from the shipped
ruleset, so these tests assert the matching machinery rather than the classifications.
"""

from __future__ import annotations

import tomllib
from importlib.resources import files

import pytest

from wheel_crypto_scan import engine
from wheel_crypto_scan.engine import _sbom_entry, apply_rules
from wheel_crypto_scan.errors import MEMBER_READ_ERROR
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
from wheel_crypto_scan.ruleset import CryptoLibrary, match_location
from wheel_crypto_scan.ruleset_loader import load_ruleset, parse_ruleset
from wheel_crypto_scan.verdict import classify


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
    """The dependency carries its own risk in its own record; do not double count it.
    `pynacl`'s own entry sets `relation`, `basis` and `family` (checked below so this
    assertion is not vacuous), and none of the three leaks onto this finding: a
    dependency edge is not the dependency's own risk, the same reason `severity` and
    `verdict` are withheld."""
    assert ruleset.distributions["pynacl"].relation is not None
    assert ruleset.distributions["pynacl"].basis
    assert ruleset.distributions["pynacl"].family is not None
    findings = run(ruleset, wheel(metadata=metadata(requires_dist_names=("pynacl", "numpy"))))
    finding = one(findings, "DIST_DEPENDS_ON_CRYPTO")
    assert finding.verdict is None
    assert finding.subject == "pynacl"
    assert finding.relation is None
    assert finding.basis == ()
    assert finding.family is None


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


@pytest.mark.parametrize(
    ("name", "resolved_table", "resolved_name"),
    [
        ("OpenSSL", "libraries", "openssl"),
        ("openssl_sys", "rust_crates", "openssl-sys"),
        ("SHA1-Smol", "rust_crates", "sha1_smol"),
    ],
)
def test_an_sbom_component_spelled_differently_still_reports_its_crypto_component(
    ruleset, name, resolved_table, resolved_name
) -> None:
    """`_sbom_entry` folds the component's name through `ruleset.sbom_library_key`/
    `sbom_crate_key`, so a name spelled with different case, or a crate spelled with
    `-` swapped for `_`, still resolves to its ruleset entry -- but the finding's
    subject stays the SBOM's own spelling, per "a name reported is a name read in
    full": report what the document said, not the folded key."""
    component = SbomComponent(
        name=name, version="1.0", purl=None, source="d.dist-info/sboms/a.json"
    )
    findings = run(ruleset, wheel(metadata=metadata(sbom_components=(component,))))
    finding = one(findings, "SBOM_CRYPTO_COMPONENT")
    assert finding.subject == name
    entry = getattr(ruleset, resolved_table)[resolved_name]
    assert finding.severity == entry.severity
    assert finding.verdict == entry.verdict
    if resolved_table == "libraries" or name == "openssl_sys":
        assert one(findings, "BIN_OPENSSL_LINKAGE_UNKNOWN").verdict == "OPAQUE"


def test_a_cargo_purl_sbom_component_is_rated_by_its_crate_entry(ruleset) -> None:
    """`openssl` is both a `[[crypto_library]]` (severity `high`) and one of its own
    `[[rust_crate]]` entries (severity `medium`, since the crate can link the system
    copy or vendor its own). A `pkg:cargo/...` purl says the component is the crate,
    so the finding is rated by the crate's entry, not the library's."""
    component = SbomComponent(
        name="openssl",
        version="0.10.66",
        purl="pkg:cargo/openssl@0.10.66",
        source="d.dist-info/sboms/a.json",
    )
    findings = run(ruleset, wheel(metadata=metadata(sbom_components=(component,))))
    finding = one(findings, "SBOM_CRYPTO_COMPONENT")
    assert finding.subject == "openssl"
    assert finding.severity == ruleset.rust_crates["openssl"].severity
    # Keeps this test from going vacuous if the ruleset ever aligns the two entries.
    assert finding.severity != ruleset.libraries["openssl"].severity


@pytest.mark.parametrize("purl", [None, "pkg:generic/openssl@3.0.13"], ids=["no-purl", "generic"])
def test_a_non_cargo_sbom_component_is_rated_by_the_library_entry(ruleset, purl) -> None:
    """Anything other than a `pkg:cargo/...` purl -- another purl type, or none at all
    -- keeps the rule's own table order, so `openssl` is rated by the C library's
    entry, the same as before a `pkg:cargo/...` purl was ever read."""
    component = SbomComponent(
        name="openssl", version="3.0.13", purl=purl, source="d.dist-info/sboms/a.json"
    )
    findings = run(ruleset, wheel(metadata=metadata(sbom_components=(component,))))
    finding = one(findings, "SBOM_CRYPTO_COMPONENT")
    assert finding.severity == ruleset.libraries["openssl"].severity


def test_a_cargo_purl_does_not_add_a_table_the_rule_does_not_list(ruleset) -> None:
    """The purl-driven reorder only ever moves `rust_crate` ahead of a table the rule
    already lists; it never adds `rust_crate` to a rule that never named it."""
    assert _sbom_entry(ruleset, ["crypto_library"], "openssl", "pkg:cargo/openssl@0.10.66") == (
        "crypto_library",
        ruleset.libraries["openssl"],
    )
    assert _sbom_entry(ruleset, ["rust_crate"], "openssl", None) == (
        "rust_crate",
        ruleset.rust_crates["openssl"],
    )


def test_an_sbom_naming_aws_lc_fips_sys_drops_its_aws_lc_rs_component(ruleset) -> None:
    """An SBOM component's `suppressed_by` is keyed on the SBOM document as the
    object: two crate components in the same document relate the way two crates on
    one binary object do, through the same rule-level `BIN_AWS_LC_RS_CRATE
    suppressed_by BIN_AWS_LC_FIPS` relation `Ruleset.crate_suppressors` derives from."""
    rs = SbomComponent(
        name="aws-lc-rs",
        version="1.18.1",
        purl="pkg:cargo/aws-lc-rs@1.18.1",
        source="demo-1.0.dist-info/sboms/rust.cdx.json",
    )
    fips = SbomComponent(
        name="aws-lc-fips-sys",
        version="0.14.2",
        purl="pkg:cargo/aws-lc-fips-sys@0.14.2",
        source="demo-1.0.dist-info/sboms/rust.cdx.json",
    )
    findings = run(ruleset, wheel(metadata=metadata(sbom_components=(rs, fips))))
    finding = one(findings, "SBOM_CRYPTO_COMPONENT")
    assert finding.subject == "aws-lc-fips-sys"
    assert finding.verdict == "CONDITIONAL"


def test_aws_lc_fips_sys_in_another_sbom_document_does_not_drop_aws_lc_rs(ruleset) -> None:
    """The per-document key: the same pair split across two SBOM documents shares no
    `Location.path`, so neither drops the other."""
    rs = SbomComponent(
        name="aws-lc-rs",
        version="1.18.1",
        purl="pkg:cargo/aws-lc-rs@1.18.1",
        source="demo-1.0.dist-info/sboms/a.cdx.json",
    )
    fips = SbomComponent(
        name="aws-lc-fips-sys",
        version="0.14.2",
        purl="pkg:cargo/aws-lc-fips-sys@0.14.2",
        source="demo-1.0.dist-info/sboms/b.cdx.json",
    )
    findings = run(ruleset, wheel(metadata=metadata(sbom_components=(rs, fips))))
    subjects = {f.subject for f in findings if f.rule_id == "SBOM_CRYPTO_COMPONENT"}
    assert subjects == {"aws-lc-rs", "aws-lc-fips-sys"}


def test_an_sbom_naming_aws_lc_fips_sys_keeps_aws_lc_sys(ruleset) -> None:
    """`aws-lc-sys` names the stock build and carries no relation to the FIPS crate,
    so it survives beside it in the same SBOM document."""
    stock = SbomComponent(
        name="aws-lc-sys",
        version="0.45.0",
        purl="pkg:cargo/aws-lc-sys@0.45.0",
        source="demo-1.0.dist-info/sboms/rust.cdx.json",
    )
    fips = SbomComponent(
        name="aws-lc-fips-sys",
        version="0.14.2",
        purl="pkg:cargo/aws-lc-fips-sys@0.14.2",
        source="demo-1.0.dist-info/sboms/rust.cdx.json",
    )
    findings = run(ruleset, wheel(metadata=metadata(sbom_components=(stock, fips))))
    subjects = {f.subject for f in findings if f.rule_id == "SBOM_CRYPTO_COMPONENT"}
    assert subjects == {"aws-lc-sys", "aws-lc-fips-sys"}


def test_an_entry_level_suppressed_by_is_honoured_over_sbom_components_in_one_document() -> None:
    """`Ruleset.crate_suppressors`' first source, an entry's own `suppressed_by`, is
    honoured over SBOM components the same way its second, rule-level source, is
    above. No shipped crate carries an entry-level relation, so this is synthetic."""
    data = shipped_data()
    data["rule"].append(
        rule_entry("TEST_ROUTED_CRATE", {"kind": "rust_crate", "table": "rust_crate"})
    )
    data["rust_crate"].append(
        {
            "name": "test-fips-crate",
            "verdict": "CONDITIONAL",
            "rule": "TEST_ROUTED_CRATE",
            "why": "w",
        }
    )
    data["rust_crate"].append(
        {
            "name": "test-stock-crate",
            "verdict": "NON_APPROVED_CRYPTO",
            "why": "w",
            "suppressed_by": ["test-fips-crate"],
        }
    )
    stock = SbomComponent(
        name="test-stock-crate",
        version="1.0.0",
        purl="pkg:cargo/test-stock-crate@1.0.0",
        source="a.cdx.json",
    )
    fips = SbomComponent(
        name="test-fips-crate",
        version="1.0.0",
        purl="pkg:cargo/test-fips-crate@1.0.0",
        source="a.cdx.json",
    )
    findings = run(parse_ruleset(data), wheel(metadata=metadata(sbom_components=(stock, fips))))
    subjects = {f.subject for f in findings if f.subject in {"test-stock-crate", "test-fips-crate"}}
    assert subjects == {"test-fips-crate"}


def test_an_sbom_naming_a_crate_beside_a_fips_binary_object_still_reports_it(ruleset) -> None:
    """SBOM and binary evidence never suppress each other, because they never share a
    `Location.path`: a FIPS finding on a binary object does not drop the SBOM's own
    aws-lc-rs component, the accepted cross-source over-flag."""
    rs = SbomComponent(
        name="aws-lc-rs",
        version="1.18.1",
        purl="pkg:cargo/aws-lc-rs@1.18.1",
        source="demo-1.0.dist-info/sboms/rust.cdx.json",
    )
    evidence = wheel(
        metadata=metadata(sbom_components=(rs,)),
        binaries=(binary("demo/_fips.so", rust_crates=(RustCrate("aws-lc-fips-sys", "0.14.2"),)),),
    )
    findings = run(ruleset, evidence)
    assert one(findings, "SBOM_CRYPTO_COMPONENT").subject == "aws-lc-rs"
    assert one(findings, "BIN_AWS_LC_FIPS").subject == "aws-lc-fips-sys"


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
    """`relation`/`basis` follow the same gate as `severity`/`verdict`: this posture
    link carries no verdict, so it must not carry a citation for one either. `family`
    is not verdict-tied and is inherited regardless, so the posture link is still
    counted in the crypto inventory."""
    evidence = wheel(binaries=(binary("demo/_ext.so", needed=("libcrypto.so.3",)),))
    finding = one(run(ruleset, evidence), "BIN_NEEDED_SYSTEM_OPENSSL")
    assert finding.severity == "info"
    assert finding.verdict is None
    assert finding.relation is None
    assert finding.basis == ()
    assert finding.family == ruleset.libraries["openssl"].family


def test_a_hash_renamed_dependency_is_treated_as_vendored(ruleset) -> None:
    evidence = wheel(binaries=(binary("demo/_ext.so", needed=("libcrypto-3a1f2b4c.so.3",)),))
    findings = run(ruleset, evidence)
    assert "BIN_NEEDED_MANGLED_CRYPTO" in ids(findings)
    assert "BIN_NEEDED_SYSTEM_OPENSSL" not in ids(findings)
    finding = one(findings, "BIN_NEEDED_MANGLED_CRYPTO")
    library = ruleset.libraries["openssl"]
    assert finding.relation == library.relation
    assert finding.basis == library.basis
    assert finding.family == library.family


# --- a needed entry cannot confirm itself: a resolved-but-unmangled one carries
# --- its own finding, never a silent `bundled` ------------------------------


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
    """The sharpest case: one object, named `libcrypto.so`, declaring
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
    """An absolute entry has its own short-circuit ahead of the own-stem discount
    above, so this needs a relative entry to reach that discount at all: one object
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


def test_an_absolute_basename_collision_reads_as_system(ruleset) -> None:
    """Two different objects that happen to share a basename, with the `needed` entry
    naming the absolute path. An absolute path is never resolved via search order by a
    real loader, so the second object's basename is as meaningless here as the
    declaring object's own name is in
    `test_a_self_referencing_absolute_system_dependency_is_not_manufactured_bundled` --
    the object *count* is never the right test for an absolute path.
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
    """The basename-collision residual is confined to relative entries. Two different
    objects that happen to share a basename, with the `needed` entry a relative name
    that can genuinely be resolved by search order (`DESIGN.md`'s accepted residual):
    the `bundled` classification may still be an imprecise false positive from the
    coincidence, but it must never be silent about it.
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
    imported_findings = run(ruleset, imported)
    defined_findings = run(ruleset, defined)
    assert "BIN_OPENSSL_SYMBOLS_IMPORTED" in ids(imported_findings)
    assert "BIN_OPENSSL_SYMBOLS_DEFINED" not in ids(imported_findings)
    assert "BIN_OPENSSL_SYMBOLS_DEFINED" in ids(defined_findings)
    assert "BIN_OPENSSL_SYMBOLS_IMPORTED" not in ids(defined_findings)
    # `family` comes from the matched symbol group, not from the rule or an entry:
    # `dynamic_symbol` has no table entry to read it from.
    assert one(imported_findings, "BIN_OPENSSL_SYMBOLS_IMPORTED").family == (
        ruleset.symbol_groups["openssl"].family
    )


def test_an_imported_blowfish_call_is_not_a_compiled_in_one(ruleset) -> None:
    imported = wheel(
        binaries=(
            binary(
                "demo/_ext.so",
                matched_symbols=(SymbolMatch("BF_encrypt", "bcrypt_blowfish", BINDING_IMPORTED),),
            ),
        )
    )
    defined = wheel(
        binaries=(
            binary(
                "demo/_ext.so",
                matched_symbols=(SymbolMatch("BF_encrypt", "bcrypt_blowfish", BINDING_DEFINED),),
            ),
        )
    )
    imported_findings = run(ruleset, imported)
    imported_finding = one(imported_findings, "BIN_BCRYPT_BLOWFISH_IMPORTED")
    assert imported_finding.verdict == "CONDITIONAL"
    assert imported_finding.needs_human_review is True
    assert "BIN_BCRYPT_BLOWFISH" not in ids(imported_findings)

    defined_findings = run(ruleset, defined)
    defined_finding = one(defined_findings, "BIN_BCRYPT_BLOWFISH")
    assert defined_finding.verdict == "NON_APPROVED_CRYPTO"
    assert "BIN_BCRYPT_BLOWFISH_IMPORTED" not in ids(defined_findings)


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


@pytest.mark.parametrize("binding", [BINDING_DEFINED, BINDING_IMPORTED])
def test_an_argon2_symbol_is_non_approved_either_binding(ruleset, binding) -> None:
    evidence = wheel(
        binaries=(
            binary(
                "demo/_ext.so",
                matched_symbols=(SymbolMatch("argon2id_hash_raw", "argon2", binding),),
            ),
        )
    )
    findings = run(ruleset, evidence)
    assert "BIN_ARGON2" in ids(findings)
    assert one(findings, "BIN_ARGON2").verdict == "NON_APPROVED_CRYPTO"


@pytest.mark.parametrize("binding", [BINDING_DEFINED, BINDING_IMPORTED])
def test_a_blake_symbol_alone_is_context_dependent(ruleset, binding) -> None:
    evidence = wheel(
        binaries=(
            binary(
                "demo/_ext.so",
                matched_symbols=(SymbolMatch("blake2b_init", "blake", binding),),
            ),
        )
    )
    findings = run(ruleset, evidence)
    finding = one(findings, "BIN_NON_CRYPTO_HASH")
    assert finding.verdict == "CONTEXT_DEPENDENT"
    # `family` comes from the matched symbol group, mirroring `dynamic_symbol`'s
    # sibling `binary_string` match on the same rule below.
    assert finding.family == ruleset.symbol_groups["blake"].family


def test_a_blake_string_alone_is_context_dependent(ruleset) -> None:
    evidence = wheel(
        binaries=(binary("demo/_ext.so", matched_strings=(StringMatch("blake", "BLAKE2b"),)),)
    )
    findings = run(ruleset, evidence)
    finding = one(findings, "BIN_NON_CRYPTO_HASH")
    assert finding.verdict == "CONTEXT_DEPENDENT"
    # `family` comes from the matched string group, not from the rule: `binary_string`
    # has no table entry to read it from either.
    assert finding.family == ruleset.string_groups["blake"].family


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


def test_the_fips_build_of_aws_lc_supersedes_the_aws_lc_rs_finding_on_the_same_object(
    ruleset,
) -> None:
    """aws-lc-rs and aws-lc-fips-sys each own a dedicated rule, so the relation is a
    rule-level `BIN_AWS_LC_RS_CRATE suppressed_by BIN_AWS_LC_FIPS`, not an entry-level
    `suppressed_by` naming the crate."""
    evidence = wheel(
        binaries=(
            binary(
                "demo/_rs.so",
                rust_crates=(
                    RustCrate("aws-lc-rs", "1.13.0"),
                    RustCrate("aws-lc-fips-sys", "0.13.0"),
                ),
            ),
        )
    )
    findings = run(ruleset, evidence)
    rule_ids = {finding.rule_id for finding in findings}
    assert "BIN_AWS_LC_RS_CRATE" not in rule_ids
    fips = one(findings, "BIN_AWS_LC_FIPS")
    assert fips.subject == "aws-lc-fips-sys"
    assert fips.verdict == "CONDITIONAL"


def test_aws_lc_fips_sys_in_another_object_does_not_supersede_aws_lc_rs(ruleset) -> None:
    evidence = wheel(
        binaries=(
            binary("demo/_rs.so", rust_crates=(RustCrate("aws-lc-rs", "1.13.0"),)),
            binary("demo/_fips.so", rust_crates=(RustCrate("aws-lc-fips-sys", "0.13.0"),)),
        )
    )
    findings = run(ruleset, evidence)
    owners = {(finding.rule_id, finding.subject) for finding in findings}
    assert ("BIN_AWS_LC_RS_CRATE", "aws-lc-rs") in owners
    assert ("BIN_AWS_LC_FIPS", "aws-lc-fips-sys") in owners


def test_aws_lc_sys_is_not_superseded_by_the_fips_build(ruleset) -> None:
    evidence = wheel(
        binaries=(
            binary(
                "demo/_rs.so",
                rust_crates=(
                    RustCrate("aws-lc-sys", "0.30.0"),
                    RustCrate("aws-lc-fips-sys", "0.13.0"),
                ),
            ),
        )
    )
    findings = [f for f in run(ruleset, evidence) if f.rule_id == "BIN_RUST_CRYPTO_CRATE"]
    subjects = {finding.subject: finding.verdict for finding in findings}
    assert subjects["aws-lc-sys"] == "NON_APPROVED_CRYPTO"


def test_an_entry_level_suppressed_by_is_superseded_even_when_routed_to_its_own_rule() -> None:
    """The resolved suppressor key names the finding the *named* crate's own routing
    produces, not whichever rule the suppressed entry belongs to. Routing a crate to
    a rule of its own must not silently break an entry-level `suppressed_by` naming
    it -- which is exactly what a loader that keyed on the suppressed entry's own
    owner, instead of the named crate's, would do. No shipped crate carries an
    entry-level `suppressed_by`, so this is built on a synthetic crate pair."""
    data = shipped_data()
    data["rule"].append(
        rule_entry("TEST_ROUTED_CRATE", {"kind": "rust_crate", "table": "rust_crate"})
    )
    data["rust_crate"].append(
        {
            "name": "test-fips-crate",
            "verdict": "CONDITIONAL",
            "rule": "TEST_ROUTED_CRATE",
            "why": "w",
        }
    )
    data["rust_crate"].append(
        {
            "name": "test-stock-crate",
            "verdict": "NON_APPROVED_CRYPTO",
            "why": "w",
            "suppressed_by": ["test-fips-crate"],
        }
    )
    evidence = wheel(
        binaries=(
            binary(
                "demo/_rs.so",
                rust_crates=(
                    RustCrate("test-stock-crate", "1.0.0"),
                    RustCrate("test-fips-crate", "1.0.0"),
                ),
            ),
        )
    )
    owners = {
        (finding.rule_id, finding.subject)
        for finding in run(parse_ruleset(data), evidence)
        if finding.subject in {"test-stock-crate", "test-fips-crate"}
    }
    assert owners == {("TEST_ROUTED_CRATE", "test-fips-crate")}


def test_a_fips_go_binary_does_not_hide_a_stock_one_beside_it(ruleset) -> None:
    evidence = wheel(
        binaries=(
            binary(
                "demo/fips.so",
                matched_strings=(
                    StringMatch("go_fips140", "GOFIPS140=v1.0.0"),
                    StringMatch("go_stock_crypto", "crypto/sha256."),
                ),
            ),
            binary(
                "demo/stock.so",
                matched_strings=(StringMatch("go_stock_crypto", "crypto/sha256."),),
            ),
        )
    )
    findings = run(ruleset, evidence)
    assert "BIN_GO_FIPS140" in ids(findings)
    stock = one(findings, "BIN_GO_STOCK_CRYPTO")
    assert [location.path for location in stock.locations] == ["demo/stock.so"]
    assert stock.occurrences == 1


def test_suppression_does_not_cascade() -> None:
    data = shipped_data()
    by_id = {rule["id"]: rule for rule in data["rule"]}
    by_id["BIN_GO_STOCK_CRYPTO"]["suppressed_by"] = ["BIN_GO_BORING_CRYPTO"]
    by_id["BIN_GO_BORING_CRYPTO"]["suppressed_by"] = ["BIN_GO_FIPS140"]
    evidence = wheel(
        binaries=(
            binary(
                "demo/_go.so",
                matched_strings=(
                    StringMatch("go_stock_crypto", "crypto/sha256."),
                    StringMatch("go_boring", "crypto/internal/boring"),
                    StringMatch("go_fips140", "GOFIPS140=v1.0.0"),
                ),
            ),
        )
    )
    findings = ids(run(parse_ruleset(data), evidence))
    assert findings & {"BIN_GO_STOCK_CRYPTO", "BIN_GO_BORING_CRYPTO", "BIN_GO_FIPS140"} == {
        "BIN_GO_FIPS140"
    }


def test_a_versionless_rust_crate_has_no_trailing_space_or_none_in_its_evidence(
    ruleset,
) -> None:
    """`cargo vendor` without `--versioned-dirs` names no version. The evidence text
    must read `cargo path for ring`, not `cargo path for ring None` and not
    `cargo path for ring ` with a dangling space."""
    evidence = wheel(
        binaries=(binary("demo/_rust.abi3.so", rust_crates=(RustCrate("ring", None),)),)
    )
    finding = one(run(ruleset, evidence), "BIN_RUST_CRYPTO_CRATE")
    assert finding.locations[0].evidence == "cargo path for ring"


def test_an_openssl_crate_alone_is_unresolved_linkage_beside_its_crate_finding(ruleset) -> None:
    """The record for the object `test_linkage` pins as `unknown`: the crate finding, and
    the rule saying OpenSSL is used and its provider could not be resolved."""
    evidence = wheel(
        binaries=(
            binary(
                "demo/_rust.abi3.so",
                needed=("libc.so.6",),
                dynsym_count=1,
                rust_crates=(RustCrate("openssl-sys", "0.9.117"),),
            ),
        )
    )
    findings = run(ruleset, evidence)
    crate = one(findings, "BIN_RUST_CRYPTO_CRATE")
    assert (crate.subject, crate.subject_kind, crate.verdict) == (
        "openssl-sys",
        "crate",
        "CONDITIONAL",
    )
    assert one(findings, "BIN_OPENSSL_LINKAGE_UNKNOWN").verdict == "OPAQUE"


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


def test_the_aws_lc_fips_version_string_suppresses_the_stock_aws_lc_finding(ruleset) -> None:
    """Both the aws_lc and aws_lc_fips string groups really match this run."""
    evidence = wheel(
        binaries=(
            binary(
                "demo/_ext.pyd",
                matched_strings=(
                    StringMatch("aws_lc", "AWS-LC FIPS 4.2.0"),
                    StringMatch("aws_lc_fips", "AWS-LC FIPS 4.2.0"),
                ),
            ),
        )
    )
    findings = ids(run(ruleset, evidence))
    assert "BIN_AWS_LC_FIPS" in findings
    assert "BIN_AWS_LC" not in findings


# --- linkage-driven rules ---------------------------------------------------


def test_a_table_wide_linkage_rule_inherits_the_librarys_own_relation_and_basis(
    ruleset,
) -> None:
    """`BIN_LINKED_CRYPTO_LIBRARY` matches `table = "crypto_library"`, so `inherit`
    is true and the finding takes libsodium's own `relation`/`basis`/`family`, the
    same way it already takes libsodium's own `severity`/`verdict` rather than the
    rule's."""
    evidence = wheel(binaries=(binary("demo/_ext.so", needed=("libsodium.so.23",)),))
    finding = one(run(ruleset, evidence), "BIN_LINKED_CRYPTO_LIBRARY")
    library = ruleset.libraries["libsodium"]
    assert finding.verdict == library.verdict
    assert finding.relation == library.relation
    assert finding.basis == library.basis
    assert finding.family == library.family


def test_system_only_linkage_states_the_condition_explicitly(ruleset) -> None:
    evidence = wheel(binaries=(binary("demo/_ext.so", needed=("libcrypto.so.3",)),))
    assert "DERIVED_SYSTEM_OPENSSL_ONLY" in ids(run(ruleset, evidence))


def test_static_linkage_produces_its_own_finding(ruleset) -> None:
    evidence = wheel(
        binaries=(
            binary(
                "demo/_rust.abi3.so",
                needed=("libc.so.6",),
                matched_strings=(
                    StringMatch("openssl_banner", "OpenSSL 3.0.14 4 Jun 2024"),
                    StringMatch("openssl_build_info", 'OPENSSLDIR: "/usr/lib/ssl"'),
                ),
            ),
        )
    )
    findings = ids(run(ruleset, evidence))
    assert "BIN_STATIC_OPENSSL" in findings
    assert "DERIVED_SYSTEM_OPENSSL_ONLY" not in findings


def test_system_and_static_evidence_in_one_object_never_reads_as_system_only(ruleset) -> None:
    """A `needed` match to the system library short-circuiting before the
    defined-symbol check ever runs would let a record carry both
    `DERIVED_SYSTEM_OPENSSL_ONLY` ("every piece of OpenSSL evidence points at the
    system library") and `BIN_OPENSSL_SYMBOLS_DEFINED` ("OpenSSL was compiled into
    it") at once -- a contradiction in the clean direction. The object's own posture
    is `mixed`, not `system`, so the two findings never appear together, and the
    `needed`-side finding still fires: neither observation is dropped.
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


# --- an object that read `unknown` withholds DERIVED_SYSTEM_OPENSSL_ONLY ----


_SYSTEM_SIBLING = binary("demo/_ssl.so", needed=("libc.so.6", "libssl.so.3"))

_CRATE_UNKNOWN = binary(
    "demo/_rust.abi3.so",
    needed=("libc.so.6",),
    dynsym_count=1,
    rust_crates=(RustCrate("openssl-sys", "0.9.117"),),
)
_IMPORT_UNKNOWN = binary(
    "demo/_ext.so",
    needed=("libc.so.6",),
    matched_symbols=(SymbolMatch("EVP_DigestInit_ex", "openssl", BINDING_IMPORTED),),
)
# A vendor-shaped RUNPATH the wheel cannot confirm, because the wheel was
# incompletely read (a binary-stage error on a different member) -- this object's
# own posture is `unknown`.
_UNCERTAIN_UNKNOWN = binary(
    "demo/_x.so", needed=("libcrypto.so.3",), runpath=("$ORIGIN/../demo.libs",)
)
_UNCERTAIN_ERROR = ScanError(stage=STAGE_BINARY, kind=MEMBER_READ_ERROR, message="truncated")


@pytest.mark.parametrize(
    ("unknown_object", "errors"),
    [
        pytest.param(_CRATE_UNKNOWN, (), id="crate"),
        pytest.param(_IMPORT_UNKNOWN, (), id="import"),
        pytest.param(_UNCERTAIN_UNKNOWN, (_UNCERTAIN_ERROR,), id="uncertain"),
    ],
)
def test_an_object_that_read_unknown_withholds_the_system_only_rule(
    ruleset, unknown_object, errors
) -> None:
    """`unknown_object`'s own posture is `unknown` in every shape, yet the wheel's
    `openssl_linkage` field reads `system`, because `unknown` never outvotes a definite
    posture. `DERIVED_SYSTEM_OPENSSL_ONLY`'s `why` would then be false ("every piece of
    OpenSSL evidence ... points at the system library"), so it is withheld, and
    `DERIVED_OPENSSL_UNRESOLVED_BESIDE_SYSTEM` names the object instead.
    """
    evidence = wheel(binaries=(_SYSTEM_SIBLING, unknown_object), errors=errors)
    assert resolve_linkage(ruleset, evidence)["openssl"] == "system"
    findings = run(ruleset, evidence)
    assert "DERIVED_SYSTEM_OPENSSL_ONLY" not in ids(findings)
    finding = one(findings, "DERIVED_OPENSSL_UNRESOLVED_BESIDE_SYSTEM")
    assert tuple(location.path for location in finding.locations) == (unknown_object.path,)


def test_withholding_the_system_only_rule_never_leaves_the_wheel_without_a_class(
    ruleset,
) -> None:
    """The critical case: for the import and uncertain shapes,
    `DERIVED_SYSTEM_OPENSSL_ONLY` is the only rule that would carry a verdict at all.
    Withholding it with nothing in its place would read `NO_CRYPTO_DETECTED` on a wheel
    that plainly uses OpenSSL -- exactly the direction `[linkage_policy]` exists to
    refuse -- so the complementary rule carries the verdict instead.
    """
    evidence = wheel(binaries=(_SYSTEM_SIBLING, _IMPORT_UNKNOWN))
    findings = run(ruleset, evidence)
    verdict = classify(ruleset, findings, resolve_linkage(ruleset, evidence))
    assert verdict.headline == "OPAQUE"
    assert "NO_CRYPTO_DETECTED" not in verdict.classes
    assert verdict.needs_human_review is True


def test_an_unreadable_sibling_does_not_withhold_the_system_only_rule(ruleset) -> None:
    """Pins that `_aggregate`'s unreadable-object decision stays: `unanswered` must
    never leak into `object_postures` as a per-object `unknown`.
    """
    opaque_object = binary("demo/_blob.so")
    evidence = wheel(binaries=(_SYSTEM_SIBLING, opaque_object))
    findings = ids(run(ruleset, evidence))
    assert "DERIVED_SYSTEM_OPENSSL_ONLY" in findings
    assert "DERIVED_OPENSSL_UNRESOLVED_BESIDE_SYSTEM" not in findings


def test_system_only_still_fires_beside_an_object_with_no_openssl_evidence(ruleset) -> None:
    unrelated_object = binary("demo/_other.so", needed=("libc.so.6",), dynsym_count=1)
    evidence = wheel(binaries=(_SYSTEM_SIBLING, unrelated_object))
    findings = ids(run(ruleset, evidence))
    assert "DERIVED_SYSTEM_OPENSSL_ONLY" in findings
    assert "DERIVED_OPENSSL_UNRESOLVED_BESIDE_SYSTEM" not in findings


@pytest.mark.parametrize("crate", ["openssl-src", "openssl-sys", "openssl"])
def test_an_sbom_naming_an_openssl_crate_withholds_the_system_only_rule(ruleset, crate) -> None:
    """The wheel-level SBOM signal withholds `DERIVED_SYSTEM_OPENSSL_ONLY` the same way
    a per-object `unknown` posture does: the wheel's own SBOM names OpenSSL or a crate
    that binds it, so not every piece of OpenSSL evidence points at the system library,
    even though `openssl_linkage` itself still reads `system` (`declared` never outvotes
    a definite posture). `DERIVED_OPENSSL_DECLARED_BESIDE_SYSTEM` carries the `OPAQUE`
    verdict that keeps the wheel from reading `NO_CRYPTO_DETECTED`.
    """
    component = SbomComponent(
        name=crate,
        version="1.0.0",
        purl=f"pkg:cargo/{crate}@1.0.0",
        source="demo-1.0.dist-info/sboms/a.cdx.json",
    )
    evidence = wheel(binaries=(_SYSTEM_SIBLING,), metadata=metadata(sbom_components=(component,)))
    assert resolve_linkage(ruleset, evidence)["openssl"] == "system"
    findings = run(ruleset, evidence)
    assert "DERIVED_SYSTEM_OPENSSL_ONLY" not in ids(findings)
    assert one(findings, "DERIVED_OPENSSL_DECLARED_BESIDE_SYSTEM").verdict == "OPAQUE"
    assert "DERIVED_OPENSSL_UNRESOLVED_BESIDE_SYSTEM" not in ids(findings)


@pytest.mark.parametrize("crate", ["openssl-sys", "openssl"])
def test_an_sbom_component_the_system_object_itself_carries_still_fires_the_system_only_rule(
    ruleset, crate
) -> None:
    """The normal shape of a system-linked Rust build: one object declares both a
    `needed` entry on the system library and, in its own cargo paths, the very crate
    the wheel's SBOM also names. That object already answered `system` on its own
    evidence, so the SBOM component restates what it said rather than naming a second,
    unaccounted-for copy, and must not cost `DERIVED_SYSTEM_OPENSSL_ONLY`.
    """
    rust_object = binary(
        "demo/_rust.abi3.so",
        needed=("libc.so.6", "libssl.so.3"),
        rust_crates=(RustCrate(crate, "0.9.117"),),
    )
    component = SbomComponent(
        name=crate,
        version="0.9.117",
        purl=f"pkg:cargo/{crate}@0.9.117",
        source="demo-1.0.dist-info/sboms/a.cdx.json",
    )
    evidence = wheel(binaries=(rust_object,), metadata=metadata(sbom_components=(component,)))
    assert resolve_linkage(ruleset, evidence)["openssl"] == "system"
    findings = ids(run(ruleset, evidence))
    assert "DERIVED_SYSTEM_OPENSSL_ONLY" in findings
    assert "DERIVED_OPENSSL_DECLARED_BESIDE_SYSTEM" not in findings


def test_an_sbom_component_only_a_non_system_object_carries_still_withholds_the_rule(
    ruleset,
) -> None:
    """The exemption above reads the crate-carrying object's own posture, not merely
    whether some object carries the crate at all: beside `_SYSTEM_SIBLING` (a plain
    system-linked object with no cargo paths of its own), `_CRATE_UNKNOWN` carries
    `openssl-sys` but its own posture is `unknown`, not `system`, so an SBOM naming
    that same crate still withholds `DERIVED_SYSTEM_OPENSSL_ONLY` -- the SBOM component
    is not confirmed as belonging to the object that answered `system`.
    """
    component = SbomComponent(
        name="openssl-sys",
        version="0.9.117",
        purl="pkg:cargo/openssl-sys@0.9.117",
        source="demo-1.0.dist-info/sboms/a.cdx.json",
    )
    evidence = wheel(
        binaries=(_SYSTEM_SIBLING, _CRATE_UNKNOWN), metadata=metadata(sbom_components=(component,))
    )
    assert resolve_linkage(ruleset, evidence)["openssl"] == "system"
    findings = ids(run(ruleset, evidence))
    assert "DERIVED_SYSTEM_OPENSSL_ONLY" not in findings
    assert "DERIVED_OPENSSL_DECLARED_BESIDE_SYSTEM" in findings


def test_an_sbom_naming_an_openssl_crate_beside_system_keeps_a_conditional_headline(
    ruleset,
) -> None:
    """The same evidence run through `classify`: `SBOM_CRYPTO_COMPONENT` carries
    `CONDITIONAL` for a crate this specific (`openssl-src` is the vendored build, still
    `CONDITIONAL`), which outranks `OPAQUE` in `[verdict] precedence`, so the headline
    stays `CONDITIONAL` and the wheel never reads `NO_CRYPTO_DETECTED`.
    """
    component = SbomComponent(
        name="openssl-src",
        version="300.3.1+3.3.1",
        purl="pkg:cargo/openssl-src@300.3.1+3.3.1",
        source="demo-1.0.dist-info/sboms/a.cdx.json",
    )
    evidence = wheel(binaries=(_SYSTEM_SIBLING,), metadata=metadata(sbom_components=(component,)))
    findings = run(ruleset, evidence)
    verdict = classify(ruleset, findings, resolve_linkage(ruleset, evidence))
    assert verdict.headline == "CONDITIONAL"
    assert "OPAQUE" in verdict.classes
    assert "NO_CRYPTO_DETECTED" not in verdict.classes


@pytest.mark.parametrize(
    ("name", "purl"),
    [
        ("cryptography", "pkg:generic/cryptography@42.0.5"),
        ("ring", "pkg:cargo/ring@0.17.8"),
        ("libsodium", "pkg:generic/libsodium@1.0.19"),
    ],
)
def test_an_unrelated_sbom_component_does_not_withhold_the_system_only_rule(
    ruleset, name, purl
) -> None:
    """The gate is library-specific (`declared_by_sbom`), not "any SBOM component
    present": a distribution name (`cryptography`), an unrelated crate (`ring`) or a
    different library (`libsodium`) must leave `DERIVED_SYSTEM_OPENSSL_ONLY` firing and
    the new rule silent.
    """
    component = SbomComponent(
        name=name, version="1.0", purl=purl, source="demo-1.0.dist-info/sboms/a.cdx.json"
    )
    evidence = wheel(binaries=(_SYSTEM_SIBLING,), metadata=metadata(sbom_components=(component,)))
    findings = ids(run(ruleset, evidence))
    assert "DERIVED_SYSTEM_OPENSSL_ONLY" in findings
    assert "DERIVED_OPENSSL_DECLARED_BESIDE_SYSTEM" not in findings


@pytest.mark.parametrize("sbom_names_openssl", [True, False])
@pytest.mark.parametrize("crate_unknown_sibling", [True, False])
def test_the_system_only_rule_and_its_two_complements_are_a_partition(
    ruleset, sbom_names_openssl, crate_unknown_sibling
) -> None:
    """Cross the wheel-level SBOM signal with the per-object `unknown` signal, always
    beside a system-linked sibling: `DERIVED_SYSTEM_OPENSSL_ONLY` fires exactly when
    neither complementary rule does, whatever combination of the two signals is present.
    """
    binaries = (_SYSTEM_SIBLING, _CRATE_UNKNOWN) if crate_unknown_sibling else (_SYSTEM_SIBLING,)
    metadata_evidence = None
    if sbom_names_openssl:
        component = SbomComponent(
            name="openssl-sys",
            version="0.9.117",
            purl="pkg:cargo/openssl-sys@0.9.117",
            source="demo-1.0.dist-info/sboms/a.cdx.json",
        )
        metadata_evidence = metadata(sbom_components=(component,))
    evidence = wheel(binaries=binaries, metadata=metadata_evidence)
    findings = ids(run(ruleset, evidence))
    system_only = "DERIVED_SYSTEM_OPENSSL_ONLY" in findings
    unresolved = "DERIVED_OPENSSL_UNRESOLVED_BESIDE_SYSTEM" in findings
    declared = "DERIVED_OPENSSL_DECLARED_BESIDE_SYSTEM" in findings
    assert system_only == (not unresolved and not declared)
    assert unresolved == crate_unknown_sibling
    assert declared == sbom_names_openssl


def test_an_sbom_naming_an_openssl_crate_is_unresolved_linkage_beside_its_component_finding(
    ruleset,
) -> None:
    component = SbomComponent(
        name="openssl-sys",
        version="0.9.117",
        purl="pkg:cargo/openssl-sys@0.9.117",
        source="demo-1.0.dist-info/sboms/a.cdx.json",
    )
    evidence = wheel(
        metadata=metadata(sbom_components=(component,)),
        binaries=(binary("demo/_rust.abi3.so", needed=("libc.so.6",), dynsym_count=1),),
    )
    findings = run(ruleset, evidence)
    assert one(findings, "SBOM_CRYPTO_COMPONENT").subject == "openssl-sys"
    assert one(findings, "BIN_OPENSSL_LINKAGE_UNKNOWN").verdict == "OPAQUE"


def test_linkage_moves_only_on_an_sbom_component_the_record_reports(ruleset) -> None:
    """Agreement guard between the field and the finding, checked both ways: the field
    must never move on a name `SBOM_CRYPTO_COMPONENT` reports no finding for, and every
    name `_sbom_entry` resolves through `crypto_library`/`rust_crate` must move the
    library that entry names, or every library whose `crates` lists that crate.
    """
    baseline = resolve_linkage(ruleset, wheel())
    candidates: set[str] = set()
    for library in ruleset.libraries.values():
        candidates.add(library.name)
        candidates.update(library.crates)
        candidates.update(library.sonames)
    candidates.update(ruleset.rust_crates)
    candidates.update(ruleset.distributions)
    # Case and `-`/`_` variants of real names: folding (`ruleset.sbom_library_key`/
    # `sbom_crate_key`) now resolves these to the same ruleset entry as the exact
    # spelling, so each one both moves a field and fires a finding. A mutation that
    # folds on only one side of the agreement breaks one of the two directions below.
    candidates.update({"OpenSSL", "OPENSSL-SYS", "openssl_sys", "LIBSODIUM"})
    for name in sorted(candidates):
        for purl in (None, f"pkg:cargo/{name}@0"):
            component = SbomComponent(name=name, version=None, purl=purl, source="a.cdx.json")
            evidence = wheel(metadata=metadata(sbom_components=(component,)))
            mapping = resolve_linkage(ruleset, evidence)
            moved = {
                library_name
                for library_name, value in mapping.items()
                if value == "unknown" and baseline.get(library_name) != "unknown"
            }
            subjects = {
                finding.subject
                for finding in run(ruleset, evidence)
                if finding.rule_id == "SBOM_CRYPTO_COMPONENT"
            }
            if moved:
                assert name in subjects, (
                    f"{name} moved {sorted(moved)} with no SBOM_CRYPTO_COMPONENT finding"
                )
            resolved = _sbom_entry(ruleset, ("crypto_library", "rust_crate"), name, purl)
            if resolved is None:
                continue
            _, entry = resolved
            assert name in subjects, f"{name} resolved to {entry.name} but fired no finding"
            if isinstance(entry, CryptoLibrary):
                bound = {entry.name}
            else:
                bound = {lib.name for lib in ruleset.libraries.values() if entry.name in lib.crates}
            assert bound <= moved, (
                f"{name} fired SBOM_CRYPTO_COMPONENT for {sorted(bound)} but moved {sorted(moved)}"
            )

    for library in ruleset.libraries.values():
        # `library.name` itself is excluded from this positive check when it also
        # names an unrelated `[[rust_crate]]` the library does not list in `crates`
        # (argon2, blake2): there the name arm only moves the field for a component
        # whose own `purl` does not say `pkg:cargo/...`, and the two assertions below
        # cover that split directly instead of this generic positive check.
        # `library.crates` is never ambiguous this way -- each entry was vetted onto
        # that specific library's list.
        ambiguous_own_name = (
            library.name in ruleset.rust_crates and library.name not in library.crates
        )
        names = library.crates if ambiguous_own_name else (library.name, *library.crates)
        for name in names:
            # Case and `-`/`_` variants: the folded comparison must still move the
            # field, whatever the SBOM's own spelling.
            for variant in (name, name.upper(), name.replace("-", "_")):
                component = SbomComponent(
                    name=variant, version=None, purl=None, source="a.cdx.json"
                )
                evidence = wheel(metadata=metadata(sbom_components=(component,)))
                assert resolve_linkage(ruleset, evidence)[library.name] == "unknown"
        if ambiguous_own_name:
            for variant in (library.name, library.name.upper()):
                crate_component = SbomComponent(
                    name=variant,
                    version=None,
                    purl=f"pkg:cargo/{variant}@0.0.0",
                    source="a.cdx.json",
                )
                evidence = wheel(metadata=metadata(sbom_components=(crate_component,)))
                assert resolve_linkage(ruleset, evidence).get(library.name) != "unknown"

                c_library_component = SbomComponent(
                    name=variant, version=None, purl=None, source="a.cdx.json"
                )
                evidence = wheel(metadata=metadata(sbom_components=(c_library_component,)))
                assert resolve_linkage(ruleset, evidence)[library.name] == "unknown"


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
    """usedforsecurity=True is a stronger signal than the no-keyword case, not a weaker
    one, and the match table names it explicitly rather than leaving it unmatched."""
    evidence = wheel(
        py_sites=(site("py_call", "hashlib.md5", algorithm="md5", usedforsecurity="true"),)
    )
    finding = one(run(ruleset, evidence), "PY_WEAK_HASH_CALL")
    assert finding.verdict == "FIPS_BREAKING"


def test_a_non_constant_usedforsecurity_on_a_weak_hash_is_unresolved(ruleset) -> None:
    """PY_WEAK_HASH_UNRESOLVED's own `why` claims this shape, and a second
    [[rule.match]] table is what makes the rule match it: the `why` alone matches
    nothing."""
    evidence = wheel(
        py_sites=(site("py_call", "hashlib.md5", algorithm="md5", usedforsecurity="unresolved"),)
    )
    findings = ids(run(ruleset, evidence))
    assert "PY_WEAK_HASH_UNRESOLVED" in findings
    assert "PY_WEAK_HASH_CALL" not in findings


def test_a_non_constant_usedforsecurity_on_a_strong_hash_is_not_flagged(ruleset) -> None:
    """sha256 stays approved regardless of usedforsecurity, so a non-constant flag on it
    must not borrow the weak-hash finding."""
    evidence = wheel(
        py_sites=(site("py_call", "hashlib.new", algorithm="sha256", usedforsecurity="unresolved"),)
    )
    findings = ids(run(ruleset, evidence))
    assert not findings & {
        "PY_WEAK_HASH_CALL",
        "PY_WEAK_HASH_CALL_MARKED",
        "PY_WEAK_HASH_UNRESOLVED",
    }


def test_an_algorithm_list_of_refused_matches_only_the_refused_list() -> None:
    """`algorithm_list = "refused"` and `"restricted"` name two different lists off
    `conventions`; a rule reading the wrong one would still load and match, just the
    wrong algorithms. `PY_WEAK_HASH_CALL` reads `"refused"` and `PY_RESTRICTED_HASH_CALL`
    reads `"restricted"` in the shipped ruleset, each against its own list; this test
    still needs its own rule to exercise `"refused"` in isolation, since the shipped
    rule's `targets` and match shape differ from what this test wants to hold fixed."""
    data = shipped_data()
    data["rule"].append(
        rule_entry(
            "PY_CALL_REFUSED_TEST",
            {"kind": "py_call", "targets": ["hashlib.new"], "algorithm_list": "refused"},
            layer="python",
        )
    )
    ruleset = parse_ruleset(data)
    refused_hit = wheel(py_sites=(site("py_call", "hashlib.new", algorithm="md5"),))
    restricted_hit = wheel(py_sites=(site("py_call", "hashlib.new", algorithm="sha1"),))
    assert "PY_CALL_REFUSED_TEST" in ids(run(ruleset, refused_hit))
    assert "PY_CALL_REFUSED_TEST" not in ids(run(ruleset, restricted_hit))


def test_an_algorithm_list_of_restricted_matches_only_the_restricted_list() -> None:
    data = shipped_data()
    data["rule"].append(
        rule_entry(
            "PY_CALL_RESTRICTED_TEST",
            {"kind": "py_call", "targets": ["hashlib.new"], "algorithm_list": "restricted"},
            layer="python",
        )
    )
    ruleset = parse_ruleset(data)
    refused_hit = wheel(py_sites=(site("py_call", "hashlib.new", algorithm="md5"),))
    restricted_hit = wheel(py_sites=(site("py_call", "hashlib.new", algorithm="sha1"),))
    assert "PY_CALL_RESTRICTED_TEST" not in ids(run(ruleset, refused_hit))
    assert "PY_CALL_RESTRICTED_TEST" in ids(run(ruleset, restricted_hit))


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


# --- location-class drift ----------------------------------------------------


def _location_class(evidence: Evidence, path: str) -> str:
    """Classify a `Location.path` the same way `MATCHER_LOCATIONS` names it, read
    back off the evidence that produced it rather than trusted by construction."""
    meta = evidence.metadata
    if meta is not None and meta.dist_info_dir:
        if path == meta.dist_info_dir:
            return "dist_info"
        if path == f"{meta.dist_info_dir}/METADATA":
            return "metadata_file"
        if path == f"{meta.dist_info_dir}/WHEEL":
            return "wheel_file"
        if path.startswith(f"{meta.dist_info_dir}/sboms/"):
            return "sbom"
    if path == evidence.filename:
        return "wheel"
    if any(b.path == path for b in evidence.binaries):
        return "object"
    if any(s.path == path for s in evidence.py_sites):
        return "python_source"
    return "unknown"


def test_every_matcher_locates_where_its_declared_location_says(ruleset) -> None:
    """`MATCHER_LOCATIONS`, and `match_location` for a `linkage` match, declare which
    class of `Location.path` each match table's hits carry. This fires every kind the
    shipped ruleset uses, through the same dispatch `engine.apply_rules` does but one
    match table at a time, and checks each hit's own `location.path` against that
    declaration instead of trusting it by construction.
    """
    # pylint: disable=protected-access
    index = engine._SonameIndex(ruleset)

    dist_info_dir = "PyNaCl-1.5.0.dist-info"
    metadata_evidence = wheel(
        metadata=metadata(
            name="PyNaCl",
            version="1.5.0",
            requires_dist_names=("cryptography",),
            generator_raw="bdist_wheel (0.41.0)",
            record_mismatches=(f"{dist_info_dir}/extra.txt",),
            sbom_components=(
                SbomComponent(
                    name="openssl",
                    version="3.0.14",
                    purl=None,
                    source=f"{dist_info_dir}/sboms/a.json",
                ),
            ),
        ),
        artifacts=ArtifactInventory(
            py_files=0, pyc_files=3, source_available=False, binaries_truncated=True
        ),
        errors=(ScanError(stage=STAGE_BINARY, kind="elf_parse_error", message="x", path="bad.so"),),
    )

    binary_evidence = wheel(
        binaries=(
            binary(
                "demo.libs/libcrypto-3a1f2b4c.so.3",
                vendored_path=True,
                soname="libcrypto-3a1f2b4c.so.3",
                matched_strings=(StringMatch("openssl_banner", "OpenSSL 3.0.14 4 Jun 2024"),),
            ),
            binary("demo/_needed.so", needed=("libcrypto-3a1f2b4c.so.3",)),
            binary(
                "demo/_symbols.so",
                matched_symbols=(SymbolMatch("sodium_init", "libsodium", BINDING_IMPORTED),),
            ),
            binary("demo/_strings.so", matched_strings=(StringMatch("boringssl", "BoringSSL"),)),
            binary("demo/_rust.so", rust_crates=(RustCrate("ring", "0.17.8"),)),
            binary("demo/_opaque.so"),
            binary("demo/_partial.pyd", format=FORMAT_PE, partial_analysis=True, needed=("a",)),
        )
    )

    crate_only = binary(
        "demo/_crate_only.so",
        needed=("libc.so.6",),
        dynsym_count=1,
        rust_crates=(RustCrate("openssl-sys", "0.9.117"),),
    )
    system_sibling = binary("demo/_system.so", needed=("libc.so.6", "libssl.so.3"))
    linkage_unknown_evidence = wheel(binaries=(crate_only,))
    linkage_object_values_evidence = wheel(binaries=(system_sibling, crate_only))

    python_evidence = wheel(
        py_sites=(
            site("py_import", "nacl"),
            site("py_call", "hashlib.md5", algorithm="md5", usedforsecurity="absent"),
            site("py_attr", "minimum_version"),
            site("py_constant", "ssl.PROTOCOL_TLSv1"),
            site("py_ctypes_load", "libcrypto", library="libcrypto.so.3"),
        )
    )

    fired_kinds: set[str] = set()
    object_values_seen = False
    wheel_linkage_seen = False

    for evidence in (
        metadata_evidence,
        binary_evidence,
        linkage_unknown_evidence,
        linkage_object_values_evidence,
        python_evidence,
    ):
        linkage = resolve_linkage(ruleset, evidence)
        for rule in ruleset.rules:
            for match in rule.matches:
                matcher = engine._MATCHERS[match["kind"]]
                for hit in matcher(rule, match, ruleset, evidence, linkage, index):
                    fired_kinds.add(match["kind"])
                    if match["kind"] == "linkage":
                        if "object_values" in match:
                            object_values_seen = True
                        else:
                            wheel_linkage_seen = True
                    expected = match_location(match)
                    if expected is None:
                        continue
                    got = _location_class(evidence, hit.location.path)
                    assert got == expected, (rule.id, match["kind"], hit.location.path)

    used_kinds_with_a_location = {
        match["kind"]
        for rule in ruleset.rules
        for match in rule.matches
        if match_location(match) is not None
    }
    assert used_kinds_with_a_location <= fired_kinds
    assert object_values_seen
    assert wheel_linkage_seen
