"""How findings become a single verdict class, its reasons and its conditions."""

from __future__ import annotations

import pytest

from wheel_crypto_scan.findings import Finding, Location
from wheel_crypto_scan.ruleset_loader import load_ruleset
from wheel_crypto_scan.verdict import NO_CRYPTO_DETECTED, classify


@pytest.fixture(scope="module")
def ruleset():
    return load_ruleset()


def finding(
    rule_id: str, verdict: str | None, *, review: bool = True, subject=None, relation=None
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity="high",
        category="c",
        layer="binary",
        confidence="high",
        needs_human_review=review,
        occurrences=1,
        locations=(Location(path="pkg/_ext.so", evidence="e"),),
        verdict=verdict,
        subject=subject,
        relation=relation,
    )


def test_no_findings_means_no_crypto_detected(ruleset) -> None:
    verdict = classify(ruleset, (), {})
    assert verdict.headline == NO_CRYPTO_DETECTED
    assert verdict.classes == (NO_CRYPTO_DETECTED,)


def test_a_wheel_with_nothing_found_does_not_need_review(ruleset) -> None:
    assert classify(ruleset, (), {}).needs_human_review is False


def test_the_most_severe_class_wins(ruleset) -> None:
    findings = (
        finding("BIN_BUNDLED_OPENSSL", "CONDITIONAL"),
        finding("BIN_LIBSODIUM", "NON_APPROVED_CRYPTO"),
        finding("PY_WEAK_HASH_CALL", "FIPS_BREAKING"),
    )
    assert classify(ruleset, findings, {}).headline == "NON_APPROVED_CRYPTO"


def test_every_class_that_fired_is_reported(ruleset) -> None:
    """One class is the headline; losing the others would be lossy."""
    findings = (
        finding("BIN_BUNDLED_OPENSSL", "CONDITIONAL"),
        finding("PY_WEAK_HASH_CALL", "FIPS_BREAKING"),
    )
    assert classify(ruleset, findings, {}).classes == ("FIPS_BREAKING", "CONDITIONAL")


def test_classes_follow_the_rulesets_precedence_order(ruleset) -> None:
    findings = (
        finding("BIN_NON_CRYPTO_HASH", "CONTEXT_DEPENDENT"),
        finding("BIN_OPAQUE", "OPAQUE"),
        finding("BIN_LIBSODIUM", "NON_APPROVED_CRYPTO"),
    )
    classes = classify(ruleset, findings, {}).classes
    assert list(classes) == sorted(classes, key=ruleset.precedence.index)


def test_findings_without_a_verdict_do_not_create_a_class(ruleset) -> None:
    findings = (finding("BIN_NEEDED_SYSTEM_OPENSSL", None, review=False),)
    assert classify(ruleset, findings, {}).headline == NO_CRYPTO_DETECTED


def test_an_informational_finding_alone_does_not_force_review(ruleset) -> None:
    findings = (finding("WHEEL_GENERATOR", None, review=False),)
    assert classify(ruleset, findings, {}).needs_human_review is False


def test_any_finding_that_asks_for_review_sets_the_flag(ruleset) -> None:
    findings = (finding("WHEEL_RECORD_MISMATCH", None, review=True),)
    assert classify(ruleset, findings, {}).needs_human_review is True


def test_any_verdict_at_all_sets_the_review_flag(ruleset) -> None:
    findings = (finding("BIN_NON_CRYPTO_HASH", "CONTEXT_DEPENDENT", review=False),)
    assert classify(ruleset, findings, {}).needs_human_review is True


def test_reasons_name_the_rule_and_its_subject(ruleset) -> None:
    findings = (finding("BIN_RUST_CRYPTO_CRATE", "NON_APPROVED_CRYPTO", subject="ring"),)
    assert classify(ruleset, findings, {}).reasons == ("BIN_RUST_CRYPTO_CRATE: ring",)


def test_reasons_fall_back_to_the_location_when_there_is_no_subject(ruleset) -> None:
    findings = (finding("BIN_OPAQUE", "OPAQUE"),)
    assert classify(ruleset, findings, {}).reasons == ("BIN_OPAQUE: pkg/_ext.so",)


def test_only_verdict_bearing_findings_are_listed_as_reasons(ruleset) -> None:
    findings = (
        finding("WHEEL_GENERATOR", None, review=False),
        finding("BIN_LIBSODIUM", "NON_APPROVED_CRYPTO", subject="libsodium"),
    )
    verdict = classify(ruleset, findings, {})
    assert verdict.rule_ids == ("BIN_LIBSODIUM",)


def test_linkage_is_carried_into_the_conditions(ruleset) -> None:
    verdict = classify(ruleset, (), {"openssl": "bundled"})
    assert verdict.conditions == {"openssl_linkage": "bundled"}


def test_several_libraries_appear_in_the_conditions(ruleset) -> None:
    verdict = classify(ruleset, (), {"openssl": "system", "libsodium": "bundled"})
    assert verdict.conditions == {"libsodium_linkage": "bundled", "openssl_linkage": "system"}


def test_reasons_and_rule_ids_are_sorted(ruleset) -> None:
    findings = (
        finding("BIN_LIBSODIUM", "NON_APPROVED_CRYPTO", subject="z"),
        finding("BIN_AWS_LC", "NON_APPROVED_CRYPTO", subject="a"),
    )
    verdict = classify(ruleset, findings, {})
    assert list(verdict.rule_ids) == sorted(verdict.rule_ids)
    assert list(verdict.reasons) == sorted(verdict.reasons)


def test_no_findings_means_no_relations(ruleset) -> None:
    assert classify(ruleset, (), {}).relations == ()


def test_relations_are_deduplicated_and_sorted(ruleset) -> None:
    """Sorted, not precedence-ordered: relations have no precedence the way verdict
    classes do."""
    findings = (
        finding("BIN_LIBSODIUM", "NON_APPROVED_CRYPTO", relation="outside_module"),
        finding("BIN_AWS_LC", "NON_APPROVED_CRYPTO", relation="not_specified"),
        finding("BIN_TOMCRYPT", "NON_APPROVED_CRYPTO", relation="outside_module"),
    )
    verdict = classify(ruleset, findings, {})
    assert verdict.relations == ("not_specified", "outside_module")


def test_a_finding_with_no_verdict_does_not_contribute_a_relation(ruleset) -> None:
    """`relation` on an informational finding would be a citation for a verdict this
    finding does not carry; `classify` only reads `relation` off `contributing`
    findings, the ones that have a verdict, the same filter `reasons`/`rule_ids` use."""
    findings = (finding("WHEEL_GENERATOR", None, review=False, relation="not_specified"),)
    assert classify(ruleset, findings, {}).relations == ()


def test_the_verdict_can_never_be_a_pass(ruleset) -> None:
    """The tool never says compliant, whatever the evidence looks like."""
    verdict = classify(ruleset, (finding("BIN_FIPS_PROVIDER_AWARE", None, review=False),), {})
    assert verdict.headline in ruleset.precedence
    assert "COMPLIANT" not in verdict.headline
    assert "COMPATIBLE" not in verdict.headline
