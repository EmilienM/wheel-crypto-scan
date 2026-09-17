"""Behaviour of the ruleset loader, its validation and the compiled scan patterns."""

from __future__ import annotations

import re
from typing import Any

import pytest

from wheel_crypto_scan.errors import RulesetError
from wheel_crypto_scan.ruleset import load_ruleset, parse_ruleset


def minimal(**overrides: Any) -> dict[str, Any]:
    """A ruleset with one rule, small enough to see what a test is changing."""
    data: dict[str, Any] = {
        "ruleset_version": "test",
        "verdict": {"precedence": ["NON_APPROVED_CRYPTO", "NO_CRYPTO_DETECTED"]},
        "limits": {
            "max_locations_per_finding": 10,
            "max_symbols_per_binary": 64,
            "max_strings_per_binary": 64,
            "max_rust_crates_per_binary": 128,
            "max_evidence_chars": 200,
            "min_string_length": 4,
        },
        "conventions": {
            "vendor_dir_globs": ["*.libs", ".dylibs"],
            "mangled_soname_regex": r"^(?P<stem>lib.+)-(?P<hash>[0-9a-f]{6,32})$",
            "cargo_path_regex": r"cargo/registry/src/[^/]+/(?P<name>[a-z-]+)-(?P<version>[0-9.]+)/",
            "weak_hash_algorithms": ["md5", "sha1"],
        },
        "crypto_distribution": [
            {"name": "PyNaCl", "rule": "DIST_NON_APPROVED_CRYPTO", "why": "libsodium primitives"}
        ],
        "crypto_library": [
            {
                "name": "openssl",
                "sonames": ["libcrypto", "libssl"],
                "verdict": "NON_APPROVED_CRYPTO",
                "severity": "high",
                "why": "the important one",
            }
        ],
        "symbol_group": [
            {"name": "openssl", "prefixes": ["EVP_"], "exact": ["RAND_bytes"], "why": "api"}
        ],
        "string_group": [{"name": "openssl_banner", "substrings": ["OpenSSL 3."], "why": "banner"}],
        "rust_crate": [
            {"name": "ring", "verdict": "NON_APPROVED_CRYPTO", "severity": "high", "why": "own"}
        ],
        "python_module": [{"name": "nacl", "severity": "high", "why": "libsodium"}],
        "ctypes_library": [{"substrings": ["libcrypto"], "why": "loaded by name"}],
        "rule": [
            {
                "id": "DIST_NON_APPROVED_CRYPTO",
                "layer": "metadata",
                "category": "crypto-implementation",
                "severity": "high",
                "confidence": "high",
                "verdict": "NON_APPROVED_CRYPTO",
                "needs_human_review": True,
                "title": "t",
                "why": "w",
                "match": {"kind": "dist_name", "table": "crypto_distribution"},
            }
        ],
    }
    data.update(overrides)
    return data


# --- loading the shipped ruleset -------------------------------------------


def test_loads_the_shipped_ruleset() -> None:
    ruleset = load_ruleset()
    assert ruleset.version == "1"
    assert len(ruleset.rules) > 20


def test_shipped_ruleset_knows_the_bundled_openssl_rule() -> None:
    rule = load_ruleset().rule("BIN_BUNDLED_OPENSSL")
    assert rule.verdict == "CONDITIONAL"
    assert rule.match["kind"] == "bundled_library"


def test_rules_can_be_selected_by_matcher_kind() -> None:
    ruleset = load_ruleset()
    ids = {rule.id for rule in ruleset.rules_for_kind("linkage")}
    assert ids == {"BIN_STATIC_OPENSSL", "DERIVED_SYSTEM_OPENSSL_ONLY"}


def test_unknown_rule_id_raises_key_error() -> None:
    with pytest.raises(KeyError):
        load_ruleset().rule("NO_SUCH_RULE")


# --- validation -------------------------------------------------------------


def test_duplicate_rule_ids_are_rejected() -> None:
    data = minimal()
    data["rule"].append(dict(data["rule"][0]))
    with pytest.raises(RulesetError, match="duplicate rule id"):
        parse_ruleset(data)


def test_unknown_matcher_kind_is_rejected() -> None:
    data = minimal()
    data["rule"][0]["match"] = {"kind": "read_the_authors_mind"}
    with pytest.raises(RulesetError, match="unknown matcher kind"):
        parse_ruleset(data)


def test_unknown_verdict_class_is_rejected() -> None:
    data = minimal()
    data["rule"][0]["verdict"] = "COMPLIANT"
    with pytest.raises(RulesetError, match="unknown verdict"):
        parse_ruleset(data)


def test_table_entry_naming_a_missing_rule_is_rejected() -> None:
    data = minimal()
    data["crypto_distribution"][0]["rule"] = "DIST_TYPO"
    with pytest.raises(RulesetError, match="unknown rule"):
        parse_ruleset(data)


def test_rule_naming_a_missing_table_is_rejected() -> None:
    data = minimal()
    data["rule"][0]["match"]["table"] = "crypto_distributions"
    with pytest.raises(RulesetError, match="unknown table"):
        parse_ruleset(data)


def test_rule_naming_a_missing_symbol_group_is_rejected() -> None:
    data = minimal()
    data["rule"][0]["match"] = {"kind": "dynamic_symbol", "group": "openssl3", "binding": "any"}
    with pytest.raises(RulesetError, match="unknown symbol group"):
        parse_ruleset(data)


def test_rule_naming_a_missing_library_is_rejected() -> None:
    data = minimal()
    data["rule"][0]["match"] = {"kind": "bundled_library", "library": "opensssl"}
    with pytest.raises(RulesetError, match="unknown library"):
        parse_ruleset(data)


def test_unknown_scan_error_kind_is_rejected() -> None:
    data = minimal()
    data["rule"][0]["match"] = {"kind": "scan_error", "error_kinds": ["cosmic_ray"]}
    with pytest.raises(RulesetError, match="unknown error kind"):
        parse_ruleset(data)


def test_two_default_rules_for_one_table_are_rejected() -> None:
    data = minimal()
    data["rule"][0]["match"]["default"] = True
    second = dict(data["rule"][0])
    second["id"] = "DIST_OTHER"
    second["match"] = {"kind": "dist_name", "table": "crypto_distribution", "default": True}
    data["rule"].append(second)
    with pytest.raises(RulesetError, match="more than one default rule"):
        parse_ruleset(data)


def test_missing_required_rule_field_is_rejected() -> None:
    data = minimal()
    del data["rule"][0]["severity"]
    with pytest.raises(RulesetError, match="severity"):
        parse_ruleset(data)


def test_error_message_names_the_offending_rule() -> None:
    data = minimal()
    data["rule"][0]["verdict"] = "COMPLIANT"
    with pytest.raises(RulesetError, match="DIST_NON_APPROVED_CRYPTO"):
        parse_ruleset(data)


# --- table access -----------------------------------------------------------


def test_distribution_names_are_canonicalised() -> None:
    """PyNaCl, pynacl and py_nacl are one project; the ruleset may spell it naturally."""
    ruleset = parse_ruleset(minimal())
    assert "pynacl" in ruleset.distributions
    assert ruleset.distributions["pynacl"].rule == "DIST_NON_APPROVED_CRYPTO"


def test_shipped_distribution_names_are_canonicalised() -> None:
    assert "pyopenssl" in load_ruleset().distributions


def test_table_entry_inherits_the_rule_severity_when_it_sets_none() -> None:
    ruleset = parse_ruleset(minimal())
    assert ruleset.distributions["pynacl"].severity is None


# --- conventions ------------------------------------------------------------


@pytest.mark.parametrize(
    ("soname", "base", "mangled"),
    [
        ("libcrypto.so.3", "libcrypto", False),
        ("libcrypto.so", "libcrypto", False),
        ("libssl.so.1.1", "libssl", False),
        ("libcrypto-3a1f2b4c.so.3", "libcrypto", True),
        ("libssl-3a1f2b4c.so.3", "libssl", True),
        ("libssl.3.dylib", "libssl", False),
        ("libcrypto-3a1f2b4c.dylib", "libcrypto", True),
        ("libsecp256k1.so.0", "libsecp256k1", False),
    ],
)
def test_soname_normalisation(soname: str, base: str, mangled: bool) -> None:
    conventions = parse_ruleset(minimal()).conventions
    result = conventions.normalise_soname(soname)
    assert (result.base, result.mangled) == (base, mangled)


@pytest.mark.parametrize(
    ("path", "vendored"),
    [
        ("cryptography.libs/libcrypto-3a1f2b4c.so.3", True),
        ("pkg/.dylibs/libssl.3.dylib", True),
        ("cryptography/hazmat/bindings/_rust.abi3.so", False),
        ("pkg/libs/libfoo.so", False),
    ],
)
def test_vendor_directory_detection(path: str, vendored: bool) -> None:
    conventions = parse_ruleset(minimal()).conventions
    assert conventions.is_vendor_path(path) is vendored


def test_weak_hash_algorithms_are_available_for_call_matching() -> None:
    conventions = parse_ruleset(minimal()).conventions
    assert "md5" in conventions.weak_hash_algorithms
    assert "sha256" not in conventions.weak_hash_algorithms


# --- compiled scan patterns -------------------------------------------------


def test_symbol_group_matches_a_prefix() -> None:
    patterns = parse_ruleset(minimal()).compile_patterns()
    assert patterns.symbol_groups_for("EVP_DigestInit_ex") == ("openssl",)


def test_symbol_group_matches_an_exact_name() -> None:
    patterns = parse_ruleset(minimal()).compile_patterns()
    assert patterns.symbol_groups_for("RAND_bytes") == ("openssl",)


def test_symbol_group_ignores_an_unrelated_name() -> None:
    patterns = parse_ruleset(minimal()).compile_patterns()
    assert patterns.symbol_groups_for("PyInit__foo") == ()


def test_symbol_group_results_are_sorted() -> None:
    """Two groups can claim one symbol; the order must not depend on table order."""
    data = minimal()
    data["symbol_group"].insert(0, {"name": "zzz", "prefixes": ["EVP_"], "exact": [], "why": "x"})
    patterns = parse_ruleset(data).compile_patterns()
    assert patterns.symbol_groups_for("EVP_DigestInit_ex") == ("openssl", "zzz")


def test_string_group_exposes_a_compiled_pattern() -> None:
    patterns = parse_ruleset(minimal()).compile_patterns()
    group = patterns.string_group("openssl_banner")
    assert isinstance(group.pattern, re.Pattern)
    assert group.pattern.search("OpenSSL 3.0.14 4 Jun 2024")


def test_string_group_pattern_escapes_regex_metacharacters() -> None:
    """Substrings are literal text. A dot must not match any character."""
    patterns = parse_ruleset(minimal()).compile_patterns()
    assert patterns.string_group("openssl_banner").pattern.search("OpenSSL 3x0") is None


def test_cargo_path_regex_extracts_crate_and_version() -> None:
    patterns = parse_ruleset(minimal()).compile_patterns()
    match = patterns.cargo_path_regex.search(
        "/root/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ring-0.17.8/src/lib.rs"
    )
    assert match is not None
    assert (match.group("name"), match.group("version")) == ("ring", "0.17.8")


def test_python_module_names_are_available_to_the_ast_scanner() -> None:
    patterns = parse_ruleset(minimal()).compile_patterns()
    assert "nacl" in patterns.py_modules


def test_ctypes_substrings_are_available_to_the_ast_scanner() -> None:
    patterns = parse_ruleset(minimal()).compile_patterns()
    assert "libcrypto" in patterns.ctypes_substrings


def test_shipped_patterns_expose_the_python_call_targets() -> None:
    patterns = load_ruleset().compile_patterns()
    assert "hashlib.md5" in patterns.py_call_targets
    assert "hashlib.new" in patterns.py_call_targets


def test_shipped_patterns_expose_tls_attributes_and_constants() -> None:
    patterns = load_ruleset().compile_patterns()
    assert "check_hostname" in patterns.py_attributes
    assert "ssl.CERT_NONE" in patterns.py_constants


def test_compiled_pattern_sequences_are_sorted() -> None:
    """Extractors iterate these; unsorted input would leak into the output order."""
    patterns = load_ruleset().compile_patterns()
    assert list(patterns.py_call_targets) == sorted(patterns.py_call_targets)
    assert list(patterns.py_modules) == sorted(patterns.py_modules)
    assert [g.name for g in patterns.symbol_groups] == sorted(
        g.name for g in patterns.symbol_groups
    )
