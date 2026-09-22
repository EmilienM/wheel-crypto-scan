"""Behaviour of the ruleset loader, its validation and the compiled scan patterns."""

from __future__ import annotations

import ast
import copy
import inspect
import re
import tomllib
from dataclasses import fields
from importlib.resources import files
from typing import Any

import pytest

from wheel_crypto_scan import engine, ruleset_loader
from wheel_crypto_scan.errors import RulesetError
from wheel_crypto_scan.evidence import ArtifactInventory, Evidence, PySite
from wheel_crypto_scan.linkage import resolve_linkage
from wheel_crypto_scan.ruleset import (
    DEFAULTABLE_TABLES,
    ENTRY_TABLES,
    MATCH_KEYS,
    MATCHER_KINDS,
    MATCHER_LOCATIONS,
    ROUTED_KINDS,
    SymbolGroup,
    sbom_crate_key,
    sbom_library_key,
)
from wheel_crypto_scan.ruleset_loader import load_ruleset, parse_ruleset


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
            # Kept identical to the shipped ruleset on purpose: the soname table below
            # is the unit test for this reduction, and a helper that drifts from what
            # ships turns that whole table into a test of a pattern nobody uses.
            "windows_version_suffix_regex": (
                r"^(?P<stem>.+?)-(?P<version>[0-9]+(_[0-9]+)?)(-(?P<decoration>[A-Za-z0-9_]+))?$"
            ),
            "cargo_path_regex": r"cargo/registry/src/[^/]+/(?P<name>[a-z-]+)-(?P<version>[0-9.]+)/",
            "cargo_vendor_path_regex": r"vendor/(?P<name>[a-z-]+)(?:-(?P<version>[0-9.]+))?/",
            "weak_hash_algorithms": ["md5", "sha1"],
            "library_suffixes": [".so", ".dylib", ".dll", ".pyd"],
            "windows_library_suffixes": [".dll", ".pyd"],
            "go_boring_group": "go_boring",
            "go_stock_group": "go_stock_crypto",
            "go_fips140_group": "go_fips140",
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
        # The two Go groups are here because `[conventions]` names them: a ruleset whose
        # go_boring_group/go_stock_group point at nothing is refused at load time.
        "string_group": [
            {"name": "openssl_banner", "substrings": ["OpenSSL 3."], "why": "banner"},
            {"name": "go_boring", "substrings": ["crypto/internal/boring"], "why": "boring"},
            {"name": "go_stock_crypto", "substrings": ["crypto/sha256."], "why": "stock"},
            {"name": "go_fips140", "substrings": ["GOFIPS140="], "why": "fips module"},
        ],
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
            },
            {
                "id": "SBOM_CRYPTO_COMPONENT",
                "layer": "metadata",
                "category": "bundled-crypto",
                "severity": "high",
                "confidence": "high",
                "needs_human_review": True,
                "title": "t",
                "why": "w",
                "match": {"kind": "sbom_component", "tables": ["crypto_library", "rust_crate"]},
            },
        ],
    }
    data.update(overrides)
    return data


def rust_crate_ruleset() -> dict[str, Any]:
    """`minimal()` plus a default `[[rust_crate]]` rule and a second crate, `boring`.

    Both `ring` and `boring` fall to the default rule, so a `suppressed_by` naming
    either resolves to an owner without any entry naming `rule` explicitly.
    """
    data = minimal()
    data["rule"].append(
        dict(
            data["rule"][0],
            id="BIN_RUST_CRYPTO_CRATE",
            layer="binary",
            match={"kind": "rust_crate", "table": "rust_crate", "default": True},
        )
    )
    data["rust_crate"].append({"name": "boring", "severity": "high", "why": "boring"})
    return data


# --- loading the shipped ruleset -------------------------------------------


def test_loads_the_shipped_ruleset() -> None:
    ruleset = load_ruleset()
    assert ruleset.version == "33"
    assert len(ruleset.rules) > 20


def test_shipped_ruleset_knows_the_bundled_openssl_rule() -> None:
    rule = load_ruleset().rule("BIN_BUNDLED_OPENSSL")
    assert rule.verdict == "CONDITIONAL"
    assert [match["kind"] for match in rule.matches] == ["bundled_library"]


def test_every_version_anchored_group_names_every_major() -> None:
    """A major a group does not name is evidence that reads as absent.

    The groups are derived rather than listed: naming them here would be the same
    enumeration this test exists to police, and a third version-anchored group added
    later would be policed by nobody. A group qualifies when a substring ends in a
    single digit and a dot, which is what `openssl_banner` and `nss` are built from.

    A banner group that names only the majors that have shipped misses the next one
    with nothing failing: cryptography's own PyPI wheels compile OpenSSL 4 in. The
    negative case pins the cheaper alternative out: the product name and a space, with
    no digit, also claims prose such as OpenSSL's own "OpenSSL 3's legacy provider
    failed to load", which a wheel linking the system library carries too.
    """
    ruleset = load_ruleset()
    anchored = re.compile(r"^(?P<product>.+ )[0-9]\.$")
    products: dict[str, set[str]] = {}
    for name, group in ruleset.string_groups.items():
        for substring in group.substrings:
            match = anchored.match(substring)
            if match is not None:
                products.setdefault(name, set()).add(match.group("product"))
    assert products, "no version-anchored group found; has the spelling changed?"

    patterns = ruleset.compile_patterns().binary
    for name, found in sorted(products.items()):
        pattern = patterns.string_group(name).pattern
        for product in sorted(found):
            for major in range(10):
                assert pattern.search(f"{product}{major}.0.14 4 Jun 2024"), (name, major)
            assert pattern.search(f"{product}3's legacy provider failed to load") is None


@pytest.mark.parametrize(
    ("crate", "verdict"),
    [
        ("openssl-src", "CONDITIONAL"),
        ("openssl-sys", "CONDITIONAL"),
        ("boring", "NON_APPROVED_CRYPTO"),
        ("boring-sys", "NON_APPROVED_CRYPTO"),
        ("sha-1", "NON_APPROVED_CRYPTO"),
        ("sha1_smol", "NON_APPROVED_CRYPTO"),
        ("md5", "NON_APPROVED_CRYPTO"),
        ("sha3", "CONDITIONAL"),
    ],
)
def test_the_shipped_crate_table_decides_what_it_says_it_decides(crate: str, verdict: str) -> None:
    """These entries are reach, and reach nothing holds can be flipped or deleted
    without a test moving. An entry's verdict is the whole of what it decides, so that
    is what is pinned: `openssl-src` says a vendored OpenSSL build is a condition to
    confirm, not a non-approved primitive, and the two spellings of
    SHA-1 and of MD5 have to agree with each other or a build pinned to the older name
    reads differently from the same code under the newer one."""
    assert load_ruleset().rust_crates[crate].verdict == verdict


@pytest.mark.parametrize(
    "symbol",
    [
        pytest.param("ossl_x25519", id="openssl3-provider-ossl_x25519"),
        pytest.param(
            "ossl_x25519_public_from_private",
            id="openssl3-provider-ossl_x25519_public_from_private",
        ),
        pytest.param("ossl_ed25519_sign", id="openssl3-provider-ossl_ed25519_sign"),
        pytest.param("ossl_ed25519_verify", id="openssl3-provider-ossl_ed25519_verify"),
        pytest.param(
            "ossl_ed25519_public_from_private",
            id="openssl3-provider-ossl_ed25519_public_from_private",
        ),
        pytest.param("X25519", id="openssl111-X25519"),
        pytest.param("X25519_public_from_private", id="openssl111-X25519_public_from_private"),
        pytest.param("ED25519_sign", id="openssl111-ED25519_sign"),
        pytest.param("ED25519_verify", id="openssl111-ED25519_verify"),
        pytest.param("ED25519_public_from_private", id="openssl111-ED25519_public_from_private"),
        pytest.param("x25519_fe51_mul", id="openssl-field-helper-x25519_fe51_mul"),
        pytest.param("x25519_fe64_mul", id="openssl-field-helper-x25519_fe64_mul"),
    ],
)
def test_the_shipped_curve25519_group_claims_what_the_docs_say(symbol: str) -> None:
    """The design docs and the `BIN_CURVE25519` `why` tell a reviewer which OpenSSL
    names reach this rule, so the group has to keep agreeing with them: every spelling
    OpenSSL itself uses for X25519/Ed25519, on 1.1.1 and on 3.x, and the internal
    field-arithmetic helpers both versions define on their assembly paths. Changing
    either side means changing the other.
    """
    patterns = load_ruleset().compile_patterns().binary
    assert patterns.symbol_groups_for(symbol) == ("curve25519",)


@pytest.mark.parametrize(
    "symbol",
    [
        pytest.param("ossl_x448", id="different-curve-openssl3"),
        pytest.param("ossl_ed448_sign", id="different-curve-openssl3"),
        pytest.param("X448", id="different-curve-openssl111"),
        pytest.param("ED448_sign", id="different-curve-openssl111"),
        pytest.param("X25519x", id="not-a-prefix-match-X25519x"),
        pytest.param("ossl_x25519x", id="not-a-prefix-match-ossl_x25519x"),
    ],
)
def test_the_shipped_curve25519_group_stays_scoped_to_curve25519(symbol: str) -> None:
    """Pins the scope to Curve25519 and guards against `X25519`/`ossl_x25519` being
    turned into a bare prefix: X448 and Ed448 are a different curve and must not match
    just because their names share a prefix with X25519/Ed25519.
    """
    patterns = load_ruleset().compile_patterns().binary
    assert patterns.symbol_groups_for(symbol) == ()


def test_rules_can_be_selected_by_matcher_kind() -> None:
    """Selection yields (rule, match) pairs: a rule may be reached through two kinds."""
    ruleset = load_ruleset()
    selected = ruleset.matches_for_kind("linkage")
    assert {rule.id for rule, _ in selected} == {
        "BIN_STATIC_OPENSSL",
        "DERIVED_SYSTEM_OPENSSL_ONLY",
        "DERIVED_OPENSSL_UNRESOLVED_BESIDE_SYSTEM",
        "BIN_LINKED_CRYPTO_LIBRARY",
        "BIN_OPENSSL_LINKAGE_UNKNOWN",
    }
    assert {match["kind"] for _, match in selected} == {"linkage"}


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


def test_a_rule_can_carry_several_match_tables() -> None:
    """`[[rule.match]]` is OR: one concern, one rule id, two ways of spotting it."""
    data = minimal()
    data["rule"][0]["match"] = [
        {"kind": "dist_name", "table": "crypto_distribution"},
        {"kind": "requires_dist", "table": "crypto_distribution"},
    ]
    ruleset = parse_ruleset(data)
    rule = ruleset.rule("DIST_NON_APPROVED_CRYPTO")
    assert [match["kind"] for match in rule.matches] == ["dist_name", "requires_dist"]
    for kind in ("dist_name", "requires_dist"):
        selected = ruleset.matches_for_kind(kind)
        assert [found.id for found, _ in selected] == ["DIST_NON_APPROVED_CRYPTO"]
        assert [match["kind"] for _, match in selected] == [kind]


def test_an_unknown_kind_among_several_matches_is_rejected() -> None:
    data = minimal()
    data["rule"][0]["match"] = [
        {"kind": "dist_name", "table": "crypto_distribution"},
        {"kind": "read_the_authors_mind"},
    ]
    with pytest.raises(RulesetError, match="unknown matcher kind"):
        parse_ruleset(data)


def test_an_unknown_linkage_exemption_is_rejected() -> None:
    """A typo here loads clean and exempts nothing, and the symptom looks like success."""
    data = minimal(linkage_policy={"why": "w", "exclude_reasons": ["pe_ordinal_imports"]})
    with pytest.raises(RulesetError, match="unknown partial reason"):
        parse_ruleset(data)


def test_an_unknown_key_in_the_linkage_policy_is_rejected() -> None:
    """`excluded_reasons` parses, exempts nothing, and looks exactly like it worked."""
    data = minimal(linkage_policy={"why": "w", "excluded_reasons": ["pe_ordinal_import"]})
    with pytest.raises(RulesetError, match="unknown keys"):
        parse_ruleset(data)


# --- unknown keys are refused on every table, not just [linkage_policy] -------------


def _shipped_data() -> dict[str, Any]:
    resource = files("wheel_crypto_scan").joinpath("data/ruleset.toml")
    return tomllib.loads(resource.read_text(encoding="utf-8"))


def _mutate_shipped_rule_match(rule_id: str, old_key: str, new_key: str) -> dict[str, Any]:
    """The shipped ruleset, with one named rule's match key renamed."""
    data = copy.deepcopy(_shipped_data())
    for rule in data["rule"]:
        if rule["id"] == rule_id:
            rule["match"][new_key] = rule["match"].pop(old_key)
            return data
    raise AssertionError(f"no shipped rule {rule_id!r}")


@pytest.mark.parametrize(
    ("case", "mutate", "key"),
    [
        (
            "supressed_by on a rule",
            lambda: {**minimal(), "rule": [{**minimal()["rule"][0], "supressed_by": []}]},
            "supressed_by",
        ),
        (
            "exclude_object_valu on a shipped rule's match",
            lambda: _mutate_shipped_rule_match(
                "DERIVED_SYSTEM_OPENSSL_ONLY", "exclude_object_values", "exclude_object_valu"
            ),
            "exclude_object_valu",
        ),
        (
            "verdit on a crypto_library entry",
            lambda: minimal(crypto_library=[{**minimal()["crypto_library"][0], "verdit": "x"}]),
            "verdit",
        ),
        (
            "severty on a rust_crate entry",
            lambda: minimal(rust_crate=[{**minimal()["rust_crate"][0], "severty": "high"}]),
            "severty",
        ),
        (
            "extra key on python_module",
            lambda: minimal(python_module=[{**minimal()["python_module"][0], "bogus": True}]),
            "bogus",
        ),
        (
            "extra key on crypto_distribution",
            lambda: minimal(
                crypto_distribution=[{**minimal()["crypto_distribution"][0], "bogus": True}]
            ),
            "bogus",
        ),
        (
            "suppressed_by on a string_group",
            lambda: minimal(
                string_group=[{**minimal()["string_group"][0], "suppressed_by": []}]
                + minimal()["string_group"][1:]
            ),
            "suppressed_by",
        ),
        (
            "extra key on symbol_group",
            lambda: minimal(symbol_group=[{**minimal()["symbol_group"][0], "bogus": True}]),
            "bogus",
        ),
        (
            "extra key on ctypes_library",
            lambda: minimal(ctypes_library=[{**minimal()["ctypes_library"][0], "bogus": True}]),
            "bogus",
        ),
        (
            "extra key in [conventions]",
            lambda: minimal(conventions={**minimal()["conventions"], "bogus": True}),
            "bogus",
        ),
        (
            "extra key in [verdict]",
            lambda: minimal(verdict={**minimal()["verdict"], "bogus": True}),
            "bogus",
        ),
        (
            "extra key in [limits], not a TypeError",
            lambda: minimal(limits={**minimal()["limits"], "bogus": True}),
            "bogus",
        ),
        (
            "a top-level linkage_polcy table",
            lambda: {**minimal(), "linkage_polcy": {"why": "w"}},
            "linkage_polcy",
        ),
        (
            "name on a bundled_library match (the engine reads library)",
            lambda: minimal(
                rule=[
                    {
                        **minimal()["rule"][0],
                        "match": {"kind": "bundled_library", "name": "openssl"},
                    }
                ]
            ),
            "name",
        ),
        (
            "library on a linkage match (the engine reads name)",
            lambda: minimal(
                rule=[
                    {
                        **minimal()["rule"][0],
                        "match": {
                            "kind": "linkage",
                            "library": "openssl",
                            "value": "system",
                        },
                    }
                ]
            ),
            "library",
        ),
        (
            "a misspelt copy_strng_group on a crypto_library",
            lambda: minimal(
                crypto_library=[
                    {
                        **minimal()["crypto_library"][0],
                        "string_group": "openssl_banner",
                        "copy_strng_group": "openssl_banner",
                    }
                ]
            ),
            "copy_strng_group",
        ),
    ],
    ids=[
        "supressed_by-on-a-rule",
        "exclude_object_valu-on-a-shipped-match",
        "verdit-on-a-crypto_library-entry",
        "severty-on-a-rust_crate-entry",
        "extra-key-on-python_module",
        "extra-key-on-crypto_distribution",
        "suppressed_by-on-a-string_group",
        "extra-key-on-symbol_group",
        "extra-key-on-ctypes_library",
        "extra-key-in-conventions",
        "extra-key-in-verdict",
        "extra-key-in-limits",
        "top-level-linkage_polcy",
        "name-on-a-bundled_library-match",
        "library-on-a-linkage-match",
        "copy_strng_group-on-a-crypto_library",
    ],
)
def test_an_unknown_key_is_refused_wherever_it_is_written(case: str, mutate: Any, key: str) -> None:
    """A typo'd or misplaced key loads clean and does nothing, everywhere the loader
    reads a table, not only `[linkage_policy]`.

    Breaks to prove it: comment out the `_refuse_unknown_keys` call the case's table
    goes through and this case turns green to red. For `[limits]` specifically,
    removing that call gives a bare `TypeError`, which `pytest.raises(RulesetError)`
    does not catch.
    """
    del case  # only steers the parametrize id
    with pytest.raises(RulesetError, match=rf"unknown keys \[.*'{re.escape(key)}'.*\]"):
        parse_ruleset(mutate())


def test_a_linkage_policy_without_a_why_is_rejected() -> None:
    data = minimal(linkage_policy={"exclude_reasons": []})
    with pytest.raises(RulesetError, match="why"):
        parse_ruleset(data)


def test_a_ruleset_with_no_linkage_policy_derives_it_from_the_rules() -> None:
    """`minimal()` has no verdict-less partial_binary rule, so it derives to nothing."""
    assert parse_ruleset(minimal()).linkage_policy.exclude_reasons == frozenset()


def test_a_verdict_less_complement_rule_claims_every_cause_it_does_not_exclude() -> None:
    """`reasons` selects and `exclude_reasons` takes the complement, for both readers.

    The containment check has to see a verdict-less rule written either way. Written
    the complement way it claims almost the whole vocabulary, which is the arm that
    silently grows when a token is added.
    """
    data = minimal()
    data["rule"].append(
        {
            "id": "BIN_PARTIAL_QUIET",
            "layer": "binary",
            "category": "opacity",
            "severity": "info",
            "confidence": "high",
            "needs_human_review": False,
            "title": "t",
            "why": "w",
            "match": {"kind": "partial_binary", "exclude_reasons": ["pe_delay_load"]},
        }
    )
    derived = parse_ruleset(data).linkage_policy.exclude_reasons
    assert "pe_delay_load" not in derived
    assert "macho_symtab_incomplete" in derived


def test_every_always_report_library_can_be_recognised_without_its_symbols() -> None:
    """A library reported whatever the evidence needs a way to be seen without symbols.

    `static` is read off a defined symbol or a string, and the symbol half is the one
    that goes missing: stripped, understated, bound by ordinal, past a cap. A library
    with `always_report` set is one whose posture is in every record, so `none` for it
    is an assertion the tool makes about every wheel, and it should not rest on the
    fragile half alone. It is a weaker premise than it sounds -- an object can carry
    the static copy and no banner -- which is why an ordinal export is not treated as
    routine on the strength of it.
    """
    libraries = load_ruleset().libraries.values()
    reported = [library for library in libraries if library.always_report]
    assert reported, "no library is reported unconditionally"
    for library in reported:
        assert library.string_group, library.name


@pytest.mark.parametrize(
    ("limit", "value"),
    [
        ("max_strings_per_binary", 0),
        ("max_symbols_per_binary", 1),
        ("max_rust_crates_per_binary", 0),
    ],
)
def test_a_limit_too_small_to_hold_one_of_each_key_is_rejected(limit, value) -> None:
    """`caps` keeps one of every key, and below that it is the alphabet again.

    `SCHEMA.md` states the guarantee without conditions, and nothing checked the one
    condition it has. A limit is not policy in the sense the rest of this file means:
    nobody sets one to change what is detected, so a value that silently does is a
    mistake rather than a decision.
    """
    data = minimal()
    data["limits"][limit] = value
    with pytest.raises(RulesetError, match="chooses which evidence survives"):
        parse_ruleset(data)


def test_the_shipped_limits_leave_room_for_every_key() -> None:
    """The shipped ruleset is the one that has to satisfy it, and it does with room."""
    ruleset = load_ruleset()
    assert ruleset.limits.max_strings_per_binary >= len(ruleset.string_groups)
    assert ruleset.limits.max_symbols_per_binary >= 2 * len(ruleset.symbol_groups)
    assert ruleset.limits.max_rust_crates_per_binary >= len(ruleset.rust_crates)


def test_a_rule_matching_nothing_is_rejected() -> None:
    data = minimal()
    data["rule"][0]["match"] = []
    with pytest.raises(RulesetError, match="match is empty"):
        parse_ruleset(data)


def test_unknown_verdict_class_is_rejected() -> None:
    data = minimal()
    data["rule"][0]["verdict"] = "COMPLIANT"
    with pytest.raises(RulesetError, match="unknown verdict"):
        parse_ruleset(data)


def test_precedence_without_the_fallback_class_is_rejected() -> None:
    data = minimal()
    data["verdict"]["precedence"] = ["NON_APPROVED_CRYPTO"]
    with pytest.raises(RulesetError, match="must end with 'NO_CRYPTO_DETECTED'"):
        parse_ruleset(data)


def test_the_fallback_class_must_close_the_precedence() -> None:
    data = minimal()
    data["verdict"]["precedence"] = ["NO_CRYPTO_DETECTED", "NON_APPROVED_CRYPTO"]
    with pytest.raises(RulesetError, match="must end with 'NO_CRYPTO_DETECTED'"):
        parse_ruleset(data)


@pytest.mark.parametrize(
    "precedence",
    [
        ["NON_APPROVED_CRYPTO", "NON_APPROVED_CRYPTO", "NO_CRYPTO_DETECTED"],
        ["NO_CRYPTO_DETECTED", "NON_APPROVED_CRYPTO", "NO_CRYPTO_DETECTED"],
    ],
)
def test_a_class_named_twice_in_precedence_is_rejected(precedence: list[str]) -> None:
    data = minimal()
    data["verdict"]["precedence"] = precedence
    with pytest.raises(RulesetError, match="more than once"):
        parse_ruleset(data)


def test_a_non_string_precedence_class_is_rejected() -> None:
    data = minimal()
    data["verdict"]["precedence"] = [1, "NON_APPROVED_CRYPTO", "NO_CRYPTO_DETECTED"]
    with pytest.raises(RulesetError, match="precedence must be a list of strings"):
        parse_ruleset(data)


def test_an_unhashable_precedence_class_is_rejected() -> None:
    data = minimal()
    data["verdict"]["precedence"] = [["NON_APPROVED_CRYPTO"], "NO_CRYPTO_DETECTED"]
    with pytest.raises(RulesetError, match="precedence must be a list of strings"):
        parse_ruleset(data)


def test_a_bare_string_precedence_is_rejected() -> None:
    data = minimal()
    data["verdict"]["precedence"] = "NO_CRYPTO_DETECTED"
    with pytest.raises(RulesetError, match="precedence must be a list of strings"):
        parse_ruleset(data)


def test_an_empty_precedence_is_rejected() -> None:
    data = minimal()
    data["verdict"]["precedence"] = []
    with pytest.raises(RulesetError, match="precedence must not be an empty list"):
        parse_ruleset(data)


@pytest.mark.parametrize(
    "table,index",
    [("rule", 0), ("crypto_library", 0), ("rust_crate", 0)],
)
def test_no_rule_or_entry_may_assign_the_fallback_class(table: str, index: int) -> None:
    data = minimal()
    data[table][index]["verdict"] = "NO_CRYPTO_DETECTED"
    with pytest.raises(RulesetError, match="no rule or entry may assign it"):
        parse_ruleset(data)


def test_table_entry_naming_a_missing_rule_is_rejected() -> None:
    data = minimal()
    data["crypto_distribution"][0]["rule"] = "DIST_TYPO"
    with pytest.raises(RulesetError, match="unknown rule"):
        parse_ruleset(data)


def test_a_library_entry_naming_a_missing_rule_is_rejected() -> None:
    data = minimal()
    data["crypto_library"][0]["rule"] = "BIN_TYPO"
    with pytest.raises(RulesetError, match="unknown rule"):
        parse_ruleset(data)


def test_a_crate_entry_naming_a_missing_rule_is_rejected() -> None:
    data = minimal()
    data["rust_crate"][0]["rule"] = "BIN_TYPO"
    with pytest.raises(RulesetError, match="unknown rule"):
        parse_ruleset(data)


def _fully_referenced_library_ruleset() -> dict[str, Any]:
    """`minimal()` with its one library pointed at every cross-reference an entry can
    carry, so a nameless entry appended to any of these tables is reached by every pass
    that reads a name off it, not only the entry table's own loop."""
    data = minimal()
    data["crypto_library"][0] = {
        **data["crypto_library"][0],
        "symbol_group": "openssl",
        "string_group": "openssl_banner",
        "crates": ["ring"],
    }
    return data


_NAMELESS_ENTRIES: dict[str, dict[str, Any]] = {
    "crypto_distribution": {"rule": "DIST_NON_APPROVED_CRYPTO", "why": "no name"},
    "crypto_library": {"why": "no name"},
    "symbol_group": {"prefixes": ["X_"], "exact": [], "why": "no name"},
    "string_group": {"why": "no name"},
    "rust_crate": {"why": "no name"},
    "python_module": {"why": "no name"},
}


@pytest.mark.parametrize("table", sorted(_NAMELESS_ENTRIES))
def test_an_entry_with_no_name_is_rejected(table: str) -> None:
    """Whichever pass reads an entry's name first -- a cross-reference set built ahead
    of an entry table's own loop, or the loop itself -- must raise the same
    `RulesetError`, never a bare `KeyError`.

    Breaks to prove it: revert `_entry_names` to `{e["name"] for e in data[table]}`.
    The `rust_crate`, `crypto_library` and `string_group` cases then raise `KeyError`.
    """
    data = _fully_referenced_library_ruleset()
    data[table].append(_NAMELESS_ENTRIES[table])
    with pytest.raises(RulesetError, match="missing required field 'name'"):
        parse_ruleset(data)


@pytest.mark.parametrize("table", sorted(_NAMELESS_ENTRIES))
def test_an_entry_whose_name_is_not_a_string_is_rejected(table: str) -> None:
    """A `name` of the wrong shape reaches the same `not in <set>` membership tests a
    missing one does, so it must be refused before them too, not crash with a bare
    `TypeError`.

    Breaks to prove it: drop the `_check_string` call from `_entry_name`. The library
    and crate cases then raise `TypeError`; the distribution case loads clean.
    """
    data = _fully_referenced_library_ruleset()
    data[table][0]["name"] = ["x"]
    with pytest.raises(RulesetError, match="name must be a string"):
        parse_ruleset(data)


def test_an_entry_that_is_not_a_table_is_rejected() -> None:
    data = minimal()
    data["rust_crate"].append("ring")
    with pytest.raises(RulesetError, match="entries must be tables"):
        parse_ruleset(data)


# --- crate-level suppressed_by ----------------------------------------------


def test_a_crate_entry_naming_an_unknown_crate_in_suppressed_by_is_rejected() -> None:
    data = rust_crate_ruleset()
    data["rust_crate"][0]["suppressed_by"] = ["typo-crate"]
    with pytest.raises(RulesetError, match="unknown crate"):
        parse_ruleset(data)


def test_a_crate_entry_naming_itself_in_suppressed_by_is_rejected() -> None:
    data = rust_crate_ruleset()
    data["rust_crate"][0]["suppressed_by"] = ["ring"]
    with pytest.raises(RulesetError, match="names itself"):
        parse_ruleset(data)


def test_a_crate_entry_naming_an_ownerless_crate_in_suppressed_by_is_rejected() -> None:
    """`ring` has no `rule` and `minimal()` declares no default rust_crate rule."""
    data = minimal()
    data["rule"].append(
        dict(
            data["rule"][0],
            id="BIN_RUST_CRYPTO_CRATE",
            layer="binary",
            match={"kind": "rust_crate", "table": "rust_crate"},
        )
    )
    data["rust_crate"].append(
        {
            "name": "sub",
            "rule": "BIN_RUST_CRYPTO_CRATE",
            "severity": "high",
            "why": "w",
            "suppressed_by": ["ring"],
        }
    )
    with pytest.raises(RulesetError, match="no rule owns"):
        parse_ruleset(data)


def test_an_ownerless_crate_carrying_suppressed_by_is_rejected() -> None:
    """The mirror of the "no rule owns" check above: this time the *subject* of
    `suppressed_by`, not the name it points at, has no owning rule. An ownerless
    crate fires in every `rust_crate` rule (`_owns(..., unowned=True)`), so its
    finding is not the single key a `suppressed_by` relation needs either, and
    letting it carry the field can close a cycle `_check_suppression_acyclic` never
    sees because it skips ownerless crates entirely."""
    data = minimal()
    data["rule"].append(
        dict(
            data["rule"][0],
            id="BIN_RUST_CRYPTO_CRATE",
            layer="binary",
            match={"kind": "rust_crate", "table": "rust_crate"},
        )
    )
    data["rust_crate"][0]["suppressed_by"] = ["sub"]
    data["rust_crate"].append(
        {"name": "sub", "rule": "BIN_RUST_CRYPTO_CRATE", "severity": "high", "why": "w"}
    )
    with pytest.raises(RulesetError, match="no rule owns this crate"):
        parse_ruleset(data)


def test_two_crates_suppressing_each_other_form_a_cycle() -> None:
    data = rust_crate_ruleset()
    data["rust_crate"][0]["suppressed_by"] = ["boring"]
    data["rust_crate"][1]["suppressed_by"] = ["ring"]
    with pytest.raises(
        RulesetError,
        match=re.escape(
            "suppressed_by forms a cycle: crate 'boring' -> crate 'ring' -> crate 'boring'"
        ),
    ):
        parse_ruleset(data)


def test_two_rules_suppressing_each_other_form_a_cycle() -> None:
    data = minimal()
    data["rule"][0]["suppressed_by"] = ["OTHER"]
    other = dict(data["rule"][0])
    other["id"] = "OTHER"
    other["suppressed_by"] = ["DIST_NON_APPROVED_CRYPTO"]
    data["rule"].append(other)
    with pytest.raises(RulesetError, match="forms a cycle"):
        parse_ruleset(data)


def test_crates_and_rules_mixed_together_form_a_cycle() -> None:
    """Crate x, owned by rule S, is suppressed by crate y, owned by rule R; R is
    suppressed by S. That closes a cycle through S -> x -> y -> S."""
    data = minimal()
    data["rule"].append(
        dict(
            data["rule"][0],
            id="RULE_R",
            layer="binary",
            match={"kind": "rust_crate", "table": "rust_crate"},
            suppressed_by=["RULE_S"],
        )
    )
    data["rule"].append(
        dict(
            data["rule"][0],
            id="RULE_S",
            layer="binary",
            match={"kind": "rust_crate", "table": "rust_crate"},
        )
    )
    data["rust_crate"] = [
        {"name": "x", "rule": "RULE_S", "severity": "high", "why": "w", "suppressed_by": ["y"]},
        {"name": "y", "rule": "RULE_R", "severity": "high", "why": "w"},
    ]
    with pytest.raises(RulesetError, match="forms a cycle"):
        parse_ruleset(data)


def test_a_one_directional_relation_between_two_crates_of_the_same_rule_loads_clean() -> None:
    """Two crates owned by one rule, related in one direction only. The cycle check
    must not flag this as a self-rule false positive."""
    data = rust_crate_ruleset()
    data["rust_crate"][0]["suppressed_by"] = ["boring"]
    parse_ruleset(data)


# --- suppressed_by can only fire where the two rules could share a path -----


def test_a_cross_layer_suppressed_by_is_rejected() -> None:
    data = minimal()
    data["rule"][0]["suppressed_by"] = ["BIN_GO_FIPS140"]
    data["rule"].append(
        dict(
            data["rule"][0],
            id="BIN_GO_FIPS140",
            layer="binary",
            suppressed_by=[],
            match={"kind": "binary_string", "group": "openssl_banner"},
        )
    )
    with pytest.raises(RulesetError, match="never share a location path"):
        parse_ruleset(data)


def test_a_same_layer_linkage_and_rust_crate_relation_is_rejected() -> None:
    """`linkage` with no `object_values` locates on the wheel's own filename;
    `rust_crate` locates on the object. Both are `layer = "binary"`, and the relation
    is still dead, because what decides it is `Location.path`, not `layer`."""
    data = minimal()
    data["rule"].append(
        dict(
            data["rule"][0],
            id="BIN_OPENSSL_LINKAGE_UNKNOWN",
            layer="binary",
            suppressed_by=["BIN_RUST_CRYPTO_CRATE"],
            match={"kind": "linkage", "name": "openssl", "value": "unknown"},
        )
    )
    data["rule"].append(
        dict(
            data["rule"][0],
            id="BIN_RUST_CRYPTO_CRATE",
            layer="binary",
            suppressed_by=[],
            match={"kind": "rust_crate", "table": "rust_crate", "default": True},
        )
    )
    with pytest.raises(RulesetError, match="never share a location path"):
        parse_ruleset(data)


def test_two_wheel_scoped_rules_of_different_kinds_cannot_relate_either() -> None:
    """Wheel-scoped is not one path either: `dist_name` locates on `<dist-info>`,
    `requires_dist` on `<dist-info>/METADATA`. Both metadata-layer and both
    wheel-scoped is not enough; their hits still never share a `Location.path`."""
    data = minimal()
    data["rule"].append(
        dict(
            data["rule"][0],
            id="DIST_DEPENDS_ON_CRYPTO",
            suppressed_by=["DIST_NON_APPROVED_CRYPTO"],
            match={"kind": "requires_dist", "any_entry": True},
        )
    )
    with pytest.raises(RulesetError, match="never share a location path"):
        parse_ruleset(data)


def test_a_linkage_rule_with_object_values_can_suppress_a_per_object_binary_rule() -> None:
    """A `linkage` match carrying `object_values` locates per object, the same class
    a per-object binary rule shares, so this relation is accepted."""
    data = minimal()
    data["rule"].append(
        dict(
            data["rule"][0],
            id="DERIVED_OPENSSL_UNRESOLVED_BESIDE_SYSTEM",
            layer="derived",
            suppressed_by=[],
            match={
                "kind": "linkage",
                "name": "openssl",
                "value": "unknown",
                "object_values": ["unknown"],
            },
        )
    )
    data["rule"].append(
        dict(
            data["rule"][0],
            id="BIN_RUST_CRYPTO_CRATE",
            layer="binary",
            suppressed_by=["DERIVED_OPENSSL_UNRESOLVED_BESIDE_SYSTEM"],
            match={"kind": "rust_crate", "table": "rust_crate", "default": True},
        )
    )
    parse_ruleset(data)


def test_a_relation_naming_a_scan_error_rule_is_accepted_as_a_wildcard() -> None:
    """`scan_error` locates on whatever path the error concerns, so it is a wildcard:
    a relation naming it is always accepted, whatever the other side locates on."""
    data = minimal()
    data["rule"][0]["suppressed_by"] = ["BIN_UNPARSEABLE"]
    data["rule"].append(
        dict(
            data["rule"][0],
            id="BIN_UNPARSEABLE",
            layer="binary",
            suppressed_by=[],
            match={"kind": "scan_error", "error_kinds": ["elf_parse_error"]},
        )
    )
    parse_ruleset(data)


def test_a_relation_naming_a_record_mismatch_rule_is_accepted_as_a_wildcard() -> None:
    data = minimal()
    data["rule"][0]["suppressed_by"] = ["WHEEL_RECORD_MISMATCH"]
    data["rule"].append(
        dict(
            data["rule"][0],
            id="WHEEL_RECORD_MISMATCH",
            layer="metadata",
            suppressed_by=[],
            match={"kind": "record_mismatch"},
        )
    )
    parse_ruleset(data)


def test_only_one_of_two_match_tables_needs_to_share_a_class() -> None:
    """The check asks whether any pair of match tables across the two rules could
    meet, not whether every pair does: a rule with one per-object table and one
    wheel-scoped table is accepted against a per-object suppressor."""
    data = minimal()
    data["rule"].append(
        dict(
            data["rule"][0],
            id="BIN_EITHER_WAY",
            layer="binary",
            suppressed_by=["BIN_RUST_CRYPTO_CRATE"],
            match=[
                {"kind": "linkage", "name": "openssl", "value": "unknown"},
                {"kind": "binary_string", "group": "openssl_banner"},
            ],
        )
    )
    data["rule"].append(
        dict(
            data["rule"][0],
            id="BIN_RUST_CRYPTO_CRATE",
            layer="binary",
            suppressed_by=[],
            match={"kind": "rust_crate", "table": "rust_crate", "default": True},
        )
    )
    parse_ruleset(data)


def test_the_shipped_suppressed_by_relations_all_locate_where_they_can_fire() -> None:
    """`BIN_AWS_LC` -> `BIN_AWS_LC_FIPS`, `BIN_AWS_LC_RS_CRATE` -> `BIN_AWS_LC_FIPS` and
    `BIN_GO_STOCK_CRYPTO` -> `BIN_GO_BORING_CRYPTO`/`BIN_GO_FIPS140` are all
    object/object; loading the shipped ruleset already proves they pass
    `_check_suppression_can_fire`, so this just names them."""
    ruleset = load_ruleset()
    assert ruleset.rule("BIN_AWS_LC").suppressed_by == ("BIN_AWS_LC_FIPS",)
    assert ruleset.rule("BIN_AWS_LC_RS_CRATE").suppressed_by == ("BIN_AWS_LC_FIPS",)
    assert set(ruleset.rule("BIN_GO_STOCK_CRYPTO").suppressed_by) == {
        "BIN_GO_BORING_CRYPTO",
        "BIN_GO_FIPS140",
    }


def test_a_bare_string_suppressed_by_on_a_rule_is_rejected() -> None:
    data = minimal()
    data["rule"][0]["suppressed_by"] = "DIST_NON_APPROVED_CRYPTO"
    with pytest.raises(RulesetError, match="suppressed_by must be a list of strings"):
        parse_ruleset(data)


def test_a_bare_string_suppressed_by_on_a_crate_entry_is_rejected() -> None:
    data = rust_crate_ruleset()
    data["rust_crate"][0]["suppressed_by"] = "boring"
    with pytest.raises(RulesetError, match="suppressed_by must be a list of strings"):
        parse_ruleset(data)


def test_suppressed_by_on_a_crypto_distribution_entry_is_rejected() -> None:
    """Only `[[rust_crate]]` reads entry-level `suppressed_by`; the natural-looking
    analogy on another table would load clean and do nothing, which is the typo
    trap the loader exists to catch."""
    data = minimal()
    data["crypto_distribution"][0]["suppressed_by"] = ["whatever"]
    with pytest.raises(
        RulesetError, match=r"suppressed_by is only supported on \[\[rust_crate\]\]"
    ):
        parse_ruleset(data)


def test_suppressed_by_on_a_crypto_library_entry_is_rejected() -> None:
    data = minimal()
    data["crypto_library"][0]["suppressed_by"] = ["whatever"]
    with pytest.raises(
        RulesetError, match=r"suppressed_by is only supported on \[\[rust_crate\]\]"
    ):
        parse_ruleset(data)


def test_suppressed_by_on_a_python_module_entry_is_rejected() -> None:
    data = minimal()
    data["python_module"][0]["suppressed_by"] = ["whatever"]
    with pytest.raises(
        RulesetError, match=r"suppressed_by is only supported on \[\[rust_crate\]\]"
    ):
        parse_ruleset(data)


def test_a_crate_entry_suppressed_by_resolves_to_the_owning_rule_and_crate_name() -> None:
    """An entry-level `suppressed_by` resolves each name to `(owning rule id, crate
    name)`. No shipped crate carries one, so this is pinned against a minimal
    fixture."""
    data = rust_crate_ruleset()
    data["rust_crate"][0]["suppressed_by"] = ["boring"]
    ruleset = parse_ruleset(data)
    assert ruleset.rust_crates["ring"].suppressed_by == (("BIN_RUST_CRYPTO_CRATE", "boring"),)


def test_no_shipped_crate_carries_an_entry_level_suppressed_by() -> None:
    """DESIGN.md states the entry-level field has no shipped user and that the shipped
    AWS-LC relation is rule-level. A crate gaining one must update that entry."""
    ruleset = load_ruleset()
    assert [name for name, crate in ruleset.rust_crates.items() if crate.suppressed_by] == []
    assert "BIN_AWS_LC_FIPS" in ruleset.rule("BIN_AWS_LC_RS_CRATE").suppressed_by


def test_a_library_naming_a_crate_the_crate_table_lacks_is_rejected() -> None:
    """A misspelt crate would never match and never move the posture, and fail nothing."""
    data = minimal()
    data["crypto_library"][0]["crates"] = ["opensll-sys"]
    with pytest.raises(RulesetError, match="not a \\[\\[rust_crate\\]\\] entry"):
        parse_ruleset(data)


def test_a_library_naming_an_unknown_copy_string_group_is_rejected() -> None:
    data = minimal()
    data["crypto_library"][0]["string_group"] = "openssl_banner"
    data["crypto_library"][0]["copy_string_group"] = "opensll_build_info"
    with pytest.raises(RulesetError, match="unknown string group"):
        parse_ruleset(data)


def test_a_copy_string_group_equal_to_the_banner_group_is_rejected() -> None:
    """The same group could never mark a copy: the banner would be its own marker
    and the gate could never open, silently."""
    data = minimal()
    data["crypto_library"][0]["string_group"] = "openssl_banner"
    data["crypto_library"][0]["copy_string_group"] = "openssl_banner"
    with pytest.raises(RulesetError, match="must differ"):
        parse_ruleset(data)


def test_a_copy_string_group_without_a_string_group_is_rejected() -> None:
    data = minimal()
    data["crypto_library"][0]["copy_string_group"] = "openssl_banner"
    with pytest.raises(RulesetError, match="needs a string_group"):
        parse_ruleset(data)


def test_openssl_names_a_copy_string_group() -> None:
    """The shipped ruleset's `openssl` entry has a way to tell a header banner from
    a real compiled-in copy, and that group is one the ruleset actually compiles."""
    ruleset = load_ruleset()
    group = ruleset.libraries["openssl"].copy_string_group
    assert group is not None
    assert group in ruleset.string_groups


def test_a_library_naming_a_bare_crate_string_is_rejected() -> None:
    """Not read as a list of one-letter crates."""
    data = minimal()
    data["crypto_library"][0]["crates"] = "ring"
    with pytest.raises(RulesetError, match="crates must be a list of strings"):
        parse_ruleset(data)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("symbol_group", ["openssl"]),
        ("string_group", ["openssl_banner"]),
        ("copy_string_group", ["go_boring"]),
    ],
)
def test_a_library_group_field_that_is_not_a_string_is_rejected(
    field: str, value: list[str]
) -> None:
    """Each of these three fields is read straight into a `not in <set>` membership
    test a few lines below, which crashes with a bare `TypeError` on a list or table
    rather than the `RulesetError` a malformed ruleset should raise.

    Breaks to prove it: remove the `_check_string` call the field goes through; each
    case then raises `TypeError`.
    """
    data = minimal()
    data["crypto_library"][0][field] = value
    if field == "copy_string_group":
        data["crypto_library"][0]["string_group"] = "openssl_banner"
    with pytest.raises(RulesetError, match=f"{field} must be a string"):
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


@pytest.mark.parametrize(
    ("bad_match", "message", "fix"),
    [
        (
            {"kind": "dynamic_symbol", "group": ["openssl"], "binding": "any"},
            "group must be a string",
            {"group": "openssl"},
        ),
        (
            {"kind": "dynamic_symbol", "groups": [["openssl"]], "binding": "any"},
            "groups must be a list of strings",
            {"groups": ["openssl"]},
        ),
        (
            {"kind": "binary_string", "group": ["openssl_banner"]},
            "group must be a string",
            {"group": "openssl_banner"},
        ),
        (
            {"kind": "dynamic_symbol", "group": "openssl", "binding": ["any"]},
            "unknown symbol binding",
            {"binding": "any"},
        ),
        (
            {"kind": ["dist_name"], "table": "crypto_distribution"},
            "unknown matcher kind",
            None,
        ),
        (
            {"kind": "dt_needed", "library": ["openssl"]},
            "must be a string",
            {"library": "openssl"},
        ),
        (
            {"kind": "bundled_library", "exclude_libraries": [["openssl"]]},
            "exclude_libraries must be a list of strings",
            {"exclude_libraries": ["openssl"]},
        ),
        (
            {"kind": "scan_error", "error_kinds": [["x"]]},
            "error_kinds must be a list of strings",
            {"error_kinds": ["bad_zip"]},
        ),
        (
            {"kind": "partial_binary", "reasons": [["x"]]},
            "reasons must be a list of strings",
            {"reasons": ["pe_ordinal_import"]},
        ),
    ],
)
def test_a_rule_reference_field_of_the_wrong_shape_is_rejected(
    bad_match: dict[str, Any], message: str, fix: dict[str, Any] | None
) -> None:
    """A reference field is read straight into a `not in <set>` membership test, or
    iterated, a few lines below where it is required or defaulted -- a list or table
    there crashes with a bare `TypeError` instead of the `RulesetError` a malformed
    ruleset should raise.

    Every case but the malformed `kind` itself also checks that swapping the one bad
    field for a good one of the same shape loads clean, so the fix narrows to that one
    field rather than accidentally also covering up a missing one.

    Breaks to prove it: revert `_check` to the bare `not in` test -- the `binding` and
    `kind` cases then raise `TypeError`. Revert the reference-field checks in
    `_validate_match_references` -- the `group`, `library`, `error_kinds` and `reasons`
    cases then raise `TypeError`.
    """

    def _with_match(match: dict[str, Any]) -> dict[str, Any]:
        data = minimal()
        data["rule"].append(
            {
                "id": "MATCH_SHAPE_TEST",
                "layer": "binary",
                "category": "crypto-implementation",
                "severity": "info",
                "confidence": "high",
                "needs_human_review": False,
                "title": "t",
                "why": "w",
                "match": match,
            }
        )
        return data

    with pytest.raises(RulesetError, match=message):
        parse_ruleset(_with_match(bad_match))
    if fix is not None:
        parse_ruleset(_with_match({**bad_match, **fix}))


def test_a_verdict_or_severity_that_is_not_a_string_is_rejected() -> None:
    """A verdict or severity of the wrong shape reaches the same `not in <set>` test a
    typo does, so both must raise the same `RulesetError` rather than a `TypeError`.

    Breaks to prove it: revert `_check` to the bare `not in` test; each case then
    raises `TypeError`.
    """
    rule_verdict = minimal()
    rule_verdict["rule"][0]["verdict"] = ["x"]
    with pytest.raises(RulesetError, match="unknown verdict class"):
        parse_ruleset(rule_verdict)

    rule_severity = minimal()
    rule_severity["rule"][0]["severity"] = ["x"]
    with pytest.raises(RulesetError, match="unknown severity"):
        parse_ruleset(rule_severity)

    crate_verdict = minimal()
    crate_verdict["rust_crate"][0]["verdict"] = ["x"]
    with pytest.raises(RulesetError, match="unknown verdict class"):
        parse_ruleset(crate_verdict)


def test_the_shipped_ruleset_with_a_malformed_entry_is_refused() -> None:
    """The two shapes reproduced against a ruleset whose libraries really do list
    crates -- unlike `minimal()`, so this also exercises the crate cross-reference
    path a wrapped-list `string_group` reaches through `crypto_library`."""
    wrapped_string_group = copy.deepcopy(_shipped_data())
    for library in wrapped_string_group["crypto_library"]:
        if library["name"] == "openssl":
            library["string_group"] = [library["string_group"]]
    with pytest.raises(RulesetError, match="string_group must be a string"):
        parse_ruleset(wrapped_string_group)

    nameless_crate = copy.deepcopy(_shipped_data())
    nameless_crate["rust_crate"].append({"why": "x"})
    with pytest.raises(RulesetError, match="missing required field 'name'"):
        parse_ruleset(nameless_crate)


def _sbom_component_rule(tables: list[str], rule_id: str = "SBOM_TEST_RULE") -> dict[str, Any]:
    return {
        "id": rule_id,
        "layer": "metadata",
        "category": "bundled-crypto",
        "severity": "high",
        "confidence": "high",
        "needs_human_review": True,
        "title": "t",
        "why": "w",
        "match": {"kind": "sbom_component", "tables": tables},
    }


def _without_sbom_component_rules(data: dict[str, Any]) -> dict[str, Any]:
    """`minimal()`'s own `SBOM_CRYPTO_COMPONENT` rule already covers both tables the
    coverage check requires, so a test of that check itself has to start without it."""
    data["rule"] = [r for r in data["rule"] if r["match"].get("kind") != "sbom_component"]
    return data


@pytest.mark.parametrize(
    "tables",
    [["crypto_distribution"], ["crypto_library"], ["rust_crate"], []],
)
def test_no_sbom_component_rule_together_covers_both_required_tables_is_rejected(
    tables: list[str],
) -> None:
    """`linkage._declared_by_sbom` only ever compares an SBOM component name against
    `crypto_library`/`rust_crate` entries, on the assumption that the ruleset's
    `sbom_component` rules together report a finding on both -- so a ruleset whose
    `sbom_component` rules never cover both tables between them would move a library's
    linkage on a component name the record carries no finding for. Refused here rather
    than left to a test over the shipped ruleset."""
    data = _without_sbom_component_rules(minimal())
    data["rule"].append(_sbom_component_rule(tables))
    with pytest.raises(RulesetError, match="sbom_component rules must together cover tables"):
        parse_ruleset(data)


def test_no_sbom_component_rule_at_all_is_rejected() -> None:
    """The case that actually breaks the field/finding agreement: with no
    `sbom_component` rule in the ruleset at all, an SBOM-only wheel still moves
    `<name>_linkage` to `unknown` with no finding anywhere in the record to say why."""
    data = _without_sbom_component_rules(minimal())
    with pytest.raises(RulesetError, match="sbom_component rules must together cover tables"):
        parse_ruleset(data)


def test_an_sbom_component_rule_cannot_use_the_singular_table_key_to_satisfy_this() -> None:
    """`engine._match_sbom_component` only ever reads `match["tables"]`; the singular
    `table` key is refused on this kind outright, so it can never fill a gap in the
    coverage a ruleset claims to satisfy through it."""
    data = _without_sbom_component_rules(minimal())
    rule = _sbom_component_rule(["rust_crate"])
    rule["match"]["table"] = "crypto_library"
    data["rule"].append(rule)
    with pytest.raises(RulesetError, match=r"unknown keys \['table'\]"):
        parse_ruleset(data)


def test_an_sbom_component_rule_with_both_required_tables_is_accepted() -> None:
    data = minimal()
    data["rule"].append(
        _sbom_component_rule(["crypto_library", "rust_crate", "crypto_distribution"])
    )
    parse_ruleset(data)


def test_two_sbom_component_rules_can_split_the_required_tables() -> None:
    """Covering `crypto_library` and `rust_crate` across two separate rules -- one
    reporting each -- is exactly as sound as one rule doing both, so the coverage
    check must accept the split rather than refuse it as missing coverage."""
    data = _without_sbom_component_rules(minimal())
    data["rule"].append(_sbom_component_rule(["crypto_library"], rule_id="SBOM_LIBRARY"))
    data["rule"].append(_sbom_component_rule(["rust_crate"], rule_id="SBOM_CRATE"))
    parse_ruleset(data)


def test_a_suppressed_sbom_component_rule_covering_required_tables_is_rejected() -> None:
    """A rule reporting `crypto_library`/`rust_crate` coverage that also carries
    `suppressed_by` can still lose its finding at scan time whenever the rule named
    there also fires, while `linkage._declared_by_sbom` moved the field regardless --
    the same field-moves-with-no-finding hole the coverage check otherwise refuses.
    The suppressor named is itself a `sbom_component` rule, so the relation shares a
    location and reaches this check rather than being refused earlier for never
    sharing one."""
    data = _without_sbom_component_rules(minimal())
    data["rule"].append(_sbom_component_rule(["crypto_distribution"], rule_id="SBOM_OTHER"))
    rule = _sbom_component_rule(["crypto_library", "rust_crate"])
    rule["suppressed_by"] = ["SBOM_OTHER"]
    data["rule"].append(rule)
    with pytest.raises(RulesetError, match="cannot carry suppressed_by"):
        parse_ruleset(data)


def test_a_suppressed_sbom_component_rule_covering_only_distribution_is_accepted() -> None:
    """`suppressed_by` is refused only on a rule the coverage check relies on for
    `crypto_library`/`rust_crate`; a rule that only ever reports `crypto_distribution`
    plays no part in that agreement and is free to carry it."""
    data = minimal()
    rule = _sbom_component_rule(["crypto_distribution"], rule_id="SBOM_DIST_ONLY")
    rule["suppressed_by"] = ["SBOM_CRYPTO_COMPONENT"]
    data["rule"].append(rule)
    parse_ruleset(data)


# --- SBOM name folding -------------------------------------------------------


def test_two_rust_crate_names_folding_together_are_rejected() -> None:
    """`foo-bar` and `foo_bar` are the same crates.io name, so the two entries would
    make `ruleset.crate_for_sbom_name` ambiguous -- dict order would silently pick a
    winner. Refused at load time instead."""
    data = minimal()
    data["rust_crate"].append({"name": "foo-bar", "severity": "high", "why": "w"})
    data["rust_crate"].append({"name": "foo_bar", "severity": "high", "why": "w"})
    with pytest.raises(RulesetError, match="same name to an SBOM"):
        parse_ruleset(data)


def test_two_crypto_library_names_folding_together_are_rejected() -> None:
    """`Foo` and `foo` fold to the same case-insensitive key, making
    `ruleset.library_for_sbom_name` ambiguous the same way."""
    data = minimal()
    data["crypto_library"].append({"name": "Foo", "sonames": ["libfoo"], "why": "w"})
    data["crypto_library"].append({"name": "foo", "sonames": ["libfoo2"], "why": "w"})
    with pytest.raises(RulesetError, match="same name to an SBOM"):
        parse_ruleset(data)


def test_sbom_library_key_does_not_fold_a_non_ascii_character_onto_ascii_case() -> None:
    """U+212A KELVIN SIGN lowercases to ASCII `k` under Python's own `str.lower()`, but
    no registry treats it as the same character as `k`. Folding it would make an SBOM
    component spelled with the Kelvin sign match an ASCII ruleset entry it never
    actually named, so a non-ASCII name is returned unchanged instead."""
    kelvin_k = "K"
    assert sbom_library_key(f"{kelvin_k}256") == f"{kelvin_k}256"
    assert sbom_library_key(f"{kelvin_k}256") != sbom_library_key("K256")


def test_sbom_crate_key_does_not_fold_a_non_ascii_character_onto_ascii_case() -> None:
    """The same Unicode-folding gap as `sbom_library_key` above, for the `-`/`_` fold
    `sbom_crate_key` also applies: crates.io names are ASCII-only, so a non-ASCII name
    is returned unchanged rather than folded onto an ASCII crate it never named."""
    kelvin_k = "K"
    assert sbom_crate_key(f"{kelvin_k}256") == f"{kelvin_k}256"
    assert sbom_crate_key(f"{kelvin_k}256") != sbom_crate_key("K256")


# --- SBOM crate suppression --------------------------------------------------------


def test_crate_suppressors_on_the_shipped_ruleset() -> None:
    """`aws-lc-rs` is dropped by `aws-lc-fips-sys` through the rule-level relation
    `BIN_AWS_LC_RS_CRATE suppressed_by BIN_AWS_LC_FIPS`; nothing else has a shipped
    relation, including an unknown name."""
    ruleset = load_ruleset()
    assert ruleset.crate_suppressors("aws-lc-rs") == ("aws-lc-fips-sys",)
    for name in ("aws-lc-sys", "rustls", "openssl-sys", "not-a-real-crate"):
        assert ruleset.crate_suppressors(name) == ()


def test_a_crate_that_moves_linkage_from_an_sbom_cannot_be_suppressed_there() -> None:
    """`ring` is listed in `openssl`'s `crates`, so `linkage._declared_by_sbom` counts
    an SBOM naming it towards moving `openssl_linkage`. Giving it a suppressor would
    let an SBOM finding for it disappear while the field still moved, with nothing
    left in the record to say why. The relation is entry-level -- set on `ring`'s own
    entry -- so the refusal names the entry, not a rule."""
    data = rust_crate_ruleset()
    data["crypto_library"][0]["crates"] = ["ring"]
    data["rust_crate"][0]["suppressed_by"] = ["boring"]
    with pytest.raises(
        RulesetError, match=r"rust_crate 'ring' names \['boring'\] in suppressed_by"
    ):
        parse_ruleset(data)


def test_a_crate_sharing_a_librarys_name_cannot_be_suppressed_there() -> None:
    """A `[[rust_crate]]` entry can share a `[[crypto_library]]`'s name without being
    listed in that library's own `crates`, the way argon2 and blake2 do in the shipped
    ruleset: both a library name and an unrelated crate's. `_declared_by_sbom` still
    counts an SBOM naming the crate towards moving the library's `<name>_linkage`, so
    giving the crate a suppressor would let its SBOM finding disappear while the field
    still moved, with nothing left in the record to say why. `openssl` here is the
    library name from `rust_crate_ruleset()`, with no `crates` of its own, so only the
    library-name arm of the check can be what catches this. The relation is again
    entry-level, on the `openssl` crate entry itself."""
    data = rust_crate_ruleset()
    data["rust_crate"].append(
        {"name": "openssl", "severity": "high", "why": "crate", "suppressed_by": ["boring"]}
    )
    with pytest.raises(
        RulesetError, match=r"rust_crate 'openssl' names \['boring'\] in suppressed_by"
    ):
        parse_ruleset(data)


def test_a_suppressor_on_the_default_crate_rule_names_that_rule_in_the_refusal() -> None:
    """`ring` falls to the default `rust_crate` rule in `rust_crate_ruleset()` and sets
    nothing on its own entry. Routing `boring` to a rule of its own and naming that rule
    in the default rule's own `suppressed_by` still reaches `ring` through
    `Ruleset.crate_suppressors`, since every crate the default rule owns shares its
    relations -- so the refusal has to name the rule relation that actually caused it,
    and the crate names that relation resolves to, rather than reading as a problem
    with `ring`'s own entry or naming a crate where the rule names a rule id."""
    data = rust_crate_ruleset()
    data["crypto_library"][0]["crates"] = ["ring"]
    data["rule"].append(
        dict(
            data["rule"][0],
            id="BIN_BORING_CRATE",
            layer="binary",
            match={"kind": "rust_crate", "table": "rust_crate"},
        )
    )
    data["rust_crate"][1]["rule"] = "BIN_BORING_CRATE"  # boring
    data["rule"][-2]["suppressed_by"] = ["BIN_BORING_CRATE"]  # BIN_RUST_CRYPTO_CRATE
    with pytest.raises(
        RulesetError,
        match=(
            r"rule 'BIN_RUST_CRYPTO_CRATE' names \['BIN_BORING_CRATE'\] in suppressed_by, "
            r"which owns \['boring'\]"
        ),
    ):
        parse_ruleset(data)


def test_unknown_scan_error_kind_is_rejected() -> None:
    data = minimal()
    data["rule"][0]["match"] = {"kind": "scan_error", "error_kinds": ["cosmic_ray"]}
    with pytest.raises(RulesetError, match="unknown error kind"):
        parse_ruleset(data)


def test_two_default_rules_for_one_table_are_rejected() -> None:
    data = minimal()
    for rule_id in ("PY_IMPORT_ONE", "PY_IMPORT_TWO"):
        data["rule"].append(
            dict(
                data["rule"][0],
                id=rule_id,
                layer="python",
                match={"kind": "py_import", "table": "python_module", "default": True},
            )
        )
    with pytest.raises(RulesetError, match="more than one default rule"):
        parse_ruleset(data)


def test_a_default_declared_by_another_kind_is_rejected() -> None:
    """A `linkage` rule claiming [[crypto_library]] would silence both bundled rules."""
    data = minimal()
    data["rule"].append(
        dict(
            data["rule"][0],
            id="BIN_LINKED_CRYPTO_LIBRARY",
            layer="binary",
            match={
                "kind": "linkage",
                "table": "crypto_library",
                "value": "bundled",
                "default": True,
            },
        )
    )
    with pytest.raises(RulesetError, match="cannot be the default"):
        parse_ruleset(data)


def test_a_default_on_a_table_that_never_falls_back_is_rejected() -> None:
    data = minimal()
    data["rule"][0]["match"]["default"] = True
    with pytest.raises(RulesetError, match="never fall back"):
        parse_ruleset(data)


def test_an_entry_routed_to_a_rule_that_ignores_routing_is_rejected() -> None:
    """`rule` on a library entry routes the bundled-library finding and nothing else.

    A `linkage` rule reads the same table and ignores `rule` entirely, so accepting
    this would drop the entry's real finding and put nothing in its place.
    """
    data = minimal()
    data["rule"].append(
        dict(
            data["rule"][0],
            id="BIN_LINKED_CRYPTO_LIBRARY",
            layer="binary",
            match={"kind": "linkage", "name": "openssl", "value": "bundled"},
        )
    )
    data["crypto_library"][0]["rule"] = "BIN_LINKED_CRYPTO_LIBRARY"
    with pytest.raises(RulesetError, match="never reads"):
        parse_ruleset(data)


def test_routing_is_declared_against_real_tables_and_matchers() -> None:
    """A typo in the routing map would reject a legal ruleset, or accept a dead one."""
    assert set(ROUTED_KINDS) <= set(ENTRY_TABLES)
    assert set().union(*ROUTED_KINDS.values()) <= MATCHER_KINDS
    assert DEFAULTABLE_TABLES <= set(ROUTED_KINDS)


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
        # A Unix name that ends in a version keeps it: there the digits are the name.
        ("libfoo-2.so", "libfoo-2", False),
        ("libnss3.so", "libnss3", False),
    ],
)
def test_soname_normalisation(soname: str, base: str, mangled: bool) -> None:
    conventions = parse_ruleset(minimal()).conventions
    result = conventions.normalise_soname(soname)
    assert (result.base, result.mangled) == (base, mangled)


@pytest.mark.parametrize(
    ("soname", "base", "mangled"),
    [
        ("libcrypto-3-x64.dll", "libcrypto", False),
        ("libcrypto-3.dll", "libcrypto", False),
        ("libssl-1_1-x64.dll", "libssl", False),
        ("libssl-3-arm64.dll", "libssl", False),
        # The decoration is a token, not four enumerated architectures: a vendor
        # spelling nobody listed must not leave the name resolving to no library at all.
        ("libcrypto-3-aarch64.dll", "libcrypto", False),
        ("libgnutls-30.dll", "libgnutls", False),
        ("libgcrypt-20.dll", "libgcrypt", False),
        # The hash goes first, so a vendored copy is still recognisably vendored.
        ("libcrypto-3-x64-a1b2c3d4.dll", "libcrypto", True),
        # Windows file names are case-insensitive, and so is the import that names one.
        ("LIBCRYPTO-3-X64.dll", "libcrypto", False),
        ("libcrypto-3-x64.DLL", "libcrypto", False),
        # Nothing to undo: no version in the stem, and no version suffix either.
        ("libcrypto.dll", "libcrypto", False),
        ("python312.dll", "python312", False),
        ("_ext.pyd", "_ext", False),
    ],
)
def test_windows_soname_normalisation(soname: str, base: str, mangled: bool) -> None:
    """Windows spells the version in the stem, so the stem is where it is undone."""
    conventions = parse_ruleset(minimal()).conventions
    result = conventions.normalise_soname(soname)
    assert (result.base, result.mangled) == (base, mangled)


def test_a_windows_suffix_that_is_never_stripped_is_refused() -> None:
    """It would never be seen, so the reduction it gates would silently never happen."""
    data = minimal()
    data["conventions"]["windows_library_suffixes"] = [".dll", ".exe"]
    with pytest.raises(RulesetError, match="windows_library_suffixes"):
        parse_ruleset(data)


def test_a_non_table_conventions_is_rejected() -> None:
    """A bare string would otherwise reach `conventions[key]` for the Go group check
    and crash with a bare `TypeError`, not the `RulesetError` a malformed ruleset
    should raise."""
    data = minimal()
    data["conventions"] = "x"
    with pytest.raises(RulesetError, match=r"\[conventions\]: must be a table"):
        parse_ruleset(data)


@pytest.mark.parametrize(
    "key",
    ["vendor_dir_globs", "weak_hash_algorithms", "library_suffixes", "windows_library_suffixes"],
)
def test_a_bare_string_conventions_list_is_rejected(key: str) -> None:
    """A bare string is iterable character by character, so `tuple(...)`/
    `frozenset(...)` would otherwise turn e.g. `vendor_dir_globs = "abc"` into the
    three single-character globs `('a', 'b', 'c')` instead of refusing it."""
    data = minimal()
    data["conventions"][key] = "abc"
    with pytest.raises(RulesetError, match=f"{key} must be a list of strings"):
        parse_ruleset(data)


def test_own_base_falls_back_to_the_file_name() -> None:
    """A build that stripped the SONAME out must not hide a vendored copy."""
    conventions = parse_ruleset(minimal()).conventions
    assert conventions.own_base("libcrypto-3a1f2b4c.so.3", "pkg.libs/renamed.so") == "libcrypto"
    assert conventions.own_base(None, "pkg.libs/libcrypto-3a1f2b4c.so.3") == "libcrypto"
    assert conventions.own_base("", "pkg.libs/libssl.so.3") == "libssl"


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
    patterns = parse_ruleset(minimal()).compile_patterns().binary
    assert patterns.symbol_groups_for("EVP_DigestInit_ex") == ("openssl",)


def test_symbol_group_matches_an_exact_name() -> None:
    patterns = parse_ruleset(minimal()).compile_patterns().binary
    assert patterns.symbol_groups_for("RAND_bytes") == ("openssl",)


def test_symbol_group_ignores_an_unrelated_name() -> None:
    patterns = parse_ruleset(minimal()).compile_patterns().binary
    assert patterns.symbol_groups_for("PyInit__foo") == ()


def test_symbol_group_results_are_sorted() -> None:
    """Two groups can claim one symbol; the order must not depend on table order."""
    data = minimal()
    data["symbol_group"].insert(0, {"name": "zzz", "prefixes": ["EVP_"], "exact": [], "why": "x"})
    patterns = parse_ruleset(data).compile_patterns().binary
    assert patterns.symbol_groups_for("EVP_DigestInit_ex") == ("openssl", "zzz")


def test_the_locator_finds_every_name_the_symbol_matcher_claims() -> None:
    """The locator is a filter, and a filter that drops a match loses evidence silently.

    `binfmt.macho` uses it to decide which runs of a string table are worth decoding at
    all, so a name it misses is a symbol that never reaches `symbol_groups_for` and an
    object that hides one reads clean. Over the shipped ruleset rather than a minimal
    one, because the names that matter are the ones the tool actually claims.
    """
    patterns = load_ruleset().compile_patterns().binary
    assert patterns.symbol_locator is not None
    names = [name for group in patterns.symbol_groups for name in sorted(group.exact)]
    names += [
        prefix + tail
        for group in patterns.symbol_groups
        for prefix in group.prefixes
        for tail in ("", "Init_ex", "9")
    ]
    for name in names:
        assert patterns.symbol_groups_for(name), name
        # As written, with a Darwin underscore, and with a byte `sanitize` removes.
        for raw in (name.encode(), b"_" + name.encode(), name.encode().replace(b"_", b"\x81_", 1)):
            assert patterns.symbol_locator.search(raw), raw


def test_the_locator_is_told_when_the_symbol_matcher_grows_an_arm() -> None:
    """`could this name match` is spelled twice: as a matcher and as a byte locator.

    They agree today because `SymbolGroup.matches` is exactly "exact, or prefix", and
    `_symbol_locator` is built from those two fields. A third field would be claimed by
    the matcher and invisible to the locator, and nothing else in the suite would say
    so: the failure is a hidden symbol going unfound, not an error.
    """
    assert {field.name for field in fields(SymbolGroup)} == {"name", "prefixes", "exact"}


def test_string_group_exposes_a_compiled_pattern() -> None:
    patterns = parse_ruleset(minimal()).compile_patterns().binary
    group = patterns.string_group("openssl_banner")
    assert isinstance(group.pattern, re.Pattern)
    assert group.pattern.search("OpenSSL 3.0.14 4 Jun 2024")


def test_string_group_pattern_escapes_regex_metacharacters() -> None:
    """Substrings are literal text. A dot must not match any character."""
    patterns = parse_ruleset(minimal()).compile_patterns().binary
    assert patterns.string_group("openssl_banner").pattern.search("OpenSSL 3x0") is None


def test_string_group_refuses_a_substring_outside_printable_ascii() -> None:
    """`match_string_groups` recovers a hit's run by searching for "\\n" boundaries.

    A substring that is not printable ASCII can only ever match by reaching across the
    "\\n" `extract_printable` joins runs with -- never bytes an object actually carries
    -- and letting one through would let a single hit's enclosing-run search swallow
    the run after it. Refused at load time, the same way an empty substring list is.
    """
    data = minimal()
    # Appended rather than swapped in: a ruleset missing the groups [conventions] names
    # is refused for that instead, and this test is about the substring.
    data["string_group"].append({"name": "g", "substrings": ["a\nb"], "why": "bad"})
    with pytest.raises(RulesetError, match="printable ASCII"):
        parse_ruleset(data)


def test_cargo_path_regex_extracts_crate_and_version() -> None:
    patterns = parse_ruleset(minimal()).compile_patterns().binary
    match = patterns.cargo_path_regex.search(
        "/root/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ring-0.17.8/src/lib.rs"
    )
    assert match is not None
    assert (match.group("name"), match.group("version")) == ("ring", "0.17.8")


def test_cargo_path_regex_extracts_crate_and_version_from_a_distro_layout() -> None:
    """The shipped pattern's `src/<index>/` segment is optional; this loader-parsed
    minimal one keeps it mandatory, so this exercises the shipped ruleset directly."""
    patterns = load_ruleset().compile_patterns().binary
    match = patterns.cargo_path_regex.search(
        "/usr/share/cargo/registry/openssl-0.10.81/src/ssl/mod.rs"
    )
    assert match is not None
    assert (match.group("name"), match.group("version")) == ("openssl", "0.10.81")


def test_cargo_vendor_path_regex_is_compiled_and_exposed() -> None:
    patterns = parse_ruleset(minimal()).compile_patterns().binary
    match = patterns.cargo_vendor_path_regex.search("vendor/openssl-sys/src/lib.rs")
    assert match is not None
    assert match.group("name") == "openssl-sys"


def test_cargo_path_regex_without_a_version_group_is_refused() -> None:
    data = minimal()
    data["conventions"]["cargo_path_regex"] = r"cargo/registry/(?P<name>[a-z-]+)/"
    with pytest.raises(RulesetError, match="needs a 'version' group"):
        parse_ruleset(data)


def test_cargo_vendor_path_regex_without_a_version_group_is_refused() -> None:
    data = minimal()
    data["conventions"]["cargo_vendor_path_regex"] = r"vendor/(?P<name>[a-z-]+)/"
    with pytest.raises(RulesetError, match="needs a 'version' group"):
        parse_ruleset(data)


def test_cargo_vendor_path_regex_without_a_name_group_is_refused() -> None:
    data = minimal()
    data["conventions"]["cargo_vendor_path_regex"] = r"vendor/(?P<version>[0-9.]+)/"
    with pytest.raises(RulesetError, match="needs a 'name' group"):
        parse_ruleset(data)


def test_python_module_names_are_available_to_the_ast_scanner() -> None:
    patterns = parse_ruleset(minimal()).compile_patterns().python
    assert "nacl" in patterns.py_modules


def test_ctypes_substrings_are_available_to_the_ast_scanner() -> None:
    patterns = parse_ruleset(minimal()).compile_patterns().python
    assert "libcrypto" in patterns.ctypes_substrings


def test_shipped_patterns_expose_the_python_call_targets() -> None:
    patterns = load_ruleset().compile_patterns().python
    assert "hashlib.md5" in patterns.py_call_targets
    assert "hashlib.new" in patterns.py_call_targets


def test_shipped_patterns_expose_tls_attributes_and_constants() -> None:
    patterns = load_ruleset().compile_patterns().python
    assert "check_hostname" in patterns.py_attributes
    assert "ssl.CERT_NONE" in patterns.py_constants


def test_compiled_pattern_sequences_are_sorted() -> None:
    """Extractors iterate these; unsorted input would leak into the output order."""
    patterns = load_ruleset().compile_patterns()
    assert list(patterns.python.py_call_targets) == sorted(patterns.python.py_call_targets)
    assert list(patterns.python.py_modules) == sorted(patterns.python.py_modules)
    assert [g.name for g in patterns.binary.symbol_groups] == sorted(
        g.name for g in patterns.binary.symbol_groups
    )


def _with_partial_rule(**match) -> dict:
    """`minimal()` plus one `partial_binary` rule, so the existing one keeps its table."""
    data = minimal()
    data["rule"].append(
        {
            "id": "BIN_PARTIAL_TEST",
            "layer": "binary",
            "category": "opacity",
            "severity": "low",
            "confidence": "high",
            "needs_human_review": True,
            "title": "t",
            "why": "w",
            "match": {"kind": "partial_binary", **match},
        }
    )
    return data


def test_an_unknown_partial_reason_is_rejected() -> None:
    """A typo'd token is a rule that matches nothing, silently, for ever."""
    with pytest.raises(RulesetError, match="unknown partial reason"):
        parse_ruleset(_with_partial_rule(reasons=["pe_ordinal_imprt"]))


def test_an_unknown_excluded_partial_reason_is_rejected() -> None:
    with pytest.raises(RulesetError, match="unknown partial reason"):
        parse_ruleset(_with_partial_rule(exclude_reasons=["nope"]))


def test_naming_both_partial_reason_keys_is_rejected() -> None:
    """They are alternatives: together they would read as a contradiction."""
    data = _with_partial_rule(reasons=["pe_ordinal_import"], exclude_reasons=["pe_delay_load"])
    with pytest.raises(RulesetError, match="alternatives"):
        parse_ruleset(data)


def test_a_partial_binary_rule_may_name_neither_key() -> None:
    """No filter means the rule speaks for every cause."""
    ruleset = parse_ruleset(_with_partial_rule())
    assert [dict(m) for m in ruleset.rule("BIN_PARTIAL_TEST").matches] == [
        {"kind": "partial_binary"}
    ]


# --- linkage object_values / exclude_object_values ---------------------------------


def _with_linkage_rule(**match) -> dict:
    """`minimal()` plus one `linkage` rule naming `openssl`."""
    data = minimal()
    data["rule"].append(
        {
            "id": "LINKAGE_OBJECT_VALUES_TEST",
            "layer": "derived",
            "category": "opacity",
            "severity": "low",
            "confidence": "high",
            "needs_human_review": True,
            "title": "t",
            "why": "w",
            "match": {"kind": "linkage", "name": "openssl", "value": "system", **match},
        }
    )
    return data


def test_an_unknown_object_value_is_rejected() -> None:
    with pytest.raises(RulesetError, match="linkage value"):
        parse_ruleset(_with_linkage_rule(object_values=["unknwon"]))


def test_an_unknown_excluded_object_value_is_rejected() -> None:
    with pytest.raises(RulesetError, match="linkage value"):
        parse_ruleset(_with_linkage_rule(exclude_object_values=["unknwon"]))


def test_naming_both_object_value_keys_is_rejected() -> None:
    """They are alternatives: together they would read as a contradiction."""
    with pytest.raises(RulesetError, match="alternatives"):
        parse_ruleset(_with_linkage_rule(object_values=["unknown"], exclude_object_values=["none"]))


def test_an_empty_exclude_object_values_is_rejected() -> None:
    """An empty exclude list would silently mean `always`, the same typo-shaped
    failure mode `usedforsecurity` and `reasons`/`exclude_reasons` are refused for."""
    with pytest.raises(RulesetError, match="exclude_object_values"):
        parse_ruleset(_with_linkage_rule(exclude_object_values=[]))


def test_an_empty_object_values_is_rejected() -> None:
    """An empty list would silently mean `never`."""
    with pytest.raises(RulesetError, match="object_values"):
        parse_ruleset(_with_linkage_rule(object_values=[]))


# --- matcher kind drift -------------------------------------------------------------


def test_every_matcher_kind_has_a_dispatch_function() -> None:
    """`MATCHER_KINDS` is what the loader accepts; `engine._MATCHERS` is what actually
    runs. A kind added to one without the other loads clean and either silently
    matches nothing (`engine.apply_rules` skips a match whose kind
    `_MATCHERS.get(...)` returns `None` for) or leaves the loader refusing a kind the
    engine can dispatch. Nothing else pins the two in step, so this does.
    """
    # pylint: disable=protected-access
    assert set(MATCHER_KINDS) == set(engine._MATCHERS)


def test_match_keys_covers_every_matcher_kind() -> None:
    """`MATCHER_KINDS` is derived from `MATCH_KEYS`, so this is the same drift guard as
    the one above, pinned against the dict the derivation actually reads."""
    # pylint: disable=protected-access
    assert set(MATCH_KEYS) == set(engine._MATCHERS)


def test_entry_key_sets_cover_every_entry_table() -> None:
    """A new `[[table]]` with no allowed-key set of its own gives every one of its
    entries a `KeyError` the first time the loader looks one up, rather than a
    `RulesetError`."""
    # pylint: disable=protected-access
    assert set(ruleset_loader._ENTRY_KEYS) == set(ENTRY_TABLES)


# --- match key drift: every key a matcher reads is one MATCH_KEYS allows, both ways --

_ENGINE_SOURCE = ast.parse(inspect.getsource(engine))
_ENGINE_FUNCTIONS: dict[str, ast.FunctionDef] = {
    node.name: node for node in ast.walk(_ENGINE_SOURCE) if isinstance(node, ast.FunctionDef)
}

_LOADER_CHECKED_KEYS = frozenset({"kind", "table", "default"})


def _reads_of_match(
    fn: ast.FunctionDef,
    funcs: dict[str, ast.FunctionDef],
    param: str = "match",
    _visited: frozenset[str] = frozenset(),
) -> tuple[set[str], list[str]]:
    """Every key one matcher function reads off its match table, bound in `fn` under
    the name `param`, and every read of `param` this collector could not classify.

    Recognises `param["k"]`, `param.get("k", ...)`, `"k" in param`/`"k" not in param`, a
    call to another module-level function passing `param` positionally (recursing into
    it under whatever name the callee's parameter at that position has, which is how
    `_groups(match)` contributes `group`/`groups`), and a call to
    `ruleset.default_rule_for_table(...)`, which reads `default` and `table` off the
    match table `parse_ruleset` built without this function seeing either name directly.

    Every other `ast.Name(id=param)` load inside `fn` is reported back as unrecognised,
    so a form this collector cannot see -- `param[key]` with a variable key, or
    `dict(param)` -- fails the test that calls this rather than silently reading as
    "nothing".
    """
    keys: set[str] = set()
    unrecognised: list[str] = []
    consumed: set[int] = set()
    match_loads: list[ast.Name] = []

    class _Visitor(ast.NodeVisitor):
        def visit_Name(self, node: ast.Name) -> None:  # noqa: N802
            if node.id == param and isinstance(node.ctx, ast.Load):
                match_loads.append(node)
            self.generic_visit(node)

        def visit_Subscript(self, node: ast.Subscript) -> None:  # noqa: N802
            if isinstance(node.value, ast.Name) and node.value.id == param:
                consumed.add(id(node.value))
                key = node.slice
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    keys.add(key.value)
                else:
                    unrecognised.append(f"{fn.name}: {param}[...] with a non-literal key")
            self.generic_visit(node)

        def visit_Compare(self, node: ast.Compare) -> None:  # noqa: N802
            for op, comparator in zip(node.ops, node.comparators, strict=True):
                if (
                    isinstance(op, (ast.In, ast.NotIn))
                    and isinstance(comparator, ast.Name)
                    and comparator.id == param
                ):
                    consumed.add(id(comparator))
                    left = node.left
                    if isinstance(left, ast.Constant) and isinstance(left.value, str):
                        keys.add(left.value)
                    else:
                        unrecognised.append(f"{fn.name}: 'x' in {param} with a non-literal key")
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "get"
                and isinstance(func.value, ast.Name)
                and func.value.id == param
            ):
                consumed.add(id(func.value))
                if node.args and isinstance(node.args[0], ast.Constant):
                    if isinstance(node.args[0].value, str):
                        keys.add(node.args[0].value)
                    else:
                        unrecognised.append(f"{fn.name}: {param}.get(...) with a non-string key")
                else:
                    unrecognised.append(f"{fn.name}: {param}.get(...) with a non-literal key")
            elif isinstance(func, ast.Attribute) and func.attr == "default_rule_for_table":
                keys.update({"default", "table"})
            elif isinstance(func, ast.Name) and func.id in funcs and func.id not in _visited:
                callee = funcs[func.id]
                callee_params = [a.arg for a in callee.args.args]
                for position, arg in enumerate(node.args):
                    if not (isinstance(arg, ast.Name) and arg.id == param):
                        continue
                    consumed.add(id(arg))
                    if position >= len(callee_params):
                        unrecognised.append(
                            f"{fn.name}: {param} passed to {func.id} at a position it "
                            "declares no parameter for"
                        )
                        continue
                    sub_keys, sub_unrecognised = _reads_of_match(
                        callee, funcs, callee_params[position], _visited | {func.id}
                    )
                    keys.update(sub_keys)
                    unrecognised.extend(sub_unrecognised)
            self.generic_visit(node)

    _Visitor().visit(fn)
    for node in match_loads:
        if id(node) not in consumed:
            unrecognised.append(f"{fn.name}: unrecognised read of {param}")
    return keys, unrecognised


def _reads(kind: str) -> set[str]:
    fn = engine._MATCHERS[kind]  # pylint: disable=protected-access
    ast_fn = _ENGINE_FUNCTIONS[fn.__name__]
    # The dispatcher (`engine.apply_rules`) passes the match table positionally --
    # `matcher(rule, match, ...)` -- so nothing requires a matcher's own second
    # parameter to be named `match`. Reading it off `ast_fn` itself, rather than
    # assuming the literal name `_reads_of_match`'s default is built for, is what makes
    # a matcher that names it something else still have its reads collected.
    param = ast_fn.args.args[1].arg
    keys, unrecognised = _reads_of_match(ast_fn, _ENGINE_FUNCTIONS, param)
    assert not unrecognised, unrecognised
    return keys


def _funcs(source: str) -> dict[str, ast.FunctionDef]:
    tree = ast.parse(source)
    return {node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}


def test_a_helper_whose_parameter_is_not_named_match_still_contributes_its_reads() -> None:
    """A module-level helper called with the match table positionally is followed by
    parameter position, not by the literal name `match`: a helper that names its own
    parameter something else still has its reads attributed to the caller.

    Breaks to prove it: recurse with the literal string `"match"` in place of
    `callee_params[position]`. The helper's parameter here is named `table`, so its
    body's `table.get(...)` is never recognised as a read of anything, `renamed`
    disappears from the collected keys, and this assertion fails.
    """
    funcs = _funcs(
        "def _match_thing(rule, match, ruleset, evidence, linkage, index):\n"
        "    return _helper(match)\n"
        "def _helper(table):\n"
        "    return table.get('renamed')\n"
    )
    keys, unrecognised = _reads_of_match(funcs["_match_thing"], funcs)
    assert not unrecognised
    assert keys == {"renamed"}


def test_a_positional_argument_past_the_callees_parameters_is_unrecognised() -> None:
    """The match table passed to a helper beyond the positional parameters that
    helper declares cannot be attributed to any name in the callee, so it is reported
    as unrecognised rather than silently dropped."""
    funcs = _funcs(
        "def _match_thing(rule, match, ruleset, evidence, linkage, index):\n"
        "    return _helper(1, match)\n"
        "def _helper(only):\n"
        "    return only\n"
    )
    keys, unrecognised = _reads_of_match(funcs["_match_thing"], funcs)
    assert not keys
    assert unrecognised


def test_every_key_a_matcher_reads_is_an_allowed_key() -> None:
    """Every key an `engine` matcher reads off `match`, for every kind, is one
    `MATCH_KEYS` allows for that kind. Also checks the collector itself is not vacuous:
    dropping `any_entry` from `MATCH_KEYS["requires_dist"]`, or adding a read
    `_match_py_constant` never had, fails this the same way a real drift would.
    """
    for kind in MATCH_KEYS:
        assert _reads(kind) <= MATCH_KEYS[kind], kind
    assert "any_entry" in _reads("requires_dist")
    assert {"group", "groups"} <= _reads("binary_string")
    assert {"default", "table"} <= _reads("rust_crate")


def test_every_allowed_match_key_is_read_or_loader_checked() -> None:
    """A key `MATCH_KEYS` allows for a kind but no matcher ever reads is a hole: it
    loads clean and does nothing, the same failure mode an unknown key is refused for.
    `kind`, `table` and `default` are the loader-checked exceptions: `table`/`default`
    are validated against `ENTRY_TABLES` and the default-routing checks in
    `parse_ruleset`, and `kind` selects the matcher itself.
    """
    for kind, allowed in MATCH_KEYS.items():
        assert allowed - _reads(kind) <= _LOADER_CHECKED_KEYS, kind


def test_reads_follows_a_matchers_own_parameter_name_not_the_literal_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`engine.apply_rules` calls every matcher positionally
    (`matcher(rule, match, ...)`), so nothing requires a matcher's own second parameter
    to be named `match`. `_reads` has to follow that parameter by position, the same way
    the dispatcher does, or a matcher that names it something else reads clean of every
    key it actually reads.

    Breaks to prove it: hardcode `param="match"` in `_reads` in place of the matcher's
    own declared parameter name. `_match_fake` never binds anything named `match`, so
    `_reads_of_match` finds no read of it, `_reads` comes back empty, and the assertion
    that `strict` was collected fails.
    """
    source = (
        "def _match_fake(rule, spec, ruleset, evidence, linkage, index):\n"
        "    if spec.get('strict'):\n"
        "        return\n"
    )
    fake_fn = _funcs(source)["_match_fake"]

    def _match_fake() -> None:  # pragma: no cover - never called, only introspected
        raise NotImplementedError

    # pylint: disable=protected-access
    monkeypatch.setitem(engine._MATCHERS, "_test_fake_kind", _match_fake)
    monkeypatch.setitem(_ENGINE_FUNCTIONS, "_match_fake", fake_fn)

    assert _reads("_test_fake_kind") == {"strict"}


def test_every_matcher_kind_declares_a_location_class() -> None:
    """`MATCHER_LOCATIONS` is what the loader's `_check_suppression_can_fire` reads;
    a kind added to `MATCHER_KINDS` without a location here would go unchecked
    silently, the same drift the dispatch-function test above holds for `_MATCHERS`.
    """
    assert set(MATCHER_LOCATIONS) == set(MATCHER_KINDS)


# --- py_call match fields ------------------------------------------------------------


def _with_py_call_rule(**match) -> dict:
    """`minimal()` plus one `py_call` rule, so the existing one keeps its table.

    `targets` defaults to a non-empty list, since it is required, so a test about some
    other field does not also have to spell it out.
    """
    match.setdefault("targets", ["hashlib.md5"])
    data = minimal()
    data["rule"].append(
        {
            "id": "PY_CALL_TEST",
            "layer": "python",
            "category": "crypto-usage",
            "severity": "low",
            "confidence": "high",
            "needs_human_review": False,
            "title": "t",
            "why": "w",
            "match": {"kind": "py_call", **match},
        }
    )
    return data


def test_a_py_call_rule_with_a_scalar_usedforsecurity_loads_clean() -> None:
    ruleset = parse_ruleset(_with_py_call_rule(usedforsecurity="absent"))
    assert ruleset.rule("PY_CALL_TEST").matches[0]["usedforsecurity"] == "absent"


def test_a_py_call_rule_with_a_list_usedforsecurity_loads_clean() -> None:
    ruleset = parse_ruleset(_with_py_call_rule(usedforsecurity=["absent", "true"]))
    assert ruleset.rule("PY_CALL_TEST").matches[0]["usedforsecurity"] == ["absent", "true"]


def test_an_unknown_scalar_usedforsecurity_value_is_rejected() -> None:
    """A typo'd token loads clean today and never matches anything, silently."""
    with pytest.raises(RulesetError, match="unknown usedforsecurity value"):
        parse_ruleset(_with_py_call_rule(usedforsecurity="tru"))


def test_an_unknown_usedforsecurity_list_element_is_rejected() -> None:
    with pytest.raises(RulesetError, match="unknown usedforsecurity value"):
        parse_ruleset(_with_py_call_rule(usedforsecurity=["absent", "tru"]))


def test_a_boolean_usedforsecurity_is_rejected_rather_than_crashing_at_scan_time() -> None:
    """A bare TOML `true` parses to a Python bool, and `attrs.get(...) not in
    want_used` raises `TypeError: argument of type 'bool' is not a container or
    iterable` at scan time when `usedforsecurity` is that bool. The loader must catch
    this shape instead of letting a custom ruleset load clean and then crash the CLI.
    """
    with pytest.raises(RulesetError, match="usedforsecurity must be a string or list of strings"):
        parse_ruleset(_with_py_call_rule(usedforsecurity=True))


def test_a_non_boolean_non_string_usedforsecurity_is_rejected() -> None:
    with pytest.raises(RulesetError, match="usedforsecurity must be a string or list of strings"):
        parse_ruleset(_with_py_call_rule(usedforsecurity=42))


def test_a_dict_usedforsecurity_is_rejected() -> None:
    """A dict is `Iterable` and iterating it yields its keys, so a naive `Iterable`
    check would let `usedforsecurity = {"absent" = true}` through as if it were the
    list `["absent"]`. It must be refused instead."""
    with pytest.raises(RulesetError, match="usedforsecurity must be a string or list of strings"):
        parse_ruleset(_with_py_call_rule(usedforsecurity={"absent": True}))


def test_an_empty_usedforsecurity_list_is_rejected() -> None:
    """`attrs.get(...) not in []` is always true, so this would load clean and never
    match anything -- the same silent failure as a typo, spelled differently."""
    with pytest.raises(RulesetError, match="usedforsecurity must not be an empty list"):
        parse_ruleset(_with_py_call_rule(usedforsecurity=[]))


def test_a_boolean_targets_is_rejected_rather_than_crashing_at_scan_time() -> None:
    """`frozenset(match.get("targets", ()))` raises the identical `TypeError` when
    `targets` is a bool."""
    with pytest.raises(RulesetError, match="targets must be a list of strings"):
        parse_ruleset(_with_py_call_rule(targets=True))


def test_a_non_string_element_in_targets_is_rejected() -> None:
    with pytest.raises(RulesetError, match="targets must be a list of strings"):
        parse_ruleset(_with_py_call_rule(targets=["hashlib.md5", 3]))


def test_a_bare_string_targets_is_rejected() -> None:
    """`targets` has no scalar-string shorthand the way `usedforsecurity` does, so a
    bare string here is not one target, it is `frozenset()` silently iterating its
    characters."""
    with pytest.raises(RulesetError, match="targets must be a list of strings"):
        parse_ruleset(_with_py_call_rule(targets="hashlib.md5"))


def test_a_missing_targets_is_rejected() -> None:
    """Without `targets`, `_target_matches` never returns true for any site, so the
    rule would load clean and never fire."""
    data = minimal()
    data["rule"].append(
        {
            "id": "PY_CALL_TEST",
            "layer": "python",
            "category": "crypto-usage",
            "severity": "low",
            "confidence": "high",
            "needs_human_review": False,
            "title": "t",
            "why": "w",
            "match": {"kind": "py_call"},
        }
    )
    with pytest.raises(RulesetError, match="missing required field 'targets'"):
        parse_ruleset(data)


def test_an_empty_targets_list_is_rejected() -> None:
    with pytest.raises(RulesetError, match="targets must not be an empty list"):
        parse_ruleset(_with_py_call_rule(targets=[]))


def test_a_valid_targets_list_loads_clean() -> None:
    ruleset = parse_ruleset(_with_py_call_rule(targets=["hashlib.md5", "*.encrypt"]))
    assert ruleset.rule("PY_CALL_TEST").matches[0]["targets"] == ["hashlib.md5", "*.encrypt"]


def test_a_non_string_algorithm_is_rejected() -> None:
    """`algorithm` is an open vocabulary -- any hash name a wheel's source might use --
    so only its type is checked here, never its value against a closed list."""
    with pytest.raises(RulesetError, match="algorithm must be a string"):
        parse_ruleset(_with_py_call_rule(algorithm=True))


def test_a_strong_algorithm_name_not_in_weak_hash_algorithms_loads_clean() -> None:
    """`algorithm` matching a rule intentionally naming a strong hash must not be
    rejected just because it is absent from `conventions.weak_hash_algorithms`, the
    same way the shipped `PY_WEAK_HASH_UNRESOLVED` rule's `algorithm = "unresolved"`
    match (`data/ruleset.toml`) is not a member of that set either."""
    ruleset = parse_ruleset(_with_py_call_rule(algorithm="sha3_256"))
    assert ruleset.rule("PY_CALL_TEST").matches[0]["algorithm"] == "sha3_256"


def test_a_boolean_weak_algorithms_only_loads_clean() -> None:
    ruleset = parse_ruleset(_with_py_call_rule(weak_algorithms_only=True))
    assert ruleset.rule("PY_CALL_TEST").matches[0]["weak_algorithms_only"] is True


def test_a_string_weak_algorithms_only_is_rejected() -> None:
    """The same class of mistake, one field over: `weak_only = bool(match.get(...))`
    makes `weak_algorithms_only = "false"` evaluate to `True`, the opposite of what a rule
    author who wrote that string almost certainly meant, with no crash and no error to
    notice it by."""
    with pytest.raises(RulesetError, match="weak_algorithms_only must be a boolean"):
        parse_ruleset(_with_py_call_rule(weak_algorithms_only="false"))


def test_a_py_attr_rule_requires_attributes() -> None:
    data = minimal()
    data["rule"].append(
        {
            "id": "PY_ATTR_TEST",
            "layer": "python",
            "category": "crypto-usage",
            "severity": "low",
            "confidence": "high",
            "needs_human_review": False,
            "title": "t",
            "why": "w",
            "match": {"kind": "py_attr"},
        }
    )
    with pytest.raises(RulesetError, match="missing required field 'attributes'"):
        parse_ruleset(data)


def _with_py_attr_rule(**match) -> dict:
    match.setdefault("attributes", ["check_hostname"])
    data = minimal()
    data["rule"].append(
        {
            "id": "PY_ATTR_TEST",
            "layer": "python",
            "category": "crypto-usage",
            "severity": "low",
            "confidence": "high",
            "needs_human_review": False,
            "title": "t",
            "why": "w",
            "match": {"kind": "py_attr", **match},
        }
    )
    return data


def test_a_boolean_attributes_is_rejected_rather_than_crashing_at_scan_time() -> None:
    """The same crash applies to `_match_py_attr`'s
    `frozenset(match.get("attributes", ()))`."""
    with pytest.raises(RulesetError, match="attributes must be a list of strings"):
        parse_ruleset(_with_py_attr_rule(attributes=True))


def test_a_boolean_values_is_rejected_rather_than_crashing_at_scan_time() -> None:
    """`_match_py_attr` does `_attrs(site).get("value") not in values`, the identical
    `TypeError` shape as `py_call`'s `usedforsecurity`, when `values` is a bool."""
    with pytest.raises(RulesetError, match="values must be a list of strings"):
        parse_ruleset(_with_py_attr_rule(values=True))


def test_an_empty_values_list_is_rejected() -> None:
    with pytest.raises(RulesetError, match="values must not be an empty list"):
        parse_ruleset(_with_py_attr_rule(values=[]))


def test_a_valid_py_attr_rule_loads_clean() -> None:
    ruleset = parse_ruleset(_with_py_attr_rule(attributes=["check_hostname"], values=["False"]))
    assert ruleset.rule("PY_ATTR_TEST").matches[0]["values"] == ["False"]


def test_a_py_constant_rule_requires_constants() -> None:
    data = minimal()
    data["rule"].append(
        {
            "id": "PY_CONSTANT_TEST",
            "layer": "python",
            "category": "crypto-usage",
            "severity": "low",
            "confidence": "high",
            "needs_human_review": False,
            "title": "t",
            "why": "w",
            "match": {"kind": "py_constant"},
        }
    )
    with pytest.raises(RulesetError, match="missing required field 'constants'"):
        parse_ruleset(data)


def test_a_boolean_constants_is_rejected_rather_than_crashing_at_scan_time() -> None:
    data = minimal()
    data["rule"].append(
        {
            "id": "PY_CONSTANT_TEST",
            "layer": "python",
            "category": "crypto-usage",
            "severity": "low",
            "confidence": "high",
            "needs_human_review": False,
            "title": "t",
            "why": "w",
            "match": {"kind": "py_constant", "constants": True},
        }
    )
    with pytest.raises(RulesetError, match="constants must be a list of strings"):
        parse_ruleset(data)


@pytest.mark.parametrize("key", ["targets", "attributes", "constants"])
def test_generic_match_sequence_keys_are_refused_on_a_kind_that_never_reads_them(
    key: str,
) -> None:
    """`Ruleset.compile_patterns` reads `GENERIC_MATCH_SEQUENCE_KEYS` off every match
    table regardless of kind, so a stray boolean in any of the three would crash it even
    for a kind, such as `dist_name`, that never reads the field itself. `MATCH_KEYS`
    refuses the key outright on such a kind at load time, before it can reach that
    point. Parametrized over all three keys rather than just `targets`, so dropping any
    one of them from `MATCH_KEYS`'s refusal fails here instead of only being covered for
    the key one test happened to pick.
    """
    data = minimal()
    data["rule"][0]["match"] = {"kind": "dist_name", "table": "crypto_distribution", key: True}
    with pytest.raises(RulesetError, match=rf"unknown keys \['{key}'\]"):
        parse_ruleset(data)


def test_a_valid_py_call_rule_still_matches_evidence_end_to_end() -> None:
    """Validation must not reject a shape it should allow: a `py_call` rule with
    well-typed `targets`, `algorithm` and a list `usedforsecurity` still produces a
    finding against a wheel carrying the matching evidence."""
    data = _with_py_call_rule(
        targets=["hashlib.new"], algorithm="md5", usedforsecurity=["absent", "true"]
    )
    ruleset = parse_ruleset(data)
    evidence = Evidence(
        filename="demo-1.0-py3-none-any.whl",
        sha256="0" * 64,
        size_bytes=1,
        artifacts=ArtifactInventory(),
        py_sites=(
            PySite(
                path="demo/mod.py",
                line=1,
                kind="py_call",
                target="hashlib.new",
                detail="hashlib.new(...) at line 1",
                attrs=(("algorithm", "md5"), ("usedforsecurity", "absent")),
            ),
        ),
    )
    findings = engine.apply_rules(ruleset, evidence, resolve_linkage(ruleset, evidence))
    assert [finding.rule_id for finding in findings] == ["PY_CALL_TEST"]


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


@pytest.mark.parametrize(
    ("name", "base", "mangled"),
    [
        ("libcrypto.dll", "libcrypto", False),
        ("libcrypto-3a1f2b4c.dll", "libcrypto", True),
        ("libssl-1_1-x64.dll", "libssl", False),
        # A vendor spelling nobody enumerated: an architecture written as an
        # alternation of four tokens would resolve this to no library at all.
        ("libcrypto-3-aarch64.dll", "libcrypto", False),
        ("_ext.pyd", "_ext", False),
    ],
)
def test_windows_library_names_normalise(name: str, base: str, mangled: bool) -> None:
    info = load_ruleset().conventions.normalise_soname(name)
    assert (info.base, info.mangled) == (base, mangled)
