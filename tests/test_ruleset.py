"""Behaviour of the ruleset loader, its validation and the compiled scan patterns."""

from __future__ import annotations

import re
from dataclasses import fields
from typing import Any

import pytest

from wheel_crypto_scan import engine
from wheel_crypto_scan.errors import RulesetError
from wheel_crypto_scan.evidence import ArtifactInventory, Evidence, PySite
from wheel_crypto_scan.linkage import resolve_linkage
from wheel_crypto_scan.ruleset import (
    DEFAULTABLE_TABLES,
    ENTRY_TABLES,
    MATCHER_KINDS,
    ROUTED_KINDS,
    SymbolGroup,
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
            }
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
    assert ruleset.version == "27"
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

    `openssl_banner` stopped at major 3 while cryptography's own PyPI wheels already
    compiled 4 in (#123), and nothing failed. The negative case pins the cheaper fix
    out: the product name and a space, with no digit, also claims prose such as
    OpenSSL's own "OpenSSL 3's legacy provider failed to load", which a wheel linking
    the system library carries too.
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
    """These entries were added as reach, and reach nothing holds can be flipped or
    deleted without a test moving (#123). An entry's verdict is the whole of what it
    decides, so that is what is pinned: `openssl-src` says a vendored OpenSSL build is
    a condition to confirm, not a non-approved primitive, and the two spellings of
    SHA-1 and of MD5 have to agree with each other or a build pinned to the older name
    reads differently from the same code under the newer one."""
    assert load_ruleset().rust_crates[crate].verdict == verdict


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
    """`excluded_reasons` parses, exempts nothing, and looks exactly like it worked.

    `[conventions]` gets away without this because every key it has is required, so a
    typo drops a required one and errors. This table's only key is optional.
    """
    data = minimal(linkage_policy={"why": "w", "excluded_reasons": ["pe_ordinal_import"]})
    with pytest.raises(RulesetError, match="unknown keys"):
        parse_ruleset(data)


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
    the static copy and no banner -- which is why the ordinal export that used to lean
    on it no longer does.
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


def test_a_crate_entry_with_no_name_is_rejected() -> None:
    """The `suppressed_by` pre-pass reads every entry's name before the per-entry
    `_require` in the main loop runs, so it must raise the same RulesetError itself
    rather than a bare KeyError."""
    data = minimal()
    data["rust_crate"].append({"verdict": "NON_APPROVED_CRYPTO", "why": "no name"})
    with pytest.raises(RulesetError, match="missing required field 'name'"):
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
    """The aws-lc-rs / aws-lc-fips-sys shape: both owned by one rule, one direction
    only. The cycle check must not flag this as a self-rule false positive."""
    data = rust_crate_ruleset()
    data["rust_crate"][0]["suppressed_by"] = ["boring"]
    parse_ruleset(data)


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


def test_aws_lc_rs_suppressed_by_resolves_to_the_fips_sys_finding_key() -> None:
    ruleset = load_ruleset()
    assert ruleset.rust_crates["aws-lc-rs"].suppressed_by == (
        ("BIN_RUST_CRYPTO_CRATE", "aws-lc-fips-sys"),
    )


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
        # The decoration is a token, not four enumerated architectures (#123): a vendor
        # spelling nobody listed used to leave the name resolving to no library at all.
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
    """No filter means the rule speaks for every cause, which is the old behaviour."""
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
    """#82: a bare TOML `true` parses to a Python bool, and `attrs.get(...) not in
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
    """#82: `frozenset(match.get("targets", ()))` raises the identical `TypeError` when
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
    """#82's crash class, one field over: `weak_only = bool(match.get(...))` makes
    `weak_algorithms_only = "false"` evaluate to `True`, the opposite of what a rule
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
    """#82's crash class also applies to `_match_py_attr`'s `frozenset(match.get(
    "attributes", ()))`."""
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
def test_generic_match_sequence_keys_are_shape_checked_on_any_kind(key: str) -> None:
    """`Ruleset.compile_patterns` reads `GENERIC_MATCH_SEQUENCE_KEYS` off every match
    table regardless of kind, so a stray boolean in any of the three crashes it even
    for a kind, such as `dist_name`, that never reads the field itself. Parametrized
    over all three keys rather than just `targets`, so deleting the loop for any one
    of them fails here instead of only being covered for the key one test happened to
    pick.
    """
    data = minimal()
    data["rule"][0]["match"] = {"kind": "dist_name", "table": "crypto_distribution", key: True}
    with pytest.raises(RulesetError, match=f"{key} must be a list of strings"):
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
