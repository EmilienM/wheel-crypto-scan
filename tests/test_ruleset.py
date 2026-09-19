"""Behaviour of the ruleset loader, its validation and the compiled scan patterns."""

from __future__ import annotations

import re
from dataclasses import fields
from typing import Any

import pytest

from wheel_crypto_scan.errors import RulesetError
from wheel_crypto_scan.ruleset import (
    DEFAULTABLE_TABLES,
    ENTRY_TABLES,
    MATCHER_KINDS,
    ROUTED_KINDS,
    SymbolGroup,
    load_ruleset,
    parse_ruleset,
)


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
            "windows_version_suffix_regex": (
                r"^(?P<stem>.+?)-(?P<version>[0-9]+(_[0-9]+)?)(-(?P<arch>x64|x86|arm64|arm64ec))?$"
            ),
            "cargo_path_regex": r"cargo/registry/src/[^/]+/(?P<name>[a-z-]+)-(?P<version>[0-9.]+)/",
            "weak_hash_algorithms": ["md5", "sha1"],
            "library_suffixes": [".so", ".dylib", ".dll", ".pyd"],
            "windows_library_suffixes": [".dll", ".pyd"],
            "go_boring_group": "go_boring",
            "go_stock_group": "go_stock_crypto",
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
    assert ruleset.version == "8"
    assert len(ruleset.rules) > 20


def test_shipped_ruleset_knows_the_bundled_openssl_rule() -> None:
    rule = load_ruleset().rule("BIN_BUNDLED_OPENSSL")
    assert rule.verdict == "CONDITIONAL"
    assert [match["kind"] for match in rule.matches] == ["bundled_library"]


def test_rules_can_be_selected_by_matcher_kind() -> None:
    """Selection yields (rule, match) pairs: a rule may be reached through two kinds."""
    ruleset = load_ruleset()
    selected = ruleset.matches_for_kind("linkage")
    assert {rule.id for rule, _ in selected} == {
        "BIN_STATIC_OPENSSL",
        "DERIVED_SYSTEM_OPENSSL_ONLY",
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
