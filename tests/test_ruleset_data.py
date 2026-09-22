"""Structural checks on the shipped ruleset.

These guard the file a crypto engineer edits. They deliberately assert nothing about
which packages are flagged, only that the data is internally consistent: no dangling
references, no unknown matcher kinds, no rule without a stated reason. Editing policy
should never require editing this test.
"""

from __future__ import annotations

import tomllib
from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest

from wheel_crypto_scan.errors import ERROR_KINDS
from wheel_crypto_scan.ruleset import MATCHER_KINDS

SEVERITIES = {"high", "medium", "low", "info"}
CONFIDENCES = {"high", "medium", "low"}
LAYERS = {"metadata", "binary", "python", "derived"}

ENTRY_TABLES = (
    "crypto_distribution",
    "crypto_library",
    "symbol_group",
    "string_group",
    "rust_crate",
    "python_module",
    "ctypes_library",
)


def matches_of(rule: dict[str, Any]) -> list[dict[str, Any]]:
    """Every match table of a rule, written as `[rule.match]` or as `[[rule.match]]`.

    These tests read the raw TOML rather than the parsed ruleset, so they see the list
    form as a list. Reaching into `rule["match"]` directly works until the first rule
    is written with two alternatives, and then stops working everywhere at once.
    """
    match = rule["match"]
    return list(match) if isinstance(match, list) else [match]


@pytest.fixture(scope="module")
def ruleset() -> dict[str, Any]:
    path = files("wheel_crypto_scan").joinpath("data/ruleset.toml")
    return tomllib.loads(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def rule_ids(ruleset: dict[str, Any]) -> set[str]:
    return {rule["id"] for rule in ruleset["rule"]}


def test_ruleset_version_is_a_string(ruleset: dict[str, Any]) -> None:
    assert isinstance(ruleset["ruleset_version"], str)


def test_rule_ids_are_unique(ruleset: dict[str, Any]) -> None:
    ids = [rule["id"] for rule in ruleset["rule"]]
    assert len(ids) == len(set(ids))


def test_every_rule_is_completely_specified(ruleset: dict[str, Any]) -> None:
    for rule in ruleset["rule"]:
        assert rule["layer"] in LAYERS, rule["id"]
        assert rule["severity"] in SEVERITIES, rule["id"]
        assert rule["confidence"] in CONFIDENCES, rule["id"]
        assert isinstance(rule["needs_human_review"], bool), rule["id"]
        assert rule["title"].strip(), rule["id"]
        for match in matches_of(rule):
            assert match["kind"] in MATCHER_KINDS, rule["id"]


def test_every_rule_explains_itself(ruleset: dict[str, Any]) -> None:
    """The `why` text is the point of the file. A rule without one cannot be reviewed."""
    for rule in ruleset["rule"]:
        assert len(rule["why"].strip()) >= 40, rule["id"]


def test_every_table_entry_explains_itself(ruleset: dict[str, Any]) -> None:
    for table in ENTRY_TABLES:
        for entry in ruleset[table]:
            label = f"{table}:{entry.get('name', '?')}"
            assert len(entry["why"].strip()) >= 20, label


def test_rule_verdicts_are_known(ruleset: dict[str, Any]) -> None:
    precedence = set(ruleset["verdict"]["precedence"])
    for rule in ruleset["rule"]:
        if "verdict" in rule:
            assert rule["verdict"] in precedence, rule["id"]


def test_table_entry_verdicts_are_known(ruleset: dict[str, Any]) -> None:
    precedence = set(ruleset["verdict"]["precedence"])
    for table in ENTRY_TABLES:
        for entry in ruleset[table]:
            if "verdict" in entry:
                assert entry["verdict"] in precedence, f"{table}:{entry.get('name')}"


def test_no_rule_can_emit_a_pass(ruleset: dict[str, Any]) -> None:
    """The tool never says compliant. Nothing in the data may claim otherwise."""
    forbidden = {
        "COMPLIANT",
        "FIPS_COMPLIANT",
        "COMPATIBLE",
        "FIPS_COMPATIBLE",
        "APPROVED",
        "PASS",
        "CLEAN",
    }
    assert not forbidden & set(ruleset["verdict"]["precedence"])
    for rule in ruleset["rule"]:
        assert rule.get("verdict") not in forbidden

    # A rule's `title` is prose, not a token, and prose can legitimately carry
    # "approved" as a substring -- "Distribution implements non-approved
    # cryptography" is a rule saying the opposite of a pass. Merging that word into
    # the token set above would flag titles like that one, so this set stays
    # narrower: only the words that spell a passing verdict outright, checked as a
    # case-insensitive substring of the full title.
    forbidden_in_titles = ("compliant", "compliance", "compatible")
    for rule in ruleset["rule"]:
        title = rule["title"].lower()
        for word in forbidden_in_titles:
            assert word not in title, (rule["id"], word)


def test_table_entries_reference_existing_rules(
    ruleset: dict[str, Any], rule_ids: set[str]
) -> None:
    for table in ENTRY_TABLES:
        for entry in ruleset[table]:
            if "rule" in entry:
                assert entry["rule"] in rule_ids, f"{table}:{entry.get('name')}"


def test_suppressed_by_references_existing_rules(
    ruleset: dict[str, Any], rule_ids: set[str]
) -> None:
    for rule in ruleset["rule"]:
        for other in rule.get("suppressed_by", []):
            assert other in rule_ids, rule["id"]
            assert other != rule["id"], rule["id"]


def test_rules_reference_existing_tables(ruleset: dict[str, Any]) -> None:
    for rule in ruleset["rule"]:
        for match in matches_of(rule):
            for key in ("table", "tables"):
                names = match.get(key)
                if names is None:
                    continue
                for name in [names] if isinstance(names, str) else names:
                    assert name in ENTRY_TABLES, rule["id"]


def test_rules_reference_existing_groups(ruleset: dict[str, Any]) -> None:
    symbol_groups = {entry["name"] for entry in ruleset["symbol_group"]}
    string_groups = {entry["name"] for entry in ruleset["string_group"]}
    for rule in ruleset["rule"]:
        for match in matches_of(rule):
            available = symbol_groups if match["kind"] == "dynamic_symbol" else string_groups
            if match["kind"] not in {"dynamic_symbol", "binary_string"}:
                continue
            names = match.get("groups", [])
            if "group" in match:
                names = [match["group"], *names]
            assert names, rule["id"]
            for name in names:
                assert name in available, f"{rule['id']} -> {name}"


def test_rules_reference_existing_libraries(ruleset: dict[str, Any]) -> None:
    libraries = {entry["name"] for entry in ruleset["crypto_library"]}
    for rule in ruleset["rule"]:
        for match in matches_of(rule):
            for key in ("library", "name"):
                if match["kind"] in {"bundled_library", "dt_needed", "linkage"} and key in match:
                    assert match[key] in libraries, rule["id"]
            for name in match.get("exclude_libraries", []):
                assert name in libraries, rule["id"]


def test_scan_error_rules_use_known_error_kinds(ruleset: dict[str, Any]) -> None:
    for rule in ruleset["rule"]:
        for match in matches_of(rule):
            if match["kind"] != "scan_error":
                continue
            for kind in match["error_kinds"]:
                assert kind in ERROR_KINDS, f"{rule['id']} -> {kind}"


def test_only_one_default_rule_per_table(ruleset: dict[str, Any]) -> None:
    defaults: dict[str, list[str]] = {}
    for rule in ruleset["rule"]:
        for match in matches_of(rule):
            if match.get("default"):
                defaults.setdefault(match["table"], []).append(rule["id"])
    for table, ids in defaults.items():
        assert len(ids) == 1, f"{table} has several default rules: {ids}"


def test_dynamic_symbol_rules_declare_a_binding(ruleset: dict[str, Any]) -> None:
    """Imported versus defined is the distinction the whole tool turns on."""
    for rule in ruleset["rule"]:
        for match in matches_of(rule):
            if match["kind"] == "dynamic_symbol":
                assert match["binding"] in {"imported", "defined", "any"}, rule["id"]


def test_symbol_groups_are_non_empty(ruleset: dict[str, Any]) -> None:
    for group in ruleset["symbol_group"]:
        assert group["prefixes"] or group["exact"], group["name"]


def test_linkage_rules_use_known_values(ruleset: dict[str, Any]) -> None:
    known = {"system", "bundled", "static", "mixed", "none", "unknown"}
    for rule in ruleset["rule"]:
        for match in matches_of(rule):
            if match["kind"] != "linkage":
                continue
            values = match.get("values", [])
            if "value" in match:
                values = [match["value"], *values]
            assert values, rule["id"]
            for value in values:
                assert value in known, rule["id"]


def test_every_error_kind_is_covered_by_a_rule(ruleset: dict[str, Any]) -> None:
    """An unmatched error kind reads as "nothing found", which is the worst outcome.

    A wheel we could not open must never be reported the same way as a wheel that
    genuinely has no crypto in it, so every failure the scanner can record has to have
    a rule that turns it into a finding.
    """
    covered: set[str] = set()
    for rule in ruleset["rule"]:
        for match in matches_of(rule):
            if match["kind"] == "scan_error":
                covered.update(match["error_kinds"])
    assert ERROR_KINDS - covered == set()


def test_every_error_kind_is_actually_emitted_somewhere() -> None:
    """A kind nothing constructs makes any rule matching it silently dead."""
    source = "\n".join(
        path.read_text(encoding="utf-8") for path in Path("src/wheel_crypto_scan").rglob("*.py")
    )
    constant_names = {kind: kind.upper() for kind in ERROR_KINDS}
    dead = {
        kind
        for kind, constant in constant_names.items()
        if source.count(constant) < 2  # the definition, plus at least one use
    }
    assert dead == set()
