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
from wheel_crypto_scan.ruleset import FAMILIES, MATCHER_KINDS, RELATIONS, ROUTED_KINDS, Ruleset
from wheel_crypto_scan.ruleset_loader import load_ruleset
from wheel_crypto_scan.standards import STANDARD_STATUSES

# The verdict classes a relation and a non-empty basis are required for. The other two
# classes a rule or entry can carry -- `OPAQUE` and the absence of a verdict -- have no
# standard to cite: unreadability is not a finding about a standard, and a rule with no
# verdict never reaches `[verdict] precedence` at all.
VERDICT_BEARING_CLASSES = frozenset(
    {"NON_APPROVED_CRYPTO", "CONDITIONAL", "FIPS_BREAKING", "CONTEXT_DEPENDENT"}
)

# The four tables `check_relation_matches_verdict` (`ruleset_coherence.py`) resolves an
# entry's owning rule through -- the same set `_entries_by_table` there walks. Mirrored
# here rather than imported, because the totality question below is different from
# that check's: this asks whether the *effective* (verdict, relation, basis) triple
# over the whole shipped ruleset is total, not whether one given pair is internally
# consistent.
_OVERRIDE_TABLES = ("crypto_distribution", "crypto_library", "rust_crate", "python_module")

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

# The tables `family` is carried on. `ctypes_library` is one row of substrings with a
# single shared `why`, never per-library entries, so there is nothing there to hang a
# family off of.
FAMILY_BEARING_TABLES = (
    "crypto_distribution",
    "crypto_library",
    "symbol_group",
    "string_group",
    "rust_crate",
    "python_module",
)

# Rules whose finding has no entry or group backing it to inherit `family` from -- the
# rule itself is the only source of one. Every other rule's finding is backed by an
# entry in one of `FAMILY_BEARING_TABLES` (or, for a `binary_string`/`dynamic_symbol`
# match, a symbol or string group), which already states its own family.
FAMILY_BEARING_RULES = frozenset(
    {
        "PY_WEAK_HASH_CALL",
        "PY_RESTRICTED_HASH_CALL",
        "PY_WEAK_HASH_CALL_MARKED",
        "PY_WEAK_HASH_UNRESOLVED",
        "PY_INSECURE_RNG",
        "PY_TLS_POLICY_OVERRIDE",
        "PY_TLS_VERSION_PINNED",
        "PY_LEGACY_TLS_PROTOCOL",
        "PY_TLS_VERIFICATION_DISABLED",
        "PY_TLS_UNVERIFIED_CONTEXT",
        "PY_CTYPES_CRYPTO_LOAD",
        "DIST_BUNDLED_TRUST_STORE",
        "BIN_GO_BORING_CRYPTO",
        "BIN_GO_FIPS140",
        "BIN_GO_STOCK_CRYPTO",
    }
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


def test_every_family_bearing_entry_has_a_family(
    ruleset: dict[str, Any], rule_ids: set[str]
) -> None:
    """`family` is policy-in-data the same way `why` is: every entry in the six tables
    that carry it states one, and so does every rule whose finding has no entry or
    group of its own to inherit one from. `rule_ids_seen == FAMILY_BEARING_RULES`
    guards the list itself -- a rename that drops a rule out of the ruleset silently
    would otherwise leave this test checking fewer rules than it claims to."""
    for table in FAMILY_BEARING_TABLES:
        for entry in ruleset[table]:
            label = f"{table}:{entry.get('name', '?')}"
            assert entry.get("family") in FAMILIES, label

    rule_ids_seen = {rid for rid in rule_ids if rid in FAMILY_BEARING_RULES}
    assert rule_ids_seen == FAMILY_BEARING_RULES
    for rule in ruleset["rule"]:
        if rule["id"] in FAMILY_BEARING_RULES:
            assert rule.get("family") in FAMILIES, rule["id"]


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

    # `RELATIONS` and `STANDARD_STATUSES` are Python vocabularies, not shipped data,
    # so this checks the tokens themselves rather than anything in `ruleset`: a
    # relation or a standard status can never be added under one of these names
    # either, upper-cased for the comparison since both vocabularies are lower_snake.
    assert not forbidden & {value.upper() for value in RELATIONS}
    assert not forbidden & {value.upper() for value in STANDARD_STATUSES}

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


# --- relation/basis totality over the shipped ruleset -----------------------
#
# These check the *effective* (rule, entry) pair: resolved through the same
# owner fallback `engine._build_finding` (and `ruleset_coherence.
# check_relation_matches_verdict`) reads an entry through, not the entry's own raw
# fields. A verdict-bearing pair that only its owning rule can supply is total, the
# same way `check_relation_matches_verdict` treats it; a pair whose own relation is
# set carries its own basis too, since the loader already refuses one without the
# other on the same rule or entry (`ruleset_loader._parse_relation_fields`).


@pytest.fixture(scope="module")
def parsed_ruleset() -> Ruleset:
    return load_ruleset()


def _owner(parsed: Ruleset, table: str, entry: Any):
    """The rule an entry's finding resolves to when it names none of its own, the
    same fallback `check_relation_matches_verdict` reads: an explicit `rule=`, else
    the table's one default rule for the matcher kind that routes it, else no owner
    at all (`crypto_distribution` always names its own rule and has no default)."""
    default = None
    if table != "crypto_distribution":
        (kind,) = ROUTED_KINDS[table]
        default = parsed.default_rule_for_table(table, kind)
    owner_id = entry.rule or (default.id if default is not None else None)
    return parsed.rule(owner_id) if owner_id is not None else None


def _effective_triple(entry: Any, owner: Any | None) -> tuple[str | None, str | None, tuple]:
    """The (verdict, relation, basis) a finding through this entry actually carries:
    the entry's own fields when it sets them, the owning rule's otherwise. `relation`
    and `basis` are read together off whichever of the two states them, mirroring the
    loader's own co-location rule."""
    verdict = entry.verdict if entry.verdict is not None else (owner and owner.verdict)
    if entry.relation is not None:
        relation, basis = entry.relation, entry.basis
    elif owner is not None:
        relation, basis = owner.relation, owner.basis
    else:
        relation, basis = None, ()
    return verdict, relation, basis


def _is_table_routed(rule: Any) -> bool:
    """True when every finding this rule can produce is reached through a named
    entry of one of the four override-bearing tables -- the shape
    `ruleset.py`'s own `ROUTED_KINDS` describes -- so the rule can never fire on its
    own with no entry to ask, and its own bare (verdict, relation) pair is not the
    one totality has to hold: the entry's effective pair, checked separately below,
    is."""
    for match in rule.matches:
        table = match.get("table")
        if table in ROUTED_KINDS and match["kind"] in ROUTED_KINDS[table]:
            return True
    return False


def test_every_verdict_bearing_rule_carries_a_relation_and_basis(parsed_ruleset: Ruleset) -> None:
    for rule in parsed_ruleset.rules:
        if rule.verdict in VERDICT_BEARING_CLASSES and not _is_table_routed(rule):
            assert rule.relation is not None, rule.id
            assert rule.basis, rule.id


def test_every_opaque_or_verdict_less_rule_carries_neither(parsed_ruleset: Ruleset) -> None:
    for rule in parsed_ruleset.rules:
        if rule.verdict is None or rule.verdict == "OPAQUE":
            assert rule.relation is None, rule.id
            assert rule.basis == (), rule.id


def test_every_effective_verdict_bearing_entry_carries_a_relation_and_basis(
    parsed_ruleset: Ruleset,
) -> None:
    """A rule routed through a table may leave both unset and let every entry state
    its own -- so this checks the pair each entry actually resolves to, not the raw
    entry fields, the same way a scan would."""
    for table in _OVERRIDE_TABLES:
        entries = getattr(
            parsed_ruleset,
            {
                "crypto_distribution": "distributions",
                "crypto_library": "libraries",
                "rust_crate": "rust_crates",
                "python_module": "python_modules",
            }[table],
        )
        for name, entry in entries.items():
            owner = _owner(parsed_ruleset, table, entry)
            verdict, relation, basis = _effective_triple(entry, owner)
            label = f"{table}:{name}"
            if verdict in VERDICT_BEARING_CLASSES:
                assert relation is not None, label
                assert basis, label


def test_every_effective_opaque_or_verdict_less_entry_carries_neither(
    parsed_ruleset: Ruleset,
) -> None:
    for table in _OVERRIDE_TABLES:
        entries = getattr(
            parsed_ruleset,
            {
                "crypto_distribution": "distributions",
                "crypto_library": "libraries",
                "rust_crate": "rust_crates",
                "python_module": "python_modules",
            }[table],
        )
        for name, entry in entries.items():
            owner = _owner(parsed_ruleset, table, entry)
            verdict, relation, basis = _effective_triple(entry, owner)
            label = f"{table}:{name}"
            if verdict is None or verdict == "OPAQUE":
                assert relation is None, label
                assert basis == (), label
