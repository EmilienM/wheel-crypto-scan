"""Parses and validates a TOML ruleset into the object model `ruleset` defines.

This module's job is to read the TOML mapping, refuse a malformed one loudly at load
time rather than silently mis-scanning, and hand back the `Ruleset` that `ruleset`
defines. Import `load_ruleset`, `parse_ruleset` and `routine_reasons` from here, not
from `ruleset`; see `DECISIONS.md` for why the loader lives in its own module.
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Iterable, Mapping
from importlib.resources import files
from pathlib import Path
from types import MappingProxyType
from typing import Any

from packaging.utils import canonicalize_name

from .errors import ERROR_KINDS, RulesetError
from .evidence import PARTIAL_REASONS, PRINTABLE, USED_FOR_SECURITY_VALUES
from .ruleset import (
    BINDINGS,
    CONFIDENCES,
    DEFAULTABLE_TABLES,
    ENTRY_TABLES,
    GENERIC_MATCH_SEQUENCE_KEYS,
    LAYERS,
    LINKAGE_VALUES,
    MATCHER_KINDS,
    ROUTED_KINDS,
    SEVERITIES,
    Conventions,
    CryptoLibrary,
    Distribution,
    Limits,
    LinkagePolicy,
    PythonModule,
    Rule,
    Ruleset,
    RustCrateEntry,
    StringGroup,
    SymbolGroup,
)


def _require(mapping: Mapping[str, Any], key: str, where: str) -> Any:
    try:
        return mapping[key]
    except KeyError:
        raise RulesetError(f"{where}: missing required field '{key}'") from None


def _check(value: Any, allowed: Iterable[str], label: str, where: str) -> str:
    if value not in allowed:
        raise RulesetError(f"{where}: unknown {label} {value!r}")
    return str(value)


def _check_used_for_security(value: Any, where: str) -> None:
    """`usedforsecurity` as `_match_py_call` reads it: a bare string is one value,
    anything else must be a list of strings, each checked against the closed set
    `USED_FOR_SECURITY_VALUES`. A bool, dict or other non-list is exactly what crashes
    `attrs.get("usedforsecurity") not in want_used` at scan time, so it is refused here
    instead of reaching that point. An empty list is refused too: `not in []` is always
    true, so it would load clean and silently never match anything -- the same failure
    mode as a typo'd value, just spelled differently.
    """
    if isinstance(value, str):
        _check(value, USED_FOR_SECURITY_VALUES, "usedforsecurity value", where)
        return
    if not isinstance(value, (list, tuple)):
        raise RulesetError(f"{where}: usedforsecurity must be a string or list of strings")
    if not value:
        raise RulesetError(f"{where}: usedforsecurity must not be an empty list")
    for item in value:
        if not isinstance(item, str):
            raise RulesetError(f"{where}: usedforsecurity must be a string or list of strings")
        _check(item, USED_FOR_SECURITY_VALUES, "usedforsecurity value", where)


def _check_string_sequence(value: Any, label: str, where: str, *, allow_empty: bool = True) -> None:
    """Shape check for an open-vocabulary `py_call`/`py_attr`/`py_constant` field: a
    list of strings, not a bool, dict, int or bare string that would crash
    `frozenset(...)` (`targets`, `attributes`, `constants`) or a `not in` check
    (`values`) at scan time. The values themselves are never checked against anything
    here -- they are open names this ruleset has no closed vocabulary for.

    `allow_empty=False` additionally refuses an empty list, for a field that is the
    thing a rule matches on: an empty `targets`, `attributes` or `values` loads clean
    and can never match anything, the same silent-typo failure `usedforsecurity`
    above is refused for.
    """
    if not isinstance(value, (list, tuple)):
        raise RulesetError(f"{where}: {label} must be a list of strings")
    if not allow_empty and not value:
        raise RulesetError(f"{where}: {label} must not be an empty list")
    for item in value:
        if not isinstance(item, str):
            raise RulesetError(f"{where}: {label} must be a list of strings")


def _parse_conventions(data: Mapping[str, Any]) -> Conventions:
    where = "[conventions]"
    try:
        mangled = re.compile(str(_require(data, "mangled_soname_regex", where)))
        windows = re.compile(str(_require(data, "windows_version_suffix_regex", where)))
        cargo = re.compile(str(_require(data, "cargo_path_regex", where)))
    except re.error as exc:
        raise RulesetError(f"{where}: invalid regular expression: {exc}") from None
    for pattern, group in ((mangled, "stem"), (windows, "stem"), (cargo, "name")):
        if group not in pattern.groupindex:
            raise RulesetError(f"{where}: pattern {pattern.pattern!r} needs a '{group}' group")
    suffixes = tuple(_require(data, "library_suffixes", where))
    windows_suffixes = tuple(_require(data, "windows_library_suffixes", where))
    # A Windows suffix that is not also stripped would never be seen, so the reduction
    # it is meant to trigger would silently never happen.
    unknown = sorted(set(windows_suffixes) - set(suffixes))
    if unknown:
        raise RulesetError(f"{where}: windows_library_suffixes {unknown} are not library_suffixes")
    return Conventions(
        vendor_dir_globs=tuple(_require(data, "vendor_dir_globs", where)),
        mangled_soname_regex=mangled,
        windows_version_suffix_regex=windows,
        cargo_path_regex=cargo,
        weak_hash_algorithms=frozenset(_require(data, "weak_hash_algorithms", where)),
        library_suffixes=suffixes,
        windows_library_suffixes=windows_suffixes,
        go_boring_group=str(_require(data, "go_boring_group", where)),
        go_stock_group=str(_require(data, "go_stock_group", where)),
        go_fips140_group=str(_require(data, "go_fips140_group", where)),
    )


def _claimed_reasons(match: Mapping[str, Any]) -> frozenset[str]:
    """Which causes one `partial_binary` match table speaks for.

    `reasons` selects, `exclude_reasons` takes the complement, and neither claims the
    lot. Written once because two callers ask it -- the linkage coherence check below
    and the tests -- and because the complement arm is the one that silently changes
    meaning when a token is added to the vocabulary.
    """
    if "reasons" in match:
        return frozenset(match["reasons"])
    return PARTIAL_REASONS - frozenset(match.get("exclude_reasons", ()))


def routine_reasons(rules: Iterable[Rule]) -> frozenset[str]:
    """Causes recorded without a verdict: not on their own a reason to look.

    Read off `verdict is None` rather than off a rule id, because that is the property
    that matters and a second verdict-less rule added later would slip past a name.
    """
    return frozenset().union(
        *(
            _claimed_reasons(match)
            for rule in rules
            if rule.verdict is None
            for match in rule.matches
            if match["kind"] == "partial_binary"
        ),
        frozenset(),
    )


def _check_limits_leave_room_for_every_key(
    limits: Limits,
    symbol_groups: Mapping[str, Any],
    string_groups: Mapping[str, Any],
    crates: Mapping[str, Any],
) -> None:
    """Refuse limits too small to hold one of everything the ruleset can match.

    `caps` keeps one of every key before filling the remainder, so no kind of
    evidence is crowded out -- while there is room for one of each. Below that the
    choice among keys is the alphabet again, and `SCHEMA.md` states the guarantee
    without conditions. Nobody sets a limit to change what is detected, so a value that
    silently does is a mistake rather than a decision.
    """
    wanted = (
        ("max_strings_per_binary", limits.max_strings_per_binary, len(string_groups)),
        # Two bindings per group, because that pair is a symbol's key.
        ("max_symbols_per_binary", limits.max_symbols_per_binary, 2 * len(symbol_groups)),
        ("max_rust_crates_per_binary", limits.max_rust_crates_per_binary, len(crates)),
    )
    for name, limit, needed in wanted:
        if limit < needed:
            raise RulesetError(
                f"[limits]: {name} is {limit}, below the {needed} keys this ruleset can "
                "match; a cap that small chooses which evidence survives by sort order"
            )


def _parse_linkage_policy(data: Mapping[str, Any] | None, rules: Iterable[Rule]) -> LinkagePolicy:
    """Read `[linkage_policy]`, which is optional and derived from the rules when absent.

    **Absent means coherent with your own rules, not "exempt nothing".** A cause
    recorded without a verdict promises the wheel is not on its own worth a human's
    time; making that same cause cost the linkage answer puts it straight back on the
    triage list through `BIN_OPENSSL_LINKAGE_UNKNOWN`, which carries `OPAQUE`. An
    empty default would have made every ruleset supplied through `--ruleset` do
    exactly that, so absence derives the exemptions from the verdict-less rules and
    the explicit table is the override that widens them.

    The same coherence is then required of a table that is written out, so a ruleset
    whose two lists contradict each other is refused at load time rather than
    resolving the contradiction silently in favour of whichever consumer runs first.

    Keys and tokens are both checked, for the reason a rule's `reasons` are checked in
    `_validate_match_references`: `excluded_reasons` would otherwise load clean and
    exempt nothing, and the symptom -- a wheel reading `unknown` where it used to read
    `none` -- looks like the feature working.
    """
    routine = routine_reasons(rules)
    where = "[linkage_policy]"
    if data is None:
        return LinkagePolicy(exclude_reasons=routine)
    unknown_keys = sorted(set(data) - {"why", "exclude_reasons"})
    if unknown_keys:
        raise RulesetError(f"{where}: unknown keys {unknown_keys}")
    _require(data, "why", where)
    reasons = frozenset(data.get("exclude_reasons", ()))
    for reason in sorted(reasons):
        if reason not in PARTIAL_REASONS:
            raise RulesetError(f"{where}: unknown partial reason {reason!r}")
    missing = sorted(routine - reasons)
    if missing:
        raise RulesetError(
            f"{where}: {missing} are recorded without a verdict and must be excluded here "
            "too, or they put the wheel back on the triage list through the linkage rule"
        )
    return LinkagePolicy(exclude_reasons=reasons)


def _parse_rule(data: Mapping[str, Any], precedence: frozenset[str]) -> Rule:
    rule_id = _require(data, "id", "[[rule]]")
    where = f"rule {rule_id!r}"
    verdict = data.get("verdict")
    if verdict is not None:
        _check(verdict, precedence, "verdict class", where)
    matches = _parse_matches(_require(data, "match", where), where)
    return Rule(
        id=str(rule_id),
        layer=_check(_require(data, "layer", where), LAYERS, "layer", where),
        category=str(_require(data, "category", where)),
        severity=_check(_require(data, "severity", where), SEVERITIES, "severity", where),
        confidence=_check(_require(data, "confidence", where), CONFIDENCES, "confidence", where),
        needs_human_review=bool(_require(data, "needs_human_review", where)),
        title=str(_require(data, "title", where)),
        why=str(_require(data, "why", where)),
        matches=matches,
        verdict=None if verdict is None else str(verdict),
        suppressed_by=tuple(data.get("suppressed_by", ())),
    )


def _parse_matches(match: Any, where: str) -> tuple[Mapping[str, Any], ...]:
    """Read `match` as one table, or as the list of alternatives `[[rule.match]]` gives."""
    tables = list(match) if isinstance(match, list) else [match]
    if not tables:
        raise RulesetError(f"{where}: match is empty")
    for table in tables:
        _check(_require(table, "kind", f"{where} match"), MATCHER_KINDS, "matcher kind", where)
    return tuple(MappingProxyType(dict(table)) for table in tables)


def _validate_rule_references(
    rule: Rule, ruleset_data: Mapping[str, Any], rule_ids: set[str]
) -> None:
    where = f"rule {rule.id!r}"
    for other in rule.suppressed_by:
        if other not in rule_ids:
            raise RulesetError(f"{where}: suppressed_by names unknown rule {other!r}")
        if other == rule.id:
            raise RulesetError(f"{where}: suppressed_by names itself")
    for match in rule.matches:
        _validate_match_references(match, ruleset_data, where)


def _validate_conventions_references(ruleset_data: Mapping[str, Any]) -> None:
    """The two string groups `[conventions]` names for the Go reader must exist.

    Here rather than in `_parse_conventions` so that one mechanism checks every group
    reference in the file, against the raw tables, in one pass and with one spelling of
    the failure. `[conventions]` says naming these groups in the ruleset means renaming
    a group cannot silently flip a verdict-relevant field, and `binfmt.golang` reads
    them for exactly that reason; unchecked, a name no group had loaded clean and left
    `GoBuildInfo.boring_crypto` false for every Go binary in the run.
    """
    where = "[conventions]"
    conventions = _require(ruleset_data, "conventions", where)
    known = {entry["name"] for entry in ruleset_data["string_group"]}
    for key in ("go_boring_group", "go_stock_group", "go_fips140_group"):
        name = str(_require(conventions, key, where))
        if name not in known:
            raise RulesetError(f"{where}: {key} names unknown string group {name!r}")


def _validate_match_references(
    match: Mapping[str, Any], ruleset_data: Mapping[str, Any], where: str
) -> None:
    kind = match["kind"]

    tables = match.get("tables", [])
    if "table" in match:
        tables = [match["table"], *tables]
    for table in tables:
        if table not in ENTRY_TABLES:
            raise RulesetError(f"{where}: unknown table {table!r}")

    if kind == "dynamic_symbol":
        _check(match.get("binding"), BINDINGS, "symbol binding", where)
        known = {entry["name"] for entry in ruleset_data["symbol_group"]}
        for name in _group_names(match):
            if name not in known:
                raise RulesetError(f"{where}: unknown symbol group {name!r}")
    elif kind == "binary_string":
        known = {entry["name"] for entry in ruleset_data["string_group"]}
        for name in _group_names(match):
            if name not in known:
                raise RulesetError(f"{where}: unknown string group {name!r}")
    elif kind == "scan_error":
        for error_kind in _require(match, "error_kinds", where):
            if error_kind not in ERROR_KINDS:
                raise RulesetError(f"{where}: unknown error kind {error_kind!r}")
    elif kind == "partial_binary":
        for key in ("reasons", "exclude_reasons"):
            for reason in match.get(key, ()):
                if reason not in PARTIAL_REASONS:
                    raise RulesetError(f"{where}: unknown partial reason {reason!r}")
        if match.get("reasons") and match.get("exclude_reasons"):
            raise RulesetError(f"{where}: reasons and exclude_reasons are alternatives")
    elif kind == "linkage":
        values = match.get("values")
        if values is None:
            _check(match.get("value"), LINKAGE_VALUES, "linkage value", where)
        else:
            for value in values:
                _check(value, LINKAGE_VALUES, "linkage value", where)
        if "object_values" in match and "exclude_object_values" in match:
            raise RulesetError(f"{where}: object_values and exclude_object_values are alternatives")
        for key in ("object_values", "exclude_object_values"):
            if key not in match:
                continue
            _check_string_sequence(match[key], key, where, allow_empty=False)
            for value in match[key]:
                _check(value, LINKAGE_VALUES, "linkage value", where)
    elif kind == "py_call":
        used_for_security = match.get("usedforsecurity")
        if used_for_security is not None:
            _check_used_for_security(used_for_security, where)
        # `targets` is what a `py_call` rule matches on (`_target_matches`); without it,
        # or with an empty list, the rule can load clean and never fire.
        _check_string_sequence(
            _require(match, "targets", where), "targets", where, allow_empty=False
        )
        # Type-checked only, deliberately never checked against
        # `ruleset.conventions.weak_hash_algorithms`: `algorithm` names whatever a
        # wheel's source passes to `hashlib.new(...)`, open-ended by construction, and
        # a rule intentionally naming a *strong* algorithm is a real, existing shape --
        # the shipped `PY_WEAK_HASH_UNRESOLVED` rule's `algorithm = "unresolved"` is
        # not a member of that set either. See DECISIONS.md.
        algorithm = match.get("algorithm")
        if algorithm is not None and not isinstance(algorithm, str):
            raise RulesetError(f"{where}: algorithm must be a string")
        weak_algorithms_only = match.get("weak_algorithms_only")
        if weak_algorithms_only is not None and not isinstance(weak_algorithms_only, bool):
            raise RulesetError(f"{where}: weak_algorithms_only must be a boolean")
    elif kind == "py_attr":
        # `attributes` is what a `py_attr` rule matches on; same reasoning as `targets`
        # above. `values`, when given, is a filter on top of it and is refused empty
        # for the same reason `usedforsecurity` is: `not in []` is always true.
        _check_string_sequence(
            _require(match, "attributes", where), "attributes", where, allow_empty=False
        )
        values = match.get("values")
        if values is not None:
            _check_string_sequence(values, "values", where, allow_empty=False)
    elif kind == "py_constant":
        _check_string_sequence(
            _require(match, "constants", where), "constants", where, allow_empty=False
        )

    # `Ruleset.compile_patterns` reads `GENERIC_MATCH_SEQUENCE_KEYS` off every match
    # table regardless of kind, so a bool or other non-list shape here crashes it even
    # on a kind that never reads the field itself, such as a `dist_name` match
    # carrying a stray `targets` key. This re-checks the same key a kind-specific arm
    # above may have already required and shape-checked with its own message (`py_call`
    # re-checks `targets`, for instance) -- harmless, and what keeps every OTHER kind
    # covered too, on the same shared list `compile_patterns` itself reads.
    for key in GENERIC_MATCH_SEQUENCE_KEYS:
        if key in match:
            _check_string_sequence(match[key], key, where)

    libraries = {entry["name"] for entry in ruleset_data["crypto_library"]}
    for key in ("library", "name"):
        if kind in {"bundled_library", "dt_needed", "linkage"} and key in match:
            if match[key] not in libraries:
                raise RulesetError(f"{where}: unknown library {match[key]!r}")
    for name in match.get("exclude_libraries", ()):
        if name not in libraries:
            raise RulesetError(f"{where}: unknown library {name!r}")


def _group_names(match: Mapping[str, Any]) -> list[str]:
    names = list(match.get("groups", ()))
    if "group" in match:
        names.insert(0, match["group"])
    return names


def _entry_rule(
    entry: Mapping[str, Any], table: str, rules: Mapping[str, Rule], where: str
) -> str | None:
    """The rule an entry routes itself to, when it names one.

    An entry that names no rule belongs to its table's default rule, which is what
    lets one table feed several rules of the same kind without them all double-firing.
    Only the kinds in `ROUTED_KINDS` read that routing, so naming a rule of any other
    kind is refused here: the ruleset would load clean and the entry would route
    nothing, taking its old rule's finding with it.
    """
    rule_id = entry.get("rule")
    if rule_id is None:
        return None
    rule = rules.get(str(rule_id))
    if rule is None:
        raise RulesetError(f"{where}: unknown rule {rule_id!r}")
    kinds = ROUTED_KINDS[table]
    if not any(match["kind"] in kinds for match in rule.matches):
        wanted = " or ".join(sorted(kinds))
        raise RulesetError(
            f"{where}: rule {rule_id!r} has no {wanted} match, so it never reads "
            f"[[{table}]] routing"
        )
    return str(rule_id)


def _entry_overrides(
    entry: Mapping[str, Any], precedence: frozenset[str], where: str
) -> dict[str, Any]:
    verdict = entry.get("verdict")
    if verdict is not None:
        _check(verdict, precedence, "verdict class", where)
    severity = entry.get("severity")
    if severity is not None:
        _check(severity, SEVERITIES, "severity", where)
    return {
        "why": str(_require(entry, "why", where)),
        "severity": None if severity is None else str(severity),
        "verdict": None if verdict is None else str(verdict),
        "needs_human_review": entry.get("needs_human_review"),
    }


def parse_ruleset(data: Mapping[str, Any], source: str = "<ruleset>") -> Ruleset:
    """Validate a ruleset mapping and build the object model.

    Raises RulesetError with a message naming the offending rule or entry. Nothing is
    silently skipped: a ruleset that cannot be fully understood is not used at all.
    """
    version = _require(data, "ruleset_version", source)
    precedence = tuple(_require(_require(data, "verdict", source), "precedence", source))
    if not precedence:
        raise RulesetError(f"{source}: [verdict] precedence is empty")
    classes = frozenset(precedence)

    for table in ENTRY_TABLES:
        if table not in data:
            raise RulesetError(f"{source}: missing required table [[{table}]]")

    rules = tuple(_parse_rule(entry, classes) for entry in _require(data, "rule", source))
    rule_ids = {rule.id for rule in rules}
    if len(rule_ids) != len(rules):
        seen: set[str] = set()
        for rule in rules:
            if rule.id in seen:
                raise RulesetError(f"{source}: duplicate rule id {rule.id!r}")
            seen.add(rule.id)
    by_id = {rule.id: rule for rule in rules}

    for rule in rules:
        _validate_rule_references(rule, data, rule_ids)
    _validate_conventions_references(data)

    defaults: dict[str, set[str]] = {}
    for rule in rules:
        for match in rule.matches:
            if not match.get("default"):
                continue
            where = f"rule {rule.id!r}"
            table = str(_require(match, "table", where))
            if table not in DEFAULTABLE_TABLES:
                raise RulesetError(f"{where}: [[{table}]] entries never fall back to a default")
            if match["kind"] not in ROUTED_KINDS[table]:
                raise RulesetError(
                    f"{where}: a {match['kind']!r} match cannot be the default for "
                    f"[[{table}]], which only {' or '.join(sorted(ROUTED_KINDS[table]))} reads"
                )
            defaults.setdefault(table, set()).add(rule.id)
    for table, ids in sorted(defaults.items()):
        if len(ids) > 1:
            raise RulesetError(
                f"{source}: more than one default rule for [[{table}]]: {sorted(ids)}"
            )

    distributions: dict[str, Distribution] = {}
    for entry in data["crypto_distribution"]:
        name = canonicalize_name(str(_require(entry, "name", "[[crypto_distribution]]")))
        where = f"crypto_distribution {name!r}"
        # Unlike the other entry tables, a distribution always names its own rule.
        rule_id = _entry_rule(entry, "crypto_distribution", by_id, where)
        if rule_id is None:
            raise RulesetError(f"{where}: missing required field 'rule'")
        distributions[name] = Distribution(
            name=name, rule=rule_id, **_entry_overrides(entry, classes, where)
        )

    libraries: dict[str, CryptoLibrary] = {}
    for entry in data["crypto_library"]:
        name = str(_require(entry, "name", "[[crypto_library]]"))
        where = f"crypto_library {name!r}"
        symbol_group = entry.get("symbol_group")
        if symbol_group is not None and symbol_group not in {
            group["name"] for group in data["symbol_group"]
        }:
            raise RulesetError(f"{where}: unknown symbol group {symbol_group!r}")
        string_group = entry.get("string_group")
        if string_group is not None and string_group not in {
            group["name"] for group in data["string_group"]
        }:
            raise RulesetError(f"{where}: unknown string group {string_group!r}")
        copy_string_group = entry.get("copy_string_group")
        if copy_string_group is not None:
            if copy_string_group not in {group["name"] for group in data["string_group"]}:
                raise RulesetError(f"{where}: unknown string group {copy_string_group!r}")
            if string_group is None:
                raise RulesetError(f"{where}: copy_string_group needs a string_group")
            if copy_string_group == string_group:
                raise RulesetError(f"{where}: copy_string_group must differ from string_group")
        _check_string_sequence(entry.get("crates", []), "crates", where)
        library_crates = tuple(str(crate) for crate in entry.get("crates", ()))
        for crate in library_crates:
            if crate not in {rust_crate["name"] for rust_crate in data["rust_crate"]}:
                raise RulesetError(f"{where}: crate {crate!r} is not a [[rust_crate]] entry")
        libraries[name] = CryptoLibrary(
            name=name,
            sonames=tuple(_require(entry, "sonames", where)),
            rule=_entry_rule(entry, "crypto_library", by_id, where),
            symbol_group=None if symbol_group is None else str(symbol_group),
            string_group=None if string_group is None else str(string_group),
            copy_string_group=None if copy_string_group is None else str(copy_string_group),
            crates=library_crates,
            always_report=bool(entry.get("always_report", False)),
            **_entry_overrides(entry, classes, where),
        )

    crates: dict[str, RustCrateEntry] = {}
    for entry in data["rust_crate"]:
        name = str(_require(entry, "name", "[[rust_crate]]"))
        where = f"rust_crate {name!r}"
        crates[name] = RustCrateEntry(
            name=name,
            rule=_entry_rule(entry, "rust_crate", by_id, where),
            **_entry_overrides(entry, classes, where),
        )

    modules: dict[str, PythonModule] = {}
    for entry in data["python_module"]:
        name = str(_require(entry, "name", "[[python_module]]"))
        where = f"python_module {name!r}"
        modules[name] = PythonModule(
            name=name,
            rule=_entry_rule(entry, "python_module", by_id, where),
            **_entry_overrides(entry, classes, where),
        )

    symbol_groups: dict[str, SymbolGroup] = {}
    for entry in data["symbol_group"]:
        name = str(_require(entry, "name", "[[symbol_group]]"))
        where = f"symbol_group {name!r}"
        prefixes = tuple(sorted(_require(entry, "prefixes", where)))
        exact = frozenset(_require(entry, "exact", where))
        if not prefixes and not exact:
            raise RulesetError(f"{where}: has neither prefixes nor exact names")
        symbol_groups[name] = SymbolGroup(name=name, prefixes=prefixes, exact=exact)

    string_groups: dict[str, StringGroup] = {}
    for entry in data["string_group"]:
        name = str(_require(entry, "name", "[[string_group]]"))
        where = f"string_group {name!r}"
        substrings = tuple(sorted(_require(entry, "substrings", where)))
        if not substrings:
            raise RulesetError(f"{where}: has no substrings")
        # `match_string_groups` runs this pattern over runs joined with
        # `binfmt.strings.RUN_SEPARATOR`, and recovers each hit's enclosing run by
        # searching outward for that separator, on the assumption that no group's
        # pattern can ever match across it. A substring outside printable ASCII either
        # can never match extracted text at all, or -- if it is the separator itself --
        # is the one character whose presence would break that assumption; either way
        # it names nothing a real object carries, since extracted runs are printable
        # ASCII by construction, so it is refused here the same way an empty substring
        # list is, rather than silently authoring a rule that can never fire or, worse,
        # letting one hit's enclosing-run search swallow the boundary of a run after it.
        if any(ord(ch) not in PRINTABLE for text in substrings for ch in text):
            raise RulesetError(f"{where}: substrings must be printable ASCII")
        string_groups[name] = StringGroup(
            name=name,
            substrings=substrings,
            pattern=re.compile("|".join(re.escape(text) for text in substrings)),
        )

    ctypes_substrings: set[str] = set()
    for entry in data["ctypes_library"]:
        _require(entry, "why", "[[ctypes_library]]")
        ctypes_substrings.update(_require(entry, "substrings", "[[ctypes_library]]"))

    limits = Limits(**dict(data.get("limits", {})))
    _check_limits_leave_room_for_every_key(limits, symbol_groups, string_groups, crates)
    return Ruleset(
        version=str(version),
        precedence=precedence,
        limits=limits,
        conventions=_parse_conventions(_require(data, "conventions", source)),
        linkage_policy=_parse_linkage_policy(data.get("linkage_policy"), rules),
        rules=rules,
        distributions=MappingProxyType(distributions),
        libraries=MappingProxyType(libraries),
        rust_crates=MappingProxyType(crates),
        python_modules=MappingProxyType(modules),
        symbol_groups=MappingProxyType(symbol_groups),
        string_groups=MappingProxyType(string_groups),
        ctypes_substrings=tuple(sorted(ctypes_substrings)),
        _by_id=MappingProxyType(by_id),
    )


def load_ruleset(path: str | Path | None = None) -> Ruleset:
    """Load the shipped ruleset, or one supplied with --ruleset."""
    if path is None:
        resource = files("wheel_crypto_scan").joinpath("data/ruleset.toml")
        return parse_ruleset(tomllib.loads(resource.read_text(encoding="utf-8")), "ruleset.toml")
    source = Path(path)
    with source.open("rb") as handle:
        return parse_ruleset(tomllib.load(handle), source.name)
