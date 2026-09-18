"""Loads and validates the TOML ruleset, and compiles the patterns extractors need.

Everything policy-shaped lives in the TOML file. This module's job is to read it, to
refuse a malformed one loudly at load time rather than silently mis-scanning, and to
hand each extractor its half of the compiled patterns -- `BinaryPatterns` or
`PythonPatterns` -- so they can bound what they collect without knowing that rules
exist. Only `ScanContext` holds both halves.
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from fnmatch import fnmatch
from importlib.resources import files
from pathlib import Path
from types import MappingProxyType
from typing import Any

from packaging.utils import canonicalize_name

from .errors import ERROR_KINDS, RulesetError

# Matcher kinds the scanner implements. A rule naming anything else cannot run, so the
# ruleset is rejected rather than quietly skipping the rule.
MATCHER_KINDS = frozenset(
    {
        "dist_name",
        "requires_dist",
        "wheel_generator",
        "no_source",
        "record_mismatch",
        "scan_error",
        "sbom_component",
        "bundled_library",
        "dt_needed",
        "dynamic_symbol",
        "binary_string",
        "rust_crate",
        "linkage",
        "opaque_binary",
        "partial_binary",
        "py_import",
        "py_call",
        "py_attr",
        "py_constant",
        "py_ctypes_load",
    }
)

SEVERITIES = frozenset({"high", "medium", "low", "info"})
CONFIDENCES = frozenset({"high", "medium", "low"})
LAYERS = frozenset({"metadata", "binary", "python", "derived"})
BINDINGS = frozenset({"imported", "defined", "any"})
LINKAGE_VALUES = frozenset({"system", "bundled", "static", "mixed", "none", "unknown"})

ENTRY_TABLES = (
    "crypto_distribution",
    "crypto_library",
    "symbol_group",
    "string_group",
    "rust_crate",
    "python_module",
    "ctypes_library",
)

# Which matcher kinds honour an entry's `rule` field. Several kinds read the same
# table -- [[crypto_library]] is read by `bundled_library`, `dt_needed`, `linkage` and
# `sbom_component` -- and only the kinds listed here route on it; the rest match every
# entry of the table they read. Routing an entry at a rule of any other kind would
# silently do nothing, so the parser refuses it.
ROUTED_KINDS = MappingProxyType(
    {
        "crypto_distribution": frozenset({"dist_name", "requires_dist"}),
        "crypto_library": frozenset({"bundled_library"}),
        "rust_crate": frozenset({"rust_crate"}),
        "python_module": frozenset({"py_import"}),
    }
)

# Tables whose entries may omit `rule` and fall to the table's default rule. Every
# [[crypto_distribution]] entry names its rule outright, so a default there could
# never be consulted and declaring one would only look effective.
DEFAULTABLE_TABLES = frozenset(ROUTED_KINDS) - {"crypto_distribution"}

_VERSION_SUFFIX = re.compile(r"\.\d+$")


def _require(mapping: Mapping[str, Any], key: str, where: str) -> Any:
    try:
        return mapping[key]
    except KeyError:
        raise RulesetError(f"{where}: missing required field '{key}'") from None


def _check(value: Any, allowed: Iterable[str], label: str, where: str) -> str:
    if value not in allowed:
        raise RulesetError(f"{where}: unknown {label} {value!r}")
    return str(value)


@dataclass(frozen=True, slots=True)
class Limits:
    """Output bounds. They cap record size; they never change what is detected."""

    max_locations_per_finding: int = 10
    max_symbols_per_binary: int = 64
    max_strings_per_binary: int = 64
    max_rust_crates_per_binary: int = 128
    max_evidence_chars: int = 200
    min_string_length: int = 4


@dataclass(frozen=True, slots=True)
class SonameInfo:
    """A library file name reduced to its base name, plus whether it was renamed.

    auditwheel and delocate append a content hash to every library they vendor, so a
    mangled name is itself evidence that the wheel carries its own copy.
    """

    base: str
    mangled: bool
    original: str


@dataclass(frozen=True, slots=True)
class Conventions:
    """How build tools lay wheels out. Structural facts, not policy."""

    vendor_dir_globs: tuple[str, ...]
    mangled_soname_regex: re.Pattern[str]
    cargo_path_regex: re.Pattern[str]
    weak_hash_algorithms: frozenset[str]
    library_suffixes: tuple[str, ...] = (".so", ".dylib", ".dll", ".pyd")
    go_boring_group: str = "go_boring"
    go_stock_group: str = "go_stock_crypto"

    def is_vendor_path(self, path: str) -> bool:
        """True when any directory component is an auditwheel or delocate vendor dir."""
        parts = path.split("/")[:-1]
        return any(fnmatch(part, glob) for part in parts for glob in self.vendor_dir_globs)

    def normalise_soname(self, name: str) -> SonameInfo:
        """Reduce `libcrypto-3a1f2b4c.so.3` to `libcrypto`, remembering it was renamed."""
        stem = name.split("/")[-1]
        while True:
            stripped = _VERSION_SUFFIX.sub("", stem)
            for suffix in self.library_suffixes:
                if stripped.endswith(suffix):
                    stripped = stripped[: -len(suffix)]
                    break
            if stripped == stem:
                break
            stem = stripped
        match = self.mangled_soname_regex.match(stem)  # pylint: disable=no-member
        if match is not None:
            return SonameInfo(base=match.group("stem"), mangled=True, original=name)
        return SonameInfo(base=stem, mangled=False, original=name)

    def own_base(self, soname: str | None, path: str) -> str:
        """The library an object claims to be: its DT_SONAME, else its file name.

        An object that declares no SONAME is still the library its file name says it
        is, which is how a vendored copy gets recognised when the build stripped the
        declaration out.
        """
        return self.normalise_soname(soname or path.rsplit("/", 1)[-1]).base


@dataclass(frozen=True, slots=True)
class Rule:
    """One rule as written in the TOML file.

    A rule carries one match table, or several when it is written as `[[rule.match]]`.
    Several are ORed: one concern reached through two matcher kinds is still one rule
    id in the record, and splitting it in two would split the finding too. NOT is what
    `suppressed_by` is for, and AND across evidence types is what `linkage` is for.

    There is deliberately no singular `match`: with two tables any such shortcut names
    whichever was written first and quietly lies about the rest. The engine dispatches
    per table and hands the matcher the one it was dispatched for.
    """

    id: str
    layer: str
    category: str
    severity: str
    confidence: str
    needs_human_review: bool
    title: str
    why: str
    matches: tuple[Mapping[str, Any], ...]
    verdict: str | None = None
    suppressed_by: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Distribution:
    """A Python project on the watch list, and the rule it fires."""

    name: str
    rule: str
    why: str
    severity: str | None = None
    verdict: str | None = None
    needs_human_review: bool | None = None


@dataclass(frozen=True, slots=True)
class CryptoLibrary:
    """A native crypto library, and how to recognise it in three different ways.

    `sonames` finds a library file or a dependency on one. `symbol_group` and
    `string_group` are what let the linkage resolver recognise a copy that was compiled
    straight into an extension, where there is no file and no dependency to find.
    """

    name: str
    sonames: tuple[str, ...]
    why: str
    rule: str | None = None
    symbol_group: str | None = None
    string_group: str | None = None
    # Report this library's linkage even when nothing matched, because consumers
    # filter on the field and a missing key is harder to handle than "none".
    always_report: bool = False
    severity: str | None = None
    verdict: str | None = None
    needs_human_review: bool | None = None


@dataclass(frozen=True, slots=True)
class RustCrateEntry:
    """A cargo crate on the watch list, with its own severity and verdict."""

    name: str
    why: str
    rule: str | None = None
    severity: str | None = None
    verdict: str | None = None
    needs_human_review: bool | None = None


@dataclass(frozen=True, slots=True)
class PythonModule:
    """An importable module on the watch list, with its own severity and verdict."""

    name: str
    why: str
    rule: str | None = None
    severity: str | None = None
    verdict: str | None = None
    needs_human_review: bool | None = None


@dataclass(frozen=True, slots=True)
class SymbolGroup:
    """Dynamic symbol names belonging to one library or primitive family."""

    name: str
    prefixes: tuple[str, ...]
    exact: frozenset[str]

    def matches(self, symbol: str) -> bool:
        return symbol in self.exact or symbol.startswith(self.prefixes)


@dataclass(frozen=True, slots=True)
class StringGroup:
    """Literal substrings to look for in read-only data, as one compiled alternation."""

    name: str
    substrings: tuple[str, ...]
    pattern: re.Pattern[str]


@dataclass(frozen=True, slots=True)
class BinaryPatterns:
    """What the binary readers need, and nothing else.

    Extractors take this as an argument instead of importing the ruleset, which is what
    keeps them free of policy while still letting them bound what they collect.
    """

    symbol_groups: tuple[SymbolGroup, ...]
    string_groups: tuple[StringGroup, ...]
    cargo_path_regex: re.Pattern[str]
    go_boring_group: str
    go_stock_group: str
    limits: Limits
    _exact_index: Mapping[str, tuple[str, ...]] = field(repr=False, default_factory=dict)
    _prefix_probe: re.Pattern[str] | None = field(repr=False, default=None)
    _string_index: Mapping[str, StringGroup] = field(repr=False, default_factory=dict)

    def symbol_groups_for(self, symbol: str) -> tuple[str, ...]:
        """Group names claiming this symbol, sorted. Empty when nothing claims it."""
        if symbol in self._exact_index:
            pass
        elif self._prefix_probe is None or not self._prefix_probe.match(symbol):
            return ()
        return tuple(group.name for group in self.symbol_groups if group.matches(symbol))

    def string_group(self, name: str) -> StringGroup:
        return self._string_index[name]


@dataclass(frozen=True, slots=True)
class PythonPatterns:
    """What the Python source extractor needs, and nothing else.

    The same bargain as `BinaryPatterns`, over a disjoint set of names: nothing here is
    read while walking a binary, and nothing there is read while walking an AST.
    """

    py_modules: tuple[str, ...]
    py_call_targets: tuple[str, ...]
    py_attributes: tuple[str, ...]
    py_constants: tuple[str, ...]
    ctypes_substrings: tuple[str, ...]
    limits: Limits


@dataclass(frozen=True, slots=True)
class ScanPatterns:
    """Both compiled halves, built once per worker and handed out one half at a time.

    The two halves share nothing but `limits`, so a contributor reading either one sees
    only the names that half can actually match on.
    """

    binary: BinaryPatterns
    python: PythonPatterns


@dataclass(frozen=True, slots=True)
class Ruleset:
    """The parsed, validated ruleset."""

    version: str
    precedence: tuple[str, ...]
    limits: Limits
    conventions: Conventions
    rules: tuple[Rule, ...]
    distributions: Mapping[str, Distribution]
    libraries: Mapping[str, CryptoLibrary]
    rust_crates: Mapping[str, RustCrateEntry]
    python_modules: Mapping[str, PythonModule]
    symbol_groups: Mapping[str, SymbolGroup]
    string_groups: Mapping[str, StringGroup]
    ctypes_substrings: tuple[str, ...]
    _by_id: Mapping[str, Rule] = field(repr=False, default_factory=dict)

    def rule(self, rule_id: str) -> Rule:
        return self._by_id[rule_id]

    def matches_for_kind(self, kind: str) -> tuple[tuple[Rule, Mapping[str, Any]], ...]:
        """Every (rule, match table) pair of this matcher kind.

        Pairs rather than rules: a rule can be reached through two kinds, so handing
        back the whole rule would leave the caller guessing which of its tables belongs
        to the kind it asked for.
        """
        return tuple(
            (rule, match) for rule in self.rules for match in rule.matches if match["kind"] == kind
        )

    def default_rule_for_table(self, table: str, kind: str) -> Rule | None:
        """The rule claiming entries of `table` that name none, for one matcher kind.

        The kind is part of the question. Several kinds read the same table and only
        one of them routes on `rule` (see `ROUTED_KINDS`), so a default declared by a
        rule of another kind is not this table's default at all.
        """
        for rule in self.rules:
            for match in rule.matches:
                if match.get("default") and match.get("table") == table and match["kind"] == kind:
                    return rule
        return None

    def compile_patterns(self) -> ScanPatterns:
        """Build the extractor-facing view of this ruleset."""
        symbol_groups = tuple(self.symbol_groups[name] for name in sorted(self.symbol_groups))
        string_groups = tuple(self.string_groups[name] for name in sorted(self.string_groups))

        exact_index: dict[str, list[str]] = {}
        prefixes: set[str] = set()
        for group in symbol_groups:
            for symbol in group.exact:
                exact_index.setdefault(symbol, []).append(group.name)
            prefixes.update(group.prefixes)

        probe = (
            re.compile("|".join(re.escape(prefix) for prefix in sorted(prefixes)))
            if prefixes
            else None
        )

        targets: set[str] = set()
        attributes: set[str] = set()
        constants: set[str] = set()
        for rule in self.rules:
            for match in rule.matches:
                targets.update(match.get("targets", ()))
                attributes.update(match.get("attributes", ()))
                constants.update(match.get("constants", ()))

        return ScanPatterns(
            binary=BinaryPatterns(
                symbol_groups=symbol_groups,
                string_groups=string_groups,
                cargo_path_regex=self.conventions.cargo_path_regex,
                go_boring_group=self.conventions.go_boring_group,
                go_stock_group=self.conventions.go_stock_group,
                limits=self.limits,
                _exact_index=MappingProxyType(
                    {name: tuple(sorted(groups)) for name, groups in exact_index.items()}
                ),
                _prefix_probe=probe,
                _string_index=MappingProxyType({group.name: group for group in string_groups}),
            ),
            python=PythonPatterns(
                py_modules=tuple(sorted(self.python_modules)),
                py_call_targets=tuple(sorted(targets)),
                py_attributes=tuple(sorted(attributes)),
                py_constants=tuple(sorted(constants)),
                ctypes_substrings=self.ctypes_substrings,
                limits=self.limits,
            ),
        )


def _parse_conventions(data: Mapping[str, Any]) -> Conventions:
    where = "[conventions]"
    try:
        mangled = re.compile(str(_require(data, "mangled_soname_regex", where)))
        cargo = re.compile(str(_require(data, "cargo_path_regex", where)))
    except re.error as exc:
        raise RulesetError(f"{where}: invalid regular expression: {exc}") from None
    for pattern, group in ((mangled, "stem"), (cargo, "name")):
        if group not in pattern.groupindex:
            raise RulesetError(f"{where}: pattern {pattern.pattern!r} needs a '{group}' group")
    return Conventions(
        vendor_dir_globs=tuple(_require(data, "vendor_dir_globs", where)),
        mangled_soname_regex=mangled,
        cargo_path_regex=cargo,
        weak_hash_algorithms=frozenset(_require(data, "weak_hash_algorithms", where)),
        library_suffixes=tuple(_require(data, "library_suffixes", where)),
        go_boring_group=str(_require(data, "go_boring_group", where)),
        go_stock_group=str(_require(data, "go_stock_group", where)),
    )


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
    elif kind == "linkage":
        values = match.get("values")
        if values is None:
            _check(match.get("value"), LINKAGE_VALUES, "linkage value", where)
        else:
            for value in values:
                _check(value, LINKAGE_VALUES, "linkage value", where)

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
        libraries[name] = CryptoLibrary(
            name=name,
            sonames=tuple(_require(entry, "sonames", where)),
            rule=_entry_rule(entry, "crypto_library", by_id, where),
            symbol_group=None if symbol_group is None else str(symbol_group),
            string_group=None if string_group is None else str(string_group),
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
        string_groups[name] = StringGroup(
            name=name,
            substrings=substrings,
            pattern=re.compile("|".join(re.escape(text) for text in substrings)),
        )

    ctypes_substrings: set[str] = set()
    for entry in data["ctypes_library"]:
        _require(entry, "why", "[[ctypes_library]]")
        ctypes_substrings.update(_require(entry, "substrings", "[[ctypes_library]]"))

    return Ruleset(
        version=str(version),
        precedence=precedence,
        limits=Limits(**dict(data.get("limits", {}))),
        conventions=_parse_conventions(_require(data, "conventions", source)),
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
