"""The ruleset object model: dataclasses, vocabulary, the prefilter, and pattern compiling.

Everything policy-shaped lives in the TOML file; this module is one of two that turn it
into something the scanner can use. It owns the parsed shape -- `Rule`, `Conventions`,
`Ruleset` and the rest -- and `Ruleset.compile_patterns` builds each extractor's half of
the compiled patterns, `BinaryPatterns` or `PythonPatterns`, so they can bound what they
collect without knowing that rules exist. Only `ScanContext` holds both halves.

Reading the TOML into this shape, and refusing a malformed one loudly at load time
rather than silently mis-scanning, is `ruleset_loader`'s job: `load_ruleset` and
`parse_ruleset` live there, not here, so import them from `ruleset_loader`. See
`DECISIONS.md` for why the module split this way.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from fnmatch import fnmatch
from types import MappingProxyType
from typing import Any

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
        "binaries_truncated",
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

# The open-vocabulary sequence fields `compile_patterns` reads off every match table,
# regardless of `kind` -- a `py_call`/`py_attr`/`py_constant`-only meaning, but read
# generically because the alternative is three copies of the same collection loop.
# `ruleset_loader._validate_match_references` imports this same tuple to shape-check
# whichever of these keys a match table carries, on any kind, so a stray boolean here
# cannot crash `compile_patterns` even on a kind that never reads the field itself.
# One definition: a fourth key added to the loop below without a matching update here
# would silently stop being validated, the same drift `MATCHER_KINDS`/`engine._MATCHERS`
# guards against for matcher kinds themselves.
GENERIC_MATCH_SEQUENCE_KEYS = ("targets", "attributes", "constants")

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

# Bytes `binfmt.strings.sanitize` removes, so a name can carry any number of them
# between its characters without changing the name the matcher is shown. `\x00` is
# excluded: it ends a name rather than sitting inside one. Possessive, because the
# literal on either side is printable and so can never be inside this run -- without
# that, a name padded with a megabyte of control bytes is a backtracking bomb.
_SANITIZED_AWAY = rb"[^\x00\x20-\x7e]*+"


def _symbol_locator(names: Iterable[str]) -> re.Pattern[bytes] | None:
    """One byte regex finding anywhere a name a symbol group claims could be hiding.

    For a reader that has a whole string table and no idea which parts of it are
    symbol names: decoding and sanitising every run costs far more than the question
    is worth, and doing it in Python is how a 2 MiB string table of two-byte runs
    turns into eighteen seconds across a universal binary's slices.

    It locates, it does not decide. A hit means "look here properly", and the caller
    still forms the real name and asks `symbol_groups_for`. So it over-approximates
    freely -- it matches a prefix anywhere in a run, not just where a name starts --
    and must never under-approximate, which is why it lives here, next to the two arms
    of `SymbolGroup.matches` it is built from. A third arm has to be added here too.

    Every character is separated by the bytes `sanitize` would strip, so a name cannot
    be hidden from its own matcher by padding it with control bytes.

    Built as a trie rather than a flat alternation, which is a third of the scanning
    cost and two thirds of the pattern: `re` retries every branch of an alternation at
    every position, and the names a ruleset claims share long prefixes by construction.
    A branch stops at the first name that ends there, because anything longer through
    that node is found by the shorter name anyway.
    """
    root: dict[int | None, Any] = {}
    for name in sorted(set(names)):
        node = root
        for byte in name.encode("utf-8", "replace"):
            node = node.setdefault(byte, {})
        node[None] = None
    return re.compile(_locator_branch(root)) if root else None


def _locator_branch(node: Mapping[int | None, Any]) -> bytes:
    """One trie node as a regex, terminal nodes pruning everything below them."""
    if None in node:
        return b""
    branches = []
    for byte, below in sorted((key, value) for key, value in node.items() if key is not None):
        tail = _locator_branch(below)
        branches.append(re.escape(bytes([byte])) + (_SANITIZED_AWAY + tail if tail else b""))
    return branches[0] if len(branches) == 1 else b"(?:" + b"|".join(branches) + b")"


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

    auditwheel, delocate and delvewheel append a content hash to every library they
    vendor, so a mangled name is itself evidence that the wheel carries its own copy.
    """

    base: str
    mangled: bool
    original: str


@dataclass(frozen=True, slots=True)
class LinkagePolicy:
    """Which `partial_reasons` causes leave a linkage posture answerable.

    `linkage` asks one question of every object -- system, bundled, static or nothing
    -- off `needed`, `vendored_path`, the imported/defined split and the matched
    strings. A cause that can cost any of those means the object did not answer, and
    the wheel's posture has to say `unknown` rather than `none`.

    Which causes those are is policy, so the list lives in `ruleset.toml` beside the
    one `BIN_PARTIAL_ROUTINE` draws for verdicts. They are two different questions
    over one vocabulary and their answers differ: `elf_go_buildinfo_unread` is worth a
    verdict and costs linkage nothing, because Go toolchain provenance feeds no field
    `linkage` reads.
    """

    exclude_reasons: frozenset[str] = frozenset()

    def costs_an_answer(self, reasons: Iterable[str]) -> bool:
        """True when any of these causes could have hidden what linkage reads.

        Excluding rather than including, so a cause added to the vocabulary later
        costs us the answer until someone decides it does not.
        """
        return any(reason not in self.exclude_reasons for reason in reasons)


@dataclass(frozen=True, slots=True)
class Conventions:
    """How build tools lay wheels out. Structural facts, not policy."""

    vendor_dir_globs: tuple[str, ...]
    mangled_soname_regex: re.Pattern[str]
    windows_version_suffix_regex: re.Pattern[str]
    cargo_path_regex: re.Pattern[str]
    cargo_vendor_path_regex: re.Pattern[str]
    weak_hash_algorithms: frozenset[str]
    # No defaults, and ahead of the defaulted fields for that reason: the loader
    # refuses a ruleset whose go_boring_group/go_stock_group name no string group, and
    # a default here would let a directly built Conventions point at groups that need
    # not exist -- reinstating the silently-false boring_crypto the loader check exists
    # to prevent, wearing a dataclass default as a disguise.
    go_boring_group: str
    go_stock_group: str
    go_fips140_group: str
    library_suffixes: tuple[str, ...] = (".so", ".dylib", ".dll", ".pyd")
    windows_library_suffixes: tuple[str, ...] = (".dll", ".pyd")

    def is_vendor_path(self, path: str) -> bool:
        """True when any directory component is an auditwheel or delocate vendor dir."""
        parts = path.split("/")[:-1]
        return any(fnmatch(part, glob) for part in parts for glob in self.vendor_dir_globs)

    def _reduced_stem(self, name: str) -> tuple[str, bool]:
        """Strip path, version suffix and library extension. Shared by
        `normalise_soname` (also undoes a hash rename) and `raw_stem` (does not)."""
        stem = name.split("/")[-1]
        windows = False
        while True:
            stripped = _VERSION_SUFFIX.sub("", stem)
            for suffix in self.library_suffixes:
                # Only a Windows suffix is matched without regard to case, because only
                # Windows file names are case-insensitive. A Linux `libcrypto.SO.3` is
                # a file genuinely called that, and reducing it would be inventing one.
                on_windows = suffix in self.windows_library_suffixes
                matched = (
                    stripped.casefold().endswith(suffix.casefold())
                    if on_windows
                    else stripped.endswith(suffix)
                )
                if matched:
                    stripped = stripped[: -len(suffix)]
                    windows = windows or on_windows
                    break
            if stripped == stem:
                break
            stem = stripped
        if windows:
            stem = stem.casefold()
        return stem, windows

    def normalise_soname(self, name: str) -> SonameInfo:
        """Reduce `libcrypto-3a1f2b4c.so.3` or `libcrypto-3-x64.dll` to `libcrypto`."""
        stem, windows = self._reduced_stem(name)
        match = self.mangled_soname_regex.match(stem)  # pylint: disable=no-member
        mangled = match is not None
        if match is not None:
            stem = match.group("stem")
        if windows:
            # After the hash, so a vendored `libcrypto-3-x64-<hash>.dll` loses the hash
            # first and is still recognised as the vendored copy it is.
            decorated = self.windows_version_suffix_regex.match(stem)  # pylint: disable=no-member
            if decorated is not None:
                stem = decorated.group("stem")
        return SonameInfo(base=stem, mangled=mangled, original=name)

    def own_base(self, soname: str | None, path: str) -> str:
        """The library an object claims to be: its DT_SONAME, else its file name.

        An object that declares no SONAME is still the library its file name says it
        is, which is how a vendored copy gets recognised when the build stripped the
        declaration out.
        """
        return self.normalise_soname(soname or path.rsplit("/", 1)[-1]).base

    def raw_stem(self, soname: str | None, path: str) -> str:
        """Like `own_base`, but keeps a content-hash rename instead of undoing it, so a
        plain `needed` entry cannot match a same-family copy renamed elsewhere. #57."""
        stem, _ = self._reduced_stem(soname or path.rsplit("/", 1)[-1])
        return stem


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

    `suppressed_by` is per object: a hit of this rule is dropped only where a hit of a
    named rule fired on the same location path, never wheel-wide. A suppressor whose
    hits are located on a different path never suppresses. What a rule locates on
    follows its matcher kind, not its `layer`: most binary-layer `linkage` rules locate
    on the wheel path, not on the object they describe, so a same-layer relation naming
    one of them against a per-object binary rule never suppresses either. A `linkage`
    match with `object_values` set is the exception -- it locates per object instead,
    the same path a per-object binary rule shares. The loader accepts a relation
    between rules that can never share a path without complaint; it fires, it just
    never suppresses. It is also non-cascading -- a suppressor that is itself
    suppressed still suppresses -- so the loader refuses a `suppressed_by` cycle rather
    than silently dropping every member of one.
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

    `crates` is weaker than all three: a Rust crate that binds the library says the
    object uses it, not which copy. It never gives a definite posture, only `unknown`
    in place of `none`. Each name must also be a `[[rust_crate]]` entry, and the loader
    refusing one that is not carries more than typo-catching: `find_rust_crates` pins
    only `rust_crate_names` ahead of its cap, so a crate listed here alone could be
    cut from a Rust object with hundreds of crates and read `none` again. A
    `CryptoLibrary` built in code skips that check and owns the same guarantee.

    `copy_string_group` names strings only a compiled-in copy carries, never its
    headers. A match from `string_group` on an object that resolves the library from
    the host, imports from it, was read in full and matches nothing in
    `copy_string_group` is header text, not a copy. `None` means a banner always
    counts as a copy.
    """

    name: str
    sonames: tuple[str, ...]
    why: str
    rule: str | None = None
    symbol_group: str | None = None
    string_group: str | None = None
    copy_string_group: str | None = None
    crates: tuple[str, ...] = ()
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
    # Resolved finding keys, (owning rule id, crate name), that suppress this crate's
    # finding on an object where one of them also fired. Filled by the loader, which
    # resolves each named crate to its owning rule through that crate's own routing or
    # the table's default.
    suppressed_by: tuple[tuple[str, str], ...] = ()


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
    cargo_vendor_path_regex: re.Pattern[str]
    go_boring_group: str
    go_stock_group: str
    go_fips140_group: str
    limits: Limits
    # Crate names the ruleset has an entry for. The extractor stays free of policy --
    # it does not know what they mean -- but a cap that did not know which crates are
    # claimed dropped them alphabetically, and a Rust wheel carrying `ring` behind a
    # hundred and twenty-eight earlier names read as carrying nothing. Required, like
    # every other member here: a default is a guard that can stop guarding silently.
    rust_crate_names: frozenset[str]
    _exact_index: Mapping[str, tuple[str, ...]] = field(repr=False, default_factory=dict)
    _prefix_probe: re.Pattern[str] | None = field(repr=False, default=None)
    _string_index: Mapping[str, StringGroup] = field(repr=False, default_factory=dict)
    # One byte regex finding every place a name a symbol group claims could be hiding
    # in an undecoded blob. `None` when no group names anything.
    symbol_locator: re.Pattern[bytes] | None = field(repr=False, default=None)

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
    linkage_policy: LinkagePolicy
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
        locator = _symbol_locator(prefixes | set(exact_index))

        sequences: dict[str, set[str]] = {key: set() for key in GENERIC_MATCH_SEQUENCE_KEYS}
        for rule in self.rules:
            for match in rule.matches:
                for key, values in sequences.items():
                    values.update(match.get(key, ()))
        targets, attributes, constants = (sequences[key] for key in GENERIC_MATCH_SEQUENCE_KEYS)

        return ScanPatterns(
            binary=BinaryPatterns(
                symbol_groups=symbol_groups,
                string_groups=string_groups,
                cargo_path_regex=self.conventions.cargo_path_regex,
                cargo_vendor_path_regex=self.conventions.cargo_vendor_path_regex,
                go_boring_group=self.conventions.go_boring_group,
                go_stock_group=self.conventions.go_stock_group,
                go_fips140_group=self.conventions.go_fips140_group,
                limits=self.limits,
                _exact_index=MappingProxyType(
                    {name: tuple(sorted(groups)) for name, groups in exact_index.items()}
                ),
                _prefix_probe=probe,
                _string_index=MappingProxyType({group.name: group for group in string_groups}),
                symbol_locator=locator,
                rust_crate_names=frozenset(self.rust_crates),
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
