"""The ruleset object model: dataclasses, vocabulary, the prefilter, and pattern compiling.

Everything policy-shaped lives in the TOML file; this module is one of three that turn
it into something the scanner can use. It owns the parsed shape -- `Rule`, `Ruleset`
and the rest -- and `Ruleset.compile_patterns` builds each extractor's half of the
compiled patterns, `BinaryPatterns` or `PythonPatterns`, so they can bound what they
collect without knowing that rules exist. Only `ScanContext` holds both halves.
`Conventions`, the other structural half of the parsed shape, lives in `conventions`
instead; import it from there.

Reading the TOML into this shape, and refusing a malformed one loudly at load time
rather than silently mis-scanning, is `ruleset_loader`'s job: `load_ruleset` and
`parse_ruleset` live there, not here, so import them from `ruleset_loader`. See
`DESIGN.md` for why the module split this way.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from .conventions import Conventions
from .standards import Standard

# What each matcher kind reads off its `[rule.match]` table, plus `kind` itself and,
# where the loader and `Ruleset.default_rule_for_table` read them, `table`/`default`. A
# key a match table carries that is not listed here is refused at load time, because it
# would otherwise load clean and do nothing -- the same typo trap `[linkage_policy]`
# closes for its own keys. `tests/test_ruleset.py` walks `engine.py` with `ast` and
# fails in both directions: a matcher reading a key its entry does not list, and a
# listed key nothing reads.
_ENTRY_ROUTING_KEYS = frozenset({"table", "default"})

MATCH_KEYS: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "dist_name": frozenset({"kind"} | _ENTRY_ROUTING_KEYS),
        "requires_dist": frozenset({"kind", "any_entry"} | _ENTRY_ROUTING_KEYS),
        "wheel_generator": frozenset({"kind"}),
        "no_source": frozenset({"kind"}),
        "record_mismatch": frozenset({"kind"}),
        "scan_error": frozenset({"kind", "error_kinds"}),
        "sbom_component": frozenset({"kind", "tables"}),
        "bundled_library": frozenset(
            {"kind", "library", "exclude_libraries"} | _ENTRY_ROUTING_KEYS
        ),
        "dt_needed": frozenset({"kind", "library", "mangled", "resolved"} | _ENTRY_ROUTING_KEYS),
        "dynamic_symbol": frozenset({"kind", "binding", "group", "groups"}),
        "binary_string": frozenset({"kind", "group", "groups"}),
        "rust_crate": frozenset({"kind"} | _ENTRY_ROUTING_KEYS),
        "linkage": frozenset(
            {
                "kind",
                "name",
                "value",
                "values",
                "exclude_libraries",
                "object_values",
                "exclude_object_values",
                "sbom_declared",
            }
            | _ENTRY_ROUTING_KEYS
        ),
        "opaque_binary": frozenset({"kind"}),
        "partial_binary": frozenset({"kind", "reasons", "exclude_reasons"}),
        "binaries_truncated": frozenset({"kind"}),
        "py_import": frozenset({"kind"} | _ENTRY_ROUTING_KEYS),
        "py_call": frozenset({"kind", "targets", "usedforsecurity", "algorithm", "algorithm_list"}),
        "py_attr": frozenset({"kind", "attributes", "values"}),
        "py_constant": frozenset({"kind", "constants"}),
        "py_ctypes_load": frozenset({"kind"} | _ENTRY_ROUTING_KEYS),
    }
)

# Matcher kinds the scanner implements. A rule naming anything else cannot run, so the
# ruleset is rejected rather than quietly skipping the rule.
MATCHER_KINDS = frozenset(MATCH_KEYS)

# What `algorithm_list` on a `py_call` match names: which of `conventions`'s two hash
# lists the match filters against, or their union under "weak" -- the same three-way
# split `Conventions.weak_hash_algorithms` derives. A closed vocabulary for the same
# reason `RELATIONS`/`FAMILIES` are: a typo here should fail to load rather than
# silently filter against nothing.
ALGORITHM_LISTS = frozenset({"refused", "restricted", "weak"})

SEVERITIES = frozenset({"high", "medium", "low", "info"})

# What a `relation` names: what would have to change for the finding to go away, the
# question a consumer of the index actually asks. Carried on `Rule` and on every entry
# in the four override-bearing tables, always beside a non-empty `basis` -- a citation
# must never stand alone -- and validated by the loader the same way `SEVERITIES` is.
RELATIONS = frozenset(
    {
        "not_specified",
        "restricted",
        "outside_module",
        "boundary_unresolved",
        "runtime_refusal",
        "policy_bypass",
        "use_unresolved",
    }
)

# Which verdict classes a `relation` is consistent with. A pair outside this table says
# two things about the same finding -- what would fix it, and how bad leaving it is --
# that disagree with each other, so `ruleset_coherence.check_relation_matches_verdict`
# refuses it at load time. `restricted` is the one relation with two answers: the
# finding is `NON_APPROVED_CRYPTO` when the wheel implements the primitive itself, and
# `CONTEXT_DEPENDENT` when it defers to the host module and only the use is in
# question. No relation names `OPAQUE`: unreadability has no standard to cite, so a
# verdict of `OPAQUE` paired with any relation is refused the same way.
RELATION_CLASSES: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "not_specified": frozenset({"NON_APPROVED_CRYPTO"}),
        "restricted": frozenset({"NON_APPROVED_CRYPTO", "CONTEXT_DEPENDENT"}),
        "outside_module": frozenset({"NON_APPROVED_CRYPTO"}),
        "boundary_unresolved": frozenset({"CONDITIONAL"}),
        "runtime_refusal": frozenset({"FIPS_BREAKING"}),
        "policy_bypass": frozenset({"CONDITIONAL"}),
        "use_unresolved": frozenset({"CONTEXT_DEPENDENT"}),
    }
)

# The FIPS-agnostic vocabulary for what a piece of evidence *is*, as opposed to what it
# means for FIPS compatibility: carried on every entry in the four override-bearing
# tables and on every `[[symbol_group]]`/`[[string_group]]`, so crypto inventory (which
# families a wheel carries) can be read without going through the FIPS lens at all.
# `library` is a general-purpose stack -- OpenSSL, libsodium, pycryptodome -- whose own
# primitives span several of the other families.
FAMILIES = frozenset(
    {
        "hash",
        "checksum",
        "block_cipher",
        "stream_cipher",
        "aead",
        "mac",
        "kdf",
        "password_hash",
        "signature",
        "key_agreement",
        "kem",
        "drbg",
        "entropy",
        "tls",
        "ssh",
        "trust_store",
        "library",
    }
)

CONFIDENCES = frozenset({"high", "medium", "low"})
LAYERS = frozenset({"metadata", "binary", "python", "derived"})
BINDINGS = frozenset({"imported", "defined", "any"})
LINKAGE_VALUES = frozenset({"system", "bundled", "static", "mixed", "none", "unknown"})

# The class of `Location.path` each matcher kind's hits carry -- `suppressed_by` keys
# on that path, so `ruleset_loader` uses this table to refuse a relation between two
# rules whose hits could never land on the same one. `None` means the path depends on
# the evidence itself and can land anywhere: `scan_error` and `record_mismatch` are
# wildcards for that reason, and a relation naming either side is always accepted. A
# `linkage` match locates on the wheel's own filename by default; one that also carries
# `object_values` locates per object instead, which `match_location` below handles
# because it depends on the match table, not the kind alone. `dist_name`,
# `requires_dist` and `wheel_generator` fall back to the wheel's own filename when a
# wheel ships no dist-info directory at all, but that branch is unreachable from a real
# scan -- metadata extraction returns no evidence at all in that case -- so it is not
# modelled as a fourth, wheel-shared class here.
MATCHER_LOCATIONS: Mapping[str, str | None] = MappingProxyType(
    {
        "dist_name": "dist_info",
        "requires_dist": "metadata_file",
        "wheel_generator": "wheel_file",
        "sbom_component": "sbom",
        "no_source": "wheel",
        "binaries_truncated": "wheel",
        "record_mismatch": None,
        "scan_error": None,
        "bundled_library": "object",
        "dt_needed": "object",
        "dynamic_symbol": "object",
        "binary_string": "object",
        "rust_crate": "object",
        "linkage": "wheel",
        "opaque_binary": "object",
        "partial_binary": "object",
        "py_import": "python_source",
        "py_call": "python_source",
        "py_attr": "python_source",
        "py_constant": "python_source",
        "py_ctypes_load": "python_source",
    }
)


def match_location(match: Mapping[str, Any]) -> str | None:
    """The location class this match table's hits locate on (see `MATCHER_LOCATIONS`).

    A `linkage` match carrying `object_values` locates per object, the one shape whose
    location class is not decided by its `kind` alone; every other kind reads straight
    off `MATCHER_LOCATIONS`.
    """
    if match["kind"] == "linkage" and "object_values" in match:
        return "object"
    return MATCHER_LOCATIONS[match["kind"]]


# The open-vocabulary sequence fields `compile_patterns` reads off every match table,
# regardless of `kind` -- a `py_call`/`py_attr`/`py_constant`-only meaning, but read
# generically because the alternative is three copies of the same collection loop.
# `MATCH_KEYS` is what keeps a stray one of these off a kind that never reads it --
# `targets` on a `dist_name` match, say -- refused at load time rather than reaching
# `compile_patterns` as a boolean or other shape it cannot handle. On the one kind
# each of these keys is allowed on, that kind's arm in
# `ruleset_loader._validate_match_references` already requires and shape-checks it;
# the loop there over this same tuple is the backstop for a kind that gains one of
# these keys in `MATCH_KEYS` without also gaining a shape-check of its own. One
# definition, read by both.
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
    return _trie_locator(names, between=_SANITIZED_AWAY)


def _code_string_locator(groups: Iterable[StringGroup]) -> re.Pattern[bytes] | None:
    """One byte regex finding anywhere a substring an `in_code` group claims could sit.

    The code pass reads raw executable bytes, not a string table split into runs by
    control-byte padding, so unlike `_symbol_locator` there is nothing to skip between
    characters: `between` is empty and a hit is the literal substring, contiguous.

    It locates, it does not decide, the same contract `_symbol_locator` carries: a hit
    means "look here properly", and `binfmt.strings.find_code_strings` still runs the
    real `StringGroup.pattern` over the printable text recovered around it. It must
    never under-approximate `StringGroup.pattern` over any `in_code` group's own
    substrings, which is why it is built from the same `substrings` field and lives
    here beside it rather than being re-derived by a caller. `None` when no group is
    flagged `in_code`, so a caller can skip the whole code-reading path on that alone.
    """
    substrings = [substring for group in groups for substring in group.substrings]
    return _trie_locator(substrings, between=b"")


def _trie_locator(names: Iterable[str], *, between: bytes) -> re.Pattern[bytes] | None:
    """A trie-built byte locator for `names`, joining consecutive bytes with `between`.

    Shared by `_symbol_locator` and `_code_string_locator`, which differ only in what
    can legitimately separate one byte of a name from the next in the bytes being
    searched: `_SANITIZED_AWAY` for a name sitting in a string table `sanitize` would
    otherwise strip control bytes from, `b""` for a substring read straight out of
    executable code, where nothing pads one character from the next.
    """
    root: dict[int | None, Any] = {}
    for name in sorted(set(names)):
        node = root
        for byte in name.encode("utf-8", "replace"):
            node = node.setdefault(byte, {})
        node[None] = None
    return re.compile(_locator_branch(root, between=between)) if root else None


def _locator_branch(node: Mapping[int | None, Any], *, between: bytes) -> bytes:
    """One trie node as a regex, terminal nodes pruning everything below them."""
    if None in node:
        return b""
    branches = []
    for byte, below in sorted((key, value) for key, value in node.items() if key is not None):
        tail = _locator_branch(below, between=between)
        branches.append(re.escape(bytes([byte])) + (between + tail if tail else b""))
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
class Rule:
    """One rule as written in the TOML file.

    A rule carries one match table, or several when it is written as `[[rule.match]]`.
    Several are ORed: one concern reached through two matcher kinds is still one rule
    id in the record, and splitting it in two would split the finding too. NOT is what
    `suppressed_by` is for, and AND across evidence types is what `linkage` is for.

    There is deliberately no singular `match`: with two tables any such shortcut names
    whichever was written first and quietly lies about the rest. The engine dispatches
    per table and hands the matcher the one it was dispatched for.

    `suppressed_by` is per object, keyed on the hit's own `Location.path`: a hit of
    this rule is dropped only where a hit of a named rule fired on that same path,
    never wheel-wide, and the loader refuses a relation between rules that can never
    share one (see `MATCHER_LOCATIONS`). It is also non-cascading -- a suppressor that
    is itself suppressed still suppresses -- so the loader refuses a `suppressed_by`
    cycle rather than silently dropping every member of one.
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
    # What would have to change for this finding to go away, and the standards that
    # say so -- see `RELATIONS`/`RELATION_CLASSES`. Always both or neither.
    relation: str | None = None
    basis: tuple[str, ...] = ()
    # What kind of primitive this finding is evidence of -- see `FAMILIES`.
    family: str | None = None


@dataclass(frozen=True, slots=True)
class Distribution:
    """A Python project on the watch list, and the rule it fires."""

    name: str
    rule: str
    why: str
    severity: str | None = None
    verdict: str | None = None
    needs_human_review: bool | None = None
    relation: str | None = None
    basis: tuple[str, ...] = ()
    family: str | None = None


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
    the host or from a bundled copy, imports from it, was read in full and matches
    nothing in `copy_string_group` is header text, not a copy. On an object with no
    dependency on the library at all, read in full, that same absence makes a banner
    uncorroborated prose rather than a copy. `None` means a banner always counts as a
    copy either way.

    `fork_symbol_groups` and `fork_string_groups` name symbol and string groups that
    identify a different library implementing this one's API under this one's names
    -- AWS-LC and BoringSSL both define OpenSSL's `EVP_*`/`BN_*`/... entry points
    under OpenSSL's own names. On an object where one of them matched (a symbol
    group only when the match is DEFINED there), this library's `symbol_group`
    definitions say some implementation of the API was compiled in, not which one,
    so definitions alone give `unknown` rather than `static` -- and a `string_group`
    match whose own text is entirely explained by the fork groups' own patterns is
    that fork's own header banner, not evidence of this library, so a banner alone
    gives `unknown` the same way, and it does not save the definitions from that
    reading either. A `needed` entry, or a combination that already reads `mixed`,
    is unaffected.
    """

    name: str
    sonames: tuple[str, ...]
    why: str
    rule: str | None = None
    symbol_group: str | None = None
    string_group: str | None = None
    copy_string_group: str | None = None
    crates: tuple[str, ...] = ()
    fork_symbol_groups: tuple[str, ...] = ()
    fork_string_groups: tuple[str, ...] = ()
    # Report this library's linkage even when nothing matched, because consumers
    # filter on the field and a missing key is harder to handle than "none".
    always_report: bool = False
    severity: str | None = None
    verdict: str | None = None
    needs_human_review: bool | None = None
    relation: str | None = None
    basis: tuple[str, ...] = ()
    family: str | None = None


@dataclass(frozen=True, slots=True)
class RustCrateEntry:
    """A cargo crate on the watch list, with its own severity and verdict."""

    name: str
    why: str
    rule: str | None = None
    severity: str | None = None
    verdict: str | None = None
    needs_human_review: bool | None = None
    relation: str | None = None
    basis: tuple[str, ...] = ()
    family: str | None = None
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
    relation: str | None = None
    basis: tuple[str, ...] = ()
    family: str | None = None


@dataclass(frozen=True, slots=True)
class SymbolGroup:
    """Dynamic symbol names belonging to one library or primitive family."""

    name: str
    prefixes: tuple[str, ...]
    exact: frozenset[str]
    # What kind of primitive this group's symbols belong to -- see `FAMILIES`. Inert to
    # matching: `SymbolGroup.matches` and the locators built from `prefixes`/`exact`
    # never read it, only carried through to the finding for the crypto inventory.
    family: str | None = None

    def matches(self, symbol: str) -> bool:
        return symbol in self.exact or symbol.startswith(self.prefixes)


@dataclass(frozen=True, slots=True)
class StringGroup:
    """Literal substrings to look for in read-only data, and, when `in_code`, in ELF
    executable sections too, as one compiled alternation."""

    name: str
    substrings: tuple[str, ...]
    pattern: re.Pattern[str]
    in_code: bool
    # What kind of primitive this group's strings belong to -- see `FAMILIES`. Inert to
    # matching, the same way and for the same reason as `SymbolGroup.family` above.
    family: str | None = None


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
    cargo_git_path_regex: re.Pattern[str]
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
    # The `in_code` groups, sorted by name -- the only groups `binfmt.elf` searches
    # ELF executable sections for. Empty for every ruleset that flags none.
    code_string_groups: tuple[StringGroup, ...] = ()
    # One byte regex finding every place a substring an `in_code` group claims could
    # sit in raw executable bytes. `None` when no group is flagged `in_code`.
    code_string_locator: re.Pattern[bytes] | None = field(repr=False, default=None)

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


def sbom_library_key(name: str) -> str:
    """Fold an SBOM component name to a `[[crypto_library]]` lookup key.

    A C library ships under no registry that treats case or punctuation as
    insignificant, and no shipped library name in the ruleset carries a `-` or `_`
    either, so the only fold that reflects a real equivalence is case: `OpenSSL` and
    `openssl` name the same library, `openssl-sys` and `openssl_sys` do not (and never
    collide with this table in the first place). Both `SBOM_CRYPTO_COMPONENT`
    (`engine._sbom_entry`) and `linkage._declared_by_sbom` must resolve a
    `crypto_library` name through this and nothing else, so the finding and the field
    can never disagree about the same string.

    Folds case only on an ASCII name. Every shipped `[[crypto_library]]` name is ASCII,
    and Unicode case folding is not the same equivalence as ASCII case: U+212A KELVIN
    SIGN lowercases to ASCII `k`, so folding a non-ASCII name here could match it
    against an ASCII entry it never actually spelled. A non-ASCII name is returned
    unchanged, which cannot collide with any shipped key.
    """
    return name.lower() if name.isascii() else name


def sbom_crate_key(name: str) -> str:
    """Fold an SBOM component name to a `[[rust_crate]]` lookup key.

    crates.io names are case-insensitive and treat `-` and `_` as the same character
    (a crate published as `foo-bar` and one published as `foo_bar` are the same
    registry entry), so an SBOM naming either spelling means the same crate. Both
    `SBOM_CRYPTO_COMPONENT` (`engine._sbom_entry`) and `linkage._declared_by_sbom` must
    resolve a `rust_crate` name through this and nothing else, so the finding and the
    field can never disagree about the same string.

    Folds case only on an ASCII name, the same reasoning and the same `sbom_library_key`
    (above) rejects Unicode case folding for: crates.io names are themselves ASCII-only,
    and a character like U+212A KELVIN SIGN folding onto ASCII `k` is not an equivalence
    crates.io draws. A non-ASCII name is returned unchanged.
    """
    return name.lower().replace("_", "-") if name.isascii() else name


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
    # Keyed on `Standard.id`. Defaults to empty rather than requiring every direct
    # `Ruleset(...)` construction in a test to supply one: a ruleset with no `basis`
    # anywhere is coherent with no standards declared at all. `default_factory`
    # rather than a bare literal: `MappingProxyType({}).__hash__` is `None` on Python
    # 3.11, so `dataclasses` reads the literal as a mutable default and refuses to
    # build the class at all -- a factory sidesteps that check regardless of hashability.
    standards: Mapping[str, Standard] = field(default_factory=lambda: MappingProxyType({}))
    _by_id: Mapping[str, Rule] = field(repr=False, default_factory=dict)
    _libraries_by_sbom_key: Mapping[str, CryptoLibrary] = field(repr=False, default_factory=dict)
    _crates_by_sbom_key: Mapping[str, RustCrateEntry] = field(repr=False, default_factory=dict)

    def rule(self, rule_id: str) -> Rule:
        return self._by_id[rule_id]

    def library_for_sbom_name(self, name: str) -> CryptoLibrary | None:
        return self._libraries_by_sbom_key.get(sbom_library_key(name))

    def crate_for_sbom_name(self, name: str) -> RustCrateEntry | None:
        return self._crates_by_sbom_key.get(sbom_crate_key(name))

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

    def crate_suppressors(self, name: str) -> tuple[str, ...]:
        """Other `[[rust_crate]]` names whose finding, on the same object, drops `name`'s.

        Mirrors what `engine._apply_suppression` does for the `rust_crate` matcher on
        one object, restricted to crate evidence: a rule's non-crate matches (such as
        `BIN_AWS_LC_FIPS`'s symbol and string groups) have nothing to match against in
        an SBOM, so only relations between crates apply here. Two sources, both keyed
        on the *owning* rule, the same way `engine._apply_suppression` reads a hit's
        entry-level `suppressed_by`: the entry's own `suppressed_by` crate names, and
        every other crate whose owner is named in this crate's own owning rule's
        `suppressed_by` (the shipped AWS-LC shape, routed through two dedicated
        rules). Returns `()` for an unknown name or a crate with no owning rule.
        """
        entry = self.rust_crates.get(name)
        if entry is None:
            return ()
        default = self.default_rule_for_table("rust_crate", "rust_crate")

        def owner_of(crate: RustCrateEntry) -> str | None:
            return crate.rule or (default.id if default is not None else None)

        owner = owner_of(entry)
        names = {other for _, other in entry.suppressed_by}
        if owner is not None:
            owner_rule = self.rule(owner)
            for other_name, other_entry in self.rust_crates.items():
                if other_name != name and owner_of(other_entry) in owner_rule.suppressed_by:
                    names.add(other_name)
        return tuple(sorted(names))

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
        code_groups = tuple(group for group in string_groups if group.in_code)
        code_locator = _code_string_locator(code_groups)

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
                cargo_git_path_regex=self.conventions.cargo_git_path_regex,
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
                code_string_groups=code_groups,
                code_string_locator=code_locator,
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
