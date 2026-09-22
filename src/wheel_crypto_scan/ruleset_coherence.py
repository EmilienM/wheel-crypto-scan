"""Checks over the parsed rules as a whole: relations between rules that no single
rule's own parse can see.

Every check here refuses a ruleset whose rules contradict each other: a `suppressed_by`
that can never fire or closes a cycle, an SBOM relation that would leave a
`<name>_linkage` moved with no finding to explain it, a `basis` that cites a standard
no longer live or names nothing, a declared standard nothing cites, and a `relation`
paired with a verdict class the compatibility table does not allow. Each reads
`Rule`/`Ruleset` objects `ruleset_loader.parse_ruleset` has already built, shape-checked
and reference-resolved, and assumes that last part: every `suppressed_by` and every
crate owner names a rule that exists, and every `[[standard]]` entry is already a valid
`Standard` with its own `successor` chain checked. Called any earlier, a dangling name
raises `KeyError` here rather than the `RulesetError` the loader's own reference checks
give it. None of them reads the raw TOML, so none needs the loader's own helpers, and
this module imports nothing from `ruleset_loader`. See `DESIGN.md`, "The cross-rule
coherence checks live in `ruleset_coherence.py`", for why these are not part of
`ruleset_loader.py`.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from .errors import RulesetError
from .ruleset import (
    RELATION_CLASSES,
    ROUTED_KINDS,
    CryptoLibrary,
    Distribution,
    PythonModule,
    Rule,
    Ruleset,
    RustCrateEntry,
    match_location,
)

# The four dataclasses `_entries_by_table` below can yield, one per override-bearing
# table -- named once so its return type does not fall back to `object`, which would
# hide a real `no-member` if one of these stopped carrying `basis`/`rule`/`relation`.
_OverrideEntry = Distribution | CryptoLibrary | RustCrateEntry | PythonModule


def check_suppression_can_fire(rules: Iterable[Rule]) -> None:
    """Refuse a `suppressed_by` naming a rule whose hits could never share the
    `Location.path` `engine._apply_suppression` keys on (`None` is a wildcard)."""
    by_id = {rule.id: rule for rule in rules}
    for rule in by_id.values():
        mine = {match_location(match) for match in rule.matches}
        for other in rule.suppressed_by:
            theirs = {match_location(match) for match in by_id[other].matches}
            if None in mine or None in theirs or mine & theirs:
                continue
            raise RulesetError(
                f"rule {rule.id!r}: suppressed_by names {other!r} ({sorted(theirs)}) but this "
                f"rule locates on {sorted(mine)}: never share a location path"
            )


def check_suppression_acyclic(
    rules: Iterable[Rule],
    crates: Mapping[str, RustCrateEntry],
    crate_owner: Mapping[str, str | None],
) -> None:
    """Refuse a `suppressed_by` cycle across rules and `[[rust_crate]]` entries.

    Suppression does not cascade: every hit that fired is read before anything is
    dropped, so a suppressor that is itself suppressed still suppresses. A cycle whose
    members all fire would therefore drop every one of them rather than keeping the
    more specific finding, which loses evidence, so it is refused here rather than
    left to a rule author to notice.

    Nodes are `("rule", id)` and `("crate", name)`; an edge `u -> v` means "u is
    suppressed by v". DFS runs in sorted node and neighbour order so the error is the
    same every time a cyclic ruleset is loaded.
    """
    by_id = {rule.id: rule for rule in rules}
    edges: dict[tuple[str, str], list[tuple[str, str]]] = {}

    def add_edge(u: tuple[str, str], v: tuple[str, str]) -> None:
        edges.setdefault(u, []).append(v)

    for rule_id, rule in by_id.items():
        for other in rule.suppressed_by:
            add_edge(("rule", rule_id), ("rule", other))
    for name, crate in crates.items():
        owner = crate_owner[name]
        if owner is None:
            continue
        if crate.suppressed_by:
            add_edge(("rule", owner), ("crate", name))
        for other_rule in by_id[owner].suppressed_by:
            add_edge(("crate", name), ("rule", other_rule))
        for _, other_crate in crate.suppressed_by:
            add_edge(("crate", name), ("crate", other_crate))

    white, grey, black = 0, 1, 2
    color: dict[tuple[str, str], int] = {}
    all_nodes = sorted({*edges} | {v for neighbours in edges.values() for v in neighbours})

    def visit(node: tuple[str, str], path: list[tuple[str, str]]) -> None:
        state = color.get(node, white)
        if state == black:
            return
        if state == grey:
            cycle = path[path.index(node) :] + [node]
            raise RulesetError(
                "suppressed_by forms a cycle: "
                + " -> ".join(f"{kind} {value!r}" for kind, value in cycle)
            )
        color[node] = grey
        path.append(node)
        for neighbour in sorted(edges.get(node, ())):
            visit(neighbour, path)
        path.pop()
        color[node] = black

    for node in all_nodes:
        if color.get(node, white) == white:
            visit(node, [])


def validate_sbom_component_coverage(rules: Iterable[Rule], source: str) -> None:
    """`linkage._declared_by_sbom` hardcodes the assumption that some `sbom_component`
    rule reports on the same two tables it reads names from, `crypto_library` and
    `rust_crate` -- so the field and the finding never disagree about the same string.
    Checked once over the whole ruleset, as the union of every `sbom_component` rule's
    own `match["tables"]`: covering the two tables across two separate rules is exactly
    as sound as one rule doing both, and this also catches the case a rule-by-rule
    check would miss -- no `sbom_component` rule at all, or every one of them narrowed
    to `crypto_distribution` alone, which leaves `linkage.resolve_linkage` moving
    `<name>_linkage` to `unknown` with no finding anywhere to say why.

    Coverage alone is not enough: a covering rule that also carries `suppressed_by`
    can still lose its finding at scan time while `_declared_by_sbom` moves the field
    regardless, since it reads the metadata directly with no idea a rule was
    suppressed -- the same hole, so such a rule is refused `suppressed_by` outright.
    """
    required = {"crypto_library", "rust_crate"}
    covered: set[str] = set()
    contributors: list[Rule] = []
    for rule in rules:
        for match in rule.matches:
            if match.get("kind") != "sbom_component":
                continue
            tables = set(match.get("tables", []))
            covered.update(tables)
            if tables & required:
                contributors.append(rule)
    missing = required - covered
    if missing:
        raise RulesetError(
            f"{source}: sbom_component rules must together cover tables {sorted(required)}, "
            f"missing {sorted(missing)}"
        )
    for rule in contributors:
        if rule.suppressed_by:
            raise RulesetError(
                f"{source}: rule {rule.id!r} covers sbom_component tables "
                f"{sorted(required)} and cannot carry suppressed_by -- a suppressed "
                f"finding would leave linkage moved with no finding to explain it"
            )


def validate_sbom_suppression_leaves_linkage_explained(ruleset: Ruleset, source: str) -> None:
    """A crate `linkage._declared_by_sbom` counts towards moving a library's
    `<name>_linkage` cannot lose its own finding to `Ruleset.crate_suppressors` (the
    hole `validate_sbom_component_coverage` refuses at rule level): checked for a
    library's own name (the `argon2`/`blake2` folded case) and every crate it lists."""
    default = ruleset.default_rule_for_table("rust_crate", "rust_crate")
    for library in ruleset.libraries.values():
        for name in sorted({library.name, *library.crates}):
            entry = ruleset.rust_crates.get(name)
            suppressors = ruleset.crate_suppressors(name) if entry is not None else ()
            if not suppressors:
                continue
            if entry.suppressed_by:
                names = sorted({other for _, other in entry.suppressed_by})
                relation = f"rust_crate {name!r} names {names} in suppressed_by"
            else:
                owner = entry.rule or (default.id if default is not None else None)
                rule_ids = list(ruleset.rule(owner).suppressed_by) if owner else []
                relation = (
                    f"rule {owner!r} names {rule_ids} in suppressed_by, "
                    f"which owns {list(suppressors)}"
                )
            raise RulesetError(
                f"{source}: rust_crate {name!r} moves {library.name}_linkage from an SBOM "
                f"and cannot be suppressed there -- {relation}"
            )


def _entries_by_table(ruleset: Ruleset) -> Iterable[tuple[str, str, _OverrideEntry]]:
    """Every entry of the four tables `_OVERRIDES` (`ruleset_loader.py`) covers, each
    labelled with the table it came from for an error message. Shared by every check
    below that walks `basis`/`relation` across a rule and every override-bearing
    entry, so the four tables are named in one place rather than once per check."""
    for table, entries in (
        ("crypto_distribution", ruleset.distributions),
        ("crypto_library", ruleset.libraries),
        ("rust_crate", ruleset.rust_crates),
        ("python_module", ruleset.python_modules),
    ):
        for name, entry in entries.items():
            yield table, name, entry


def check_basis_targets_a_live_standard(ruleset: Ruleset, source: str) -> None:
    """Refuse a `basis` naming a standard that is not a live citation.

    Assumes `ruleset.standards` is the fully parsed `[[standard]]` table -- ids unique,
    every `successor` resolved and its chain acyclic (`standards.parse_standards`) --
    and reads only `.status` off it. This is the supersession check `edition`/`status`
    exist to make possible: a NIST revision does not retroactively change what a wheel
    does, but it does mean a `basis` still pointing at the superseded text is citing
    something no longer the standard to check against, `draft` and `planned` are not
    yet in force at all, and `withdrawn` no longer is either.
    """
    live = frozenset({"current", "revision_planned"})
    for rule in ruleset.rules:
        _check_basis_ids(ruleset, rule.basis, live, f"rule {rule.id!r}", source)
    for table, name, entry in _entries_by_table(ruleset):
        _check_basis_ids(ruleset, entry.basis, live, f"{table} {name!r}", source)


def _check_basis_ids(
    ruleset: Ruleset, basis: Iterable[str], live: frozenset[str], where: str, source: str
) -> None:
    for basis_id in basis:
        standard = ruleset.standards.get(basis_id)
        if standard is None:
            raise RulesetError(f"{source}: {where} basis names unknown standard {basis_id!r}")
        if standard.status not in live:
            raise RulesetError(
                f"{source}: {where} basis names {basis_id!r}, whose status is "
                f"{standard.status!r}, not current or revision_planned"
            )


def check_every_standard_is_reachable(ruleset: Ruleset, source: str) -> None:
    """Refuse a declared standard that no `basis` cites and that is nobody's successor.

    Assumes `ruleset.standards` is the fully parsed table and that every `basis`
    already names one of these (`check_basis_targets_a_live_standard`, run first). A
    `withdrawn` standard is kept only as the context a `successor` link points back
    from, and a `planned` one documents what is coming before anything can cite it, so
    those two statuses alone may sit unreferenced; every other standard is dead data
    with nothing pointing at it, which this refuses the same way an unread
    `[[symbol_group]]` is.
    """
    named: set[str] = set()
    for rule in ruleset.rules:
        named.update(rule.basis)
    for _, _, entry in _entries_by_table(ruleset):
        named.update(entry.basis)
    successors = {s.successor for s in ruleset.standards.values() if s.successor is not None}
    reachable = named | successors
    for standard_id, standard in ruleset.standards.items():
        if standard_id in reachable or standard.status in {"withdrawn", "planned"}:
            continue
        raise RulesetError(
            f"{source}: standard {standard_id!r} is named by no basis and is nobody's "
            "successor, and its status does not exempt it"
        )


def _rules_of_kind(ruleset: Ruleset, kind: str) -> Iterable[Rule]:
    """Every rule carrying at least one `[rule.match]` table of matcher kind `kind`."""
    return (rule for rule in ruleset.rules if any(match["kind"] == kind for match in rule.matches))


def check_relation_matches_verdict(ruleset: Ruleset, source: str) -> None:
    """Refuse a (verdict, relation) pair `RELATION_CLASSES` does not allow.

    Checks the exact pair a scan would emit without importing `engine.py`, mirroring
    how `engine._build_finding` resolves a hit's verdict: a rule's own `verdict`/
    `relation` are used directly, and an entry in one of the four override-bearing
    tables falls back to its owning rule's `verdict`/`relation` the same way
    `engine._match_bundled_library`/`_match_rust_crate`/`_match_dist_name`/
    `_match_py_import` resolve the rule an unrouted entry belongs to: the entry's own
    explicit `rule`, else the table's default rule for the one matcher kind
    `ROUTED_KINDS` routes that table through, else no owner at all (`crypto_distribution`
    always names its own rule and has no default -- every entry there names one).
    Only a pair where both sides are resolved and non-`None` is checked: `OPAQUE` has
    no row in `RELATION_CLASSES`, so a verdict of `OPAQUE` paired with any relation is
    refused, and a verdict with no relation (or the reverse) on a rule, or on an entry
    with an owner, never reaches the check -- the loader's own co-location check
    (`ruleset_loader._parse_relation_fields`) already refuses that pairing at parse
    time for anything that carries both fields together.

    An entry with **no** owner at all -- every shipped `[[crypto_library]]` entry
    today: no rule declares itself `bundled_library`'s default, and none names
    `rule=` -- is not covered by that fallback, so it gets its own two rules, neither
    of which is "treat the missing half as absent and skip the pair," because that
    would let the shipped shape's actual scan-time behaviour go unchecked:

    * `relation` with no resolvable `verdict` (not on the entry, and no owner to ask)
      is refused outright. A relation names what would fix a finding against some
      verdict class; one that can never be checked against any class is not a citation
      of anything, in any ruleset, at any point in this project's data being filled in.
    * `verdict` with no `relation` of its own is *not* refused the same way -- but no
      shipped `[[crypto_library]]` entry takes that shape: all 13 carry both fields
      directly, and `tests/test_ruleset_data.py`'s totality tests
      (`test_every_effective_verdict_bearing_entry_carries_a_relation_and_basis` and
      its neither-carries sibling) enforce the pairing over exactly this set of
      entries. What this branch still guards is a ruleset those tests never see: a
      `--ruleset` file loaded at scan time, where a `bundled_library` entry could set
      `verdict` alone. At scan time `_match_bundled_library` lets *any* `bundled_library`
      rule read an unowned entry (`engine._owns` returns its `unowned` argument, `True`,
      when there is no owner to compare against), each supplying its own `relation`
      fallback for whichever object it matches, so the entry's `verdict` is checked
      here against every such rule's own `relation`, not skipped for lack of one
      fixed rule to ask.
    """
    for rule in ruleset.rules:
        _check_relation_against_verdict(rule.verdict, rule.relation, f"rule {rule.id!r}", source)
    for table, name, entry in _entries_by_table(ruleset):
        default = None
        if table != "crypto_distribution":
            (kind,) = ROUTED_KINDS[table]
            default = ruleset.default_rule_for_table(table, kind)
        owner_id = entry.rule or (default.id if default is not None else None)
        owner = ruleset.rule(owner_id) if owner_id is not None else None
        verdict = entry.verdict if entry.verdict is not None else (owner and owner.verdict)
        relation = entry.relation if entry.relation is not None else (owner and owner.relation)
        _check_relation_against_verdict(verdict, relation, f"{table} {name!r}", source)
        if owner is not None:
            continue
        if relation is not None and verdict is None:
            raise RulesetError(
                f"{source}: {table} {name!r} states relation {relation!r} with no "
                "verdict anywhere to check it against"
            )
        if verdict is not None and relation is None:
            (kind,) = ROUTED_KINDS[table]
            for candidate in _rules_of_kind(ruleset, kind):
                if candidate.relation is not None:
                    where = f"{table} {name!r} via rule {candidate.id!r}"
                    _check_relation_against_verdict(verdict, candidate.relation, where, source)


def _check_relation_against_verdict(
    verdict: str | None, relation: str | None, where: str, source: str
) -> None:
    if verdict is None or relation is None:
        return
    classes = RELATION_CLASSES[relation]
    if verdict not in classes:
        raise RulesetError(
            f"{source}: {where} pairs verdict {verdict!r} with relation {relation!r}, "
            f"which only fits {sorted(classes)}"
        )
