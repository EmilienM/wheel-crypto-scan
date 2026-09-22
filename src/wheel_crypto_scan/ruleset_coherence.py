"""Checks over the parsed rules as a whole: relations between rules that no single
rule's own parse can see.

Every check here refuses a ruleset whose rules contradict each other: a `suppressed_by`
that can never fire or closes a cycle, and an SBOM relation that would leave a
`<name>_linkage` moved with no finding to explain it. Each reads `Rule`/`Ruleset`
objects `ruleset_loader.parse_ruleset` has already built, shape-checked and
reference-resolved, and assumes that last part: every `suppressed_by` and every crate
owner names a rule that exists. Called any earlier, a dangling name raises `KeyError`
here rather than the `RulesetError` the loader's own reference checks give it. None of
them reads the raw TOML, so none needs the loader's own helpers, and this module
imports nothing from `ruleset_loader`. See `DESIGN.md`, "The cross-rule coherence
checks live in `ruleset_coherence.py`", for why these are not part of
`ruleset_loader.py`.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from .errors import RulesetError
from .ruleset import Rule, Ruleset, RustCrateEntry, match_location


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
