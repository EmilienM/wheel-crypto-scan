"""`Standard`, the NIST/FIPS publication a `basis` entry points at, and the
`[[standard]]` table's own parser.

The model and its parser live together for the reason `Conventions`/`parse_conventions`
do (see `conventions.py`): nothing else reads either without the other, and
`ruleset_loader.parse_ruleset` needs `Standard`/`parse_standards` from here to build a
`Ruleset`, so importing `ruleset_loader` from here would make the two modules import
each other. It is also where the line budget forced the split: `ruleset_loader.py` was
already 935 of pylint's 1000-line module cap before this table existed, with no room to
add a full table's parsing and cross-checks inline.

The checks here are the ones internal to the `[[standard]]` table alone: shape, the
closed `status` vocabulary, unique ids, and that `successor` names a real entry and
closes no cycle. Whether a `basis` elsewhere in the ruleset points at a standard whose
status makes it a live citation, and whether every declared standard is reachable, are
cross-table questions and live in `ruleset_coherence.py` instead, the same split that
module draws for `suppressed_by` and SBOM coverage.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from .errors import RulesetError

# `revision_planned` and `draft`/`planned` are both "not yet the citation to make", but
# for different reasons: a `revision_planned` standard is still the current one, on a
# published schedule to be replaced, so `basis` may still name it (see
# `ruleset_coherence.check_basis_targets_a_live_standard`); `draft` and `planned` are
# not yet in force at all, and `withdrawn` no longer is.
STANDARD_STATUSES = frozenset({"current", "revision_planned", "draft", "planned", "withdrawn"})

_STANDARD_KEYS = frozenset(
    {"id", "title", "edition", "status", "why", "successor", "sunset", "url"}
)


def _require(mapping: Mapping[str, Any], key: str, where: str) -> Any:
    try:
        return mapping[key]
    except KeyError:
        raise RulesetError(f"{where}: missing required field '{key}'") from None


def _refuse_unknown_keys(data: Mapping[str, Any], allowed: Iterable[str], where: str) -> None:
    unknown_keys = sorted(set(data) - set(allowed))
    if unknown_keys:
        raise RulesetError(f"{where}: unknown keys {unknown_keys}")


def _check(value: Any, allowed: Iterable[str], label: str, where: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise RulesetError(f"{where}: unknown {label} {value!r}")
    return str(value)


def _check_optional_string(value: Any, label: str, where: str) -> str | None:
    if value is not None and not isinstance(value, str):
        raise RulesetError(f"{where}: {label} must be a string")
    return value


@dataclass(frozen=True, slots=True)
class Standard:
    """One NIST/FIPS publication a rule or an entry's `basis` can point at.

    `edition` and `status` are what make `basis` a checkable citation rather than a
    bare name: a `basis` naming this standard is refused at load time unless `status`
    is `current` or `revision_planned` (`ruleset_coherence.
    check_basis_targets_a_live_standard`), which is the whole reason this table
    carries them instead of `basis` staying a plain string. `successor` links a
    superseded standard to the one that replaced it, so a `withdrawn` entry stays in
    the table as the context a citation moved from, rather than disappearing and
    taking that link with it.
    """

    id: str
    title: str
    edition: str
    status: str
    why: str
    successor: str | None = None
    sunset: str | None = None
    url: str | None = None


def parse_standards(data: Iterable[Any]) -> Mapping[str, Standard]:
    """Parse `[[standard]]` into id-keyed `Standard`s, refusing a malformed table.

    Takes the raw list of TOML tables, the same shape `data.get("standard", [])` gives
    `ruleset_loader.parse_ruleset`, not the whole ruleset mapping: nothing here reads
    any other table. Whether a `basis` elsewhere names one of these, and whether every
    one of these is named by some `basis` or `successor`, are cross-table questions
    `ruleset_coherence.check_basis_targets_a_live_standard`/
    `check_every_standard_is_reachable` answer once the whole ruleset is built, not
    this function.
    """
    standards: dict[str, Standard] = {}
    for entry in data:
        if not isinstance(entry, Mapping):
            raise RulesetError("[[standard]]: entries must be tables")
        raw_id = _require(entry, "id", "[[standard]]")
        if not isinstance(raw_id, str):
            raise RulesetError("[[standard]]: id must be a string")
        where = f"standard {raw_id!r}"
        if raw_id in standards:
            raise RulesetError(f"{where}: duplicate standard id")
        _refuse_unknown_keys(entry, _STANDARD_KEYS, where)
        status = _check(_require(entry, "status", where), STANDARD_STATUSES, "status", where)
        standards[raw_id] = Standard(
            id=raw_id,
            title=str(_require(entry, "title", where)),
            edition=str(_require(entry, "edition", where)),
            status=status,
            why=str(_require(entry, "why", where)),
            successor=_check_optional_string(entry.get("successor"), "successor", where),
            sunset=_check_optional_string(entry.get("sunset"), "sunset", where),
            url=_check_optional_string(entry.get("url"), "url", where),
        )

    for standard in standards.values():
        if standard.successor is not None and standard.successor not in standards:
            raise RulesetError(
                f"standard {standard.id!r}: successor names unknown standard {standard.successor!r}"
            )
    _check_successor_chain_acyclic(standards)

    return MappingProxyType(standards)


def _check_successor_chain_acyclic(standards: Mapping[str, Standard]) -> None:
    """Refuse a `successor` chain that loops back on itself.

    Internal to this table alone -- unlike `suppressed_by`
    (`ruleset_coherence.check_suppression_acyclic`), which crosses rules and
    `[[rust_crate]]` entries, a `successor` chain never leaves `[[standard]]`, so the
    natural place to walk it is here, right after the table that could form one is
    built. Each standard names at most one successor, so the walk below is the same
    white/grey/black DFS `check_suppression_acyclic` runs over a richer graph, in
    sorted node order so a cyclic ruleset fails the same way every time it is loaded.
    """
    white, grey, black = 0, 1, 2
    color: dict[str, int] = {}

    def visit(node: str, path: list[str]) -> None:
        state = color.get(node, white)
        if state == black:
            return
        if state == grey:
            cycle = path[path.index(node) :] + [node]
            raise RulesetError("successor forms a cycle: " + " -> ".join(cycle))
        color[node] = grey
        path.append(node)
        successor = standards[node].successor
        if successor is not None:
            visit(successor, path)
        path.pop()
        color[node] = black

    for start in sorted(standards):
        if color.get(start, white) == white:
            visit(start, [])
