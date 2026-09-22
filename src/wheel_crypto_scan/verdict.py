"""Turns findings into a verdict class, its reasons and its conditions.

Two rules govern this module. It never emits a passing class: the taxonomy has no
"compliant" and no "compatible", and cannot acquire either, because absence of evidence is
not evidence of absence -- nothing the tool reads rules out crypto it did not see -- and
FIPS compliance, a human's judgement about a deployment, is out of scope regardless. And it
never throws away a class: a wheel that both bundles OpenSSL and calls `hashlib.md5()`
reports one headline class and keeps the rest in `classes`, so a consumer filtering on a
single field is not silently misled.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from .findings import Finding
from .ruleset import Ruleset

# The loader requires this class to close a ruleset's `[verdict] precedence`, and
# refuses it as the `verdict` of any rule or table entry: it is the class a wheel gets
# when no finding assigns one, not a class a finding can assign.
NO_CRYPTO_DETECTED = "NO_CRYPTO_DETECTED"


@dataclass(frozen=True, slots=True)
class Verdict:
    """The wheel's classification and everything needed to argue with it."""

    headline: str
    classes: tuple[str, ...]
    rule_ids: tuple[str, ...]
    reasons: tuple[str, ...]
    needs_human_review: bool
    conditions: Mapping[str, str] = field(default_factory=dict)
    # Every relation a contributing finding cited, sorted: relations have no
    # precedence order the way verdict classes do.
    relations: tuple[str, ...] = ()


def classify(ruleset: Ruleset, findings: Sequence[Finding], linkage: Mapping[str, str]) -> Verdict:
    """Resolve the findings into one class, keeping every class that fired."""
    contributing = [finding for finding in findings if finding.verdict is not None]
    fired = {finding.verdict for finding in contributing}
    classes = tuple(name for name in ruleset.precedence if name in fired)
    if not classes:
        # Absence of evidence, not evidence of absence. The class name says so.
        classes = (NO_CRYPTO_DETECTED,)

    reasons = sorted({f"{f.rule_id}: {_subject_of(f)}" for f in contributing})
    rule_ids = sorted({finding.rule_id for finding in contributing})
    relations = tuple(sorted({f.relation for f in contributing if f.relation}))

    return Verdict(
        headline=classes[0],
        classes=classes,
        rule_ids=tuple(rule_ids),
        reasons=tuple(reasons),
        needs_human_review=(
            classes[0] != NO_CRYPTO_DETECTED
            or any(finding.needs_human_review for finding in findings)
        ),
        conditions={f"{name}_linkage": value for name, value in sorted(linkage.items())},
        relations=relations,
    )


def _subject_of(finding: Finding) -> str:
    if finding.subject:
        return finding.subject
    if finding.locations:
        return finding.locations[0].path
    return finding.rule_id
