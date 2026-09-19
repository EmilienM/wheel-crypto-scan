"""Resolves how each named crypto library is actually linked: system, bundled or static.

This is the question the tool exists to answer. A wheel that resolves `libcrypto.so.3`
from the host inherits the host's FIPS provider and its crypto policy. A wheel that
ships or statically links its own copy does not, and nothing the host is configured to
do will change that.

Three ways a wheel can carry its own OpenSSL, and all three have to be caught:

  - a library file copied into `*.libs/` or `.dylibs/` by auditwheel or delocate;
  - a dependency on a hash-renamed library such as `libcrypto-3a1f2b4c.so.3`, which is
    what those tools rewrite the dependency to;
  - OpenSSL compiled straight into the extension, with no library file and no
    dependency at all. `cryptography` 42 and later does exactly this, so a check that
    only looked for vendor directories would call that wheel system-linked and be
    wrong in the worst possible direction.
"""

from __future__ import annotations

from .evidence import BINDING_DEFINED, BINDING_IMPORTED, STAGE_BINARY, BinaryEvidence, Evidence
from .ruleset import Conventions, CryptoLibrary, Ruleset

LINKAGE_SYSTEM = "system"
LINKAGE_BUNDLED = "bundled"
LINKAGE_STATIC = "static"
LINKAGE_MIXED = "mixed"
LINKAGE_NONE = "none"
LINKAGE_UNKNOWN = "unknown"

# Postures that are a real observation rather than an absence of one. Only these
# combine into "mixed"; "unknown" is a weaker signal and never outvotes them.
_DEFINITE = (LINKAGE_SYSTEM, LINKAGE_BUNDLED, LINKAGE_STATIC)


def resolve_linkage(ruleset: Ruleset, evidence: Evidence) -> dict[str, str]:
    """Map each crypto library with evidence in this wheel to its linkage posture."""
    unanswered = _left_unanswered(ruleset, evidence)
    result: dict[str, str] = {}
    for name in sorted(ruleset.libraries):
        library = ruleset.libraries[name]
        postures = {
            _binary_posture(binary, library, ruleset.conventions) for binary in evidence.binaries
        }
        value = _aggregate(postures, unanswered and library.always_report)
        if value != LINKAGE_NONE or library.always_report:
            result[name] = value
    return result


def _aggregate(postures: set[str], unanswered: bool) -> str:
    """Reduce per-binary postures to one answer for the whole wheel.

    `unanswered` is the wheel-wide signal that some object did not answer, and it is
    only consulted when nothing in the wheel answered definitely: one unreadable
    object must not erase what the readable ones said. It reaches here already gated
    on `always_report`, so an object we could not read makes the answer `unknown` for
    the libraries reported whatever the evidence -- where a false `none` is what does
    the damage -- and does not list every library in the ruleset as unknown.
    """
    definite = sorted(posture for posture in postures if posture in _DEFINITE)
    if len(definite) == 1:
        return definite[0]
    if len(definite) > 1:
        return LINKAGE_MIXED
    if LINKAGE_UNKNOWN in postures or unanswered:
        return LINKAGE_UNKNOWN
    return LINKAGE_NONE


def _binary_posture(
    binary: BinaryEvidence, library: CryptoLibrary, conventions: Conventions
) -> str:
    sonames = frozenset(library.sonames)

    if binary.vendored_path and conventions.own_base(binary.soname, binary.path) in sonames:
        return LINKAGE_BUNDLED

    system = False
    for needed in binary.needed:
        info = conventions.normalise_soname(needed)
        if info.base not in sonames:
            continue
        if info.mangled:
            # auditwheel, delocate and delvewheel only rename what they vendored.
            return LINKAGE_BUNDLED
        system = True
    if system:
        return LINKAGE_SYSTEM

    defined = _has_symbol(binary, library.symbol_group, BINDING_DEFINED)
    if defined or _has_string(binary, library.string_group):
        return LINKAGE_STATIC

    if _has_symbol(binary, library.symbol_group, BINDING_IMPORTED):
        # It calls a library it neither ships nor declares. Whatever provides those
        # symbols at runtime is outside this wheel and outside our sight.
        return LINKAGE_UNKNOWN

    if binary.is_opaque:
        return LINKAGE_UNKNOWN
    return LINKAGE_NONE


def _has_symbol(binary: BinaryEvidence, group: str | None, binding: str) -> bool:
    if group is None:
        return False
    return any(
        symbol.group == group and symbol.binding == binding for symbol in binary.matched_symbols
    )


def _has_string(binary: BinaryEvidence, group: str | None) -> bool:
    if group is None:
        return False
    return any(match.group == group for match in binary.matched_strings)


def _left_unanswered(ruleset: Ruleset, evidence: Evidence) -> bool:
    """Did any object in this wheel fail to answer the question linkage asks?

    Three ways, and the third was missing for a long time. An object that yielded
    nothing at all; a binary that never produced a record, which shows up as a
    binary-stage error; and an object a reader read and explicitly marked as not read
    in full.

    That third one is the everyday case rather than the exotic one -- a stripped macOS
    extension records `macho_symtab_incomplete` and no error -- and without it the
    record said both "we could not read this object's symbols" and "there is no
    OpenSSL in it", which is a claim the first half says we cannot make. `is_opaque`
    does not rescue it: `needed` is non-empty for every loadable dylib and every
    `.pyd`.

    Which causes count is policy and is read off the ruleset, because most of
    `partial_reasons` is a failure and some of it is a linker convention that leaves
    every field linkage reads intact. Counting the tuple wholesale would turn every
    ordinal import into `openssl_linkage: unknown`, which is the noise #32 removed.
    """
    for binary in evidence.binaries:
        if binary.is_opaque:
            return True
        if not binary.partial_analysis:
            continue
        # A partial read naming no cause is the shape `engine._match_partial_binary`
        # singles out as the most serious of all: no reader produces it, so the
        # evidence was built by hand, and an unexplained partial read is the last
        # thing to quietly downgrade. The two consumers of one field must not read it
        # in opposite directions.
        if not binary.partial_reasons or ruleset.linkage_policy.costs_an_answer(
            binary.partial_reasons
        ):
            return True
    return any(error.stage == STAGE_BINARY for error in evidence.errors)
