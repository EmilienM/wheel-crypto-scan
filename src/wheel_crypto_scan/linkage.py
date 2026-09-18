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
    opaque = _has_opaque_binary(evidence)
    result: dict[str, str] = {}
    for name in sorted(ruleset.libraries):
        library = ruleset.libraries[name]
        postures = {
            _binary_posture(binary, library, ruleset.conventions) for binary in evidence.binaries
        }
        value = _aggregate(postures, opaque and library.always_report)
        if value != LINKAGE_NONE or library.always_report:
            result[name] = value
    return result


def _aggregate(postures: set[str], opaque: bool) -> str:
    """Reduce per-binary postures to one answer for the whole wheel."""
    definite = sorted(posture for posture in postures if posture in _DEFINITE)
    if len(definite) == 1:
        return definite[0]
    if len(definite) > 1:
        return LINKAGE_MIXED
    if LINKAGE_UNKNOWN in postures or opaque:
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
            # auditwheel and delocate only rename libraries they vendored.
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


def _has_opaque_binary(evidence: Evidence) -> bool:
    if any(binary.is_opaque for binary in evidence.binaries):
        return True
    return any(error.stage == STAGE_BINARY for error in evidence.errors)
