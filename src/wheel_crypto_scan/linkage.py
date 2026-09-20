"""Resolves how each named crypto library is actually linked: system, bundled or static.

This is the question the tool exists to answer. A wheel that resolves `libcrypto.so.3`
from the host inherits the host's FIPS provider and its crypto policy. A wheel that
ships or statically links its own copy does not, and nothing the host is configured to
do will change that.

Three ways a wheel can carry its own OpenSSL, and all three have to be caught:

  - a library file copied into `*.libs/` or `.dylibs/` by auditwheel or delocate;
  - a dependency on a hash-renamed library such as `libcrypto-3a1f2b4c.so.3`, which is
    what auditwheel and delvewheel rewrite the dependency to;
  - OpenSSL compiled straight into the extension, with no library file and no
    dependency at all. `cryptography` 42 and later does exactly this, so a check that
    only looked for vendor directories would call that wheel system-linked and be
    wrong in the worst possible direction.

A fourth spelling of the first case matters just as much: delocate, the macOS
equivalent of auditwheel, copies a dependency into `.dylibs/` and rewrites the load
command to point at it *without* renaming the file. A `needed` entry can therefore name
a plain, unmangled `libcrypto.3.dylib` and still resolve entirely inside the wheel, so
`mangled` cannot be the only test for "does this `needed` entry name a copy the wheel
ships". See #57.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping

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


def member_stem_counts(conventions: Conventions, evidence: Evidence) -> Mapping[str, int]:
    """How many objects in this wheel answer to each file identity.

    A count, not a set, because a `needed` entry can share its own declaring object's
    `Conventions.raw_stem` without that meaning anything -- an object named
    `libcrypto.so` that itself declares an absolute, genuinely-system
    `/usr/lib64/libcrypto.so.3` shares a stem with its own dependency purely by
    coincidence of file naming, and a `needed` entry can never legitimately resolve
    to the object declaring it. `_resolves_within_wheel` uses the count to discount an
    object's own contribution to its own answer while still honouring a second,
    genuinely different object that happens to share the same stem. See #57.

    The object's `path` is set by `layers.binaries.scan_binaries` for every member it
    attempts to read, whether or not the read succeeded, so a vendored copy whose
    internal structure could not be parsed still counts.
    """
    return Counter(conventions.raw_stem(binary.soname, binary.path) for binary in evidence.binaries)


def _resolves_within_wheel(own_stem: str, needed_stem: str, counts: Mapping[str, int]) -> bool:
    """True when some object OTHER than the one declaring `needed` answers to its stem.

    An object's own stem never counts toward its own `needed` entries (see
    `member_stem_counts`), so when the two coincide, confirmation requires a second
    contributor; when they differ, the declaring object contributes nothing to that
    stem in the first place and any count at all is a different, genuine object.
    """
    count = counts.get(needed_stem, 0)
    return count > 1 if needed_stem == own_stem else count > 0


def wheel_incompletely_read(evidence: Evidence) -> bool:
    """True when some member of this wheel never became a `BinaryEvidence` at all:
    skipped by an archive-level limit (`artifacts.skipped`), one that raised on open
    or failed its CRC (`errors` at `STAGE_BINARY`, from `layers.binaries.scan_binaries`),
    or a symlink (`artifacts.symlinks`) -- `layers.binaries.is_binary_member` returns
    `False` for every symlink, so a vendored library shipped as one is never read as a
    binary at all, and records neither a `skipped` entry nor a `STAGE_BINARY` error.
    Whichever it is, `member_stem_counts` cannot be a complete answer: the object a
    vendor-shaped path is pointing at might be exactly the one that never got read.
    See #57.
    """
    return bool(
        evidence.artifacts.skipped
        or evidence.artifacts.symlinks
        or any(error.stage == STAGE_BINARY for error in evidence.errors)
    )


def _looks_vendored(needed: str, binary: BinaryEvidence, conventions: Conventions) -> bool:
    """True when `needed`, or an `RPATH`/`RUNPATH`/`LC_RPATH` entry joined to it,
    embeds a vendor-directory path component -- delocate's `@loader_path/.dylibs/...`
    convention, `@rpath/name` plus a vendor-shaped `LC_RPATH`, or a bare ELF
    `DT_NEEDED` name alongside a vendor-shaped `RUNPATH`. Joining the *whole* `needed`
    string (rather than stripping a leading `@rpath/` first) still finds a vendor
    directory anywhere in the combined path, so one check covers `@rpath` and a bare
    name alike.

    A path shaped like vendoring is a hint about where to look, never confirmation by
    itself, and the caller only consults this when the wheel was not read in full
    (`wheel_incompletely_read`): when every member was read, `member_stem_counts`
    already speaks for the whole wheel, and a vendor-shaped path naming nothing there
    is genuine `system`, not `unknown`. See #57.
    """
    if conventions.is_vendor_path(needed):
        return True
    return any(
        conventions.is_vendor_path(f"{rpath.rstrip('/')}/{needed}")
        for rpath in (*binary.rpath, *binary.runpath)
    )


def needed_posture(
    info_original: str,
    mangled: bool,
    own_stem: str,
    binary: BinaryEvidence,
    conventions: Conventions,
    counts: Mapping[str, int],
    incomplete: bool,
) -> str:
    """Read one `needed` entry in isolation, off the same evidence `_binary_posture`
    aggregates per object: `LINKAGE_BUNDLED` when it is mangled or resolves to an
    object this wheel itself ships (`Conventions.raw_stem`, matched against
    `member_stem_counts` through `_resolves_within_wheel` -- delocate's convention,
    which never mangles, needs the second half); `LINKAGE_UNKNOWN` when the wheel was
    not read in full and the path looks vendored (`_looks_vendored`) but names
    nothing confirmed, because a path shaped like vendoring is not proof by itself
    and an incompletely-read wheel cannot rule it out either (#57); `LINKAGE_SYSTEM`
    otherwise -- including a vendor-shaped path naming nothing, when the wheel was
    read in full and can therefore rule it out.

    Shared with `engine._match_dt_needed`, which reports this per `needed` entry
    rather than aggregating it, so the record and the finding cannot disagree about
    the same string.
    """
    needed_stem = conventions.raw_stem(None, info_original)
    if mangled or _resolves_within_wheel(own_stem, needed_stem, counts):
        return LINKAGE_BUNDLED
    if incomplete and _looks_vendored(info_original, binary, conventions):
        return LINKAGE_UNKNOWN
    return LINKAGE_SYSTEM


def resolve_linkage(ruleset: Ruleset, evidence: Evidence) -> dict[str, str]:
    """Map each crypto library with evidence in this wheel to its linkage posture."""
    unanswered = _left_unanswered(ruleset, evidence)
    counts = member_stem_counts(ruleset.conventions, evidence)
    incomplete = wheel_incompletely_read(evidence)
    result: dict[str, str] = {}
    for name in sorted(ruleset.libraries):
        library = ruleset.libraries[name]
        postures = {
            _binary_posture(binary, library, ruleset.conventions, counts, incomplete)
            for binary in evidence.binaries
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

    `mixed` can now arrive already resolved for a single object (#60: `needed`
    matched the system library and the object also defines or banners its own
    copy), not only as this function's own combination of two definite postures
    from different objects. `mixed` has no finer split than that in the
    vocabulary, so one object already reading `mixed` makes the wheel `mixed`
    outright, whatever any other object says.
    """
    if LINKAGE_MIXED in postures:
        return LINKAGE_MIXED
    definite = sorted(posture for posture in postures if posture in _DEFINITE)
    if len(definite) == 1:
        return definite[0]
    if len(definite) > 1:
        return LINKAGE_MIXED
    if LINKAGE_UNKNOWN in postures or unanswered:
        return LINKAGE_UNKNOWN
    return LINKAGE_NONE


def _binary_posture(
    binary: BinaryEvidence,
    library: CryptoLibrary,
    conventions: Conventions,
    counts: Mapping[str, int],
    incomplete: bool,
) -> str:
    sonames = frozenset(library.sonames)

    if binary.vendored_path and conventions.own_base(binary.soname, binary.path) in sonames:
        return LINKAGE_BUNDLED

    own_stem = conventions.raw_stem(binary.soname, binary.path)
    system = False
    uncertain = False
    for needed in binary.needed:
        info = conventions.normalise_soname(needed)
        if info.base not in sonames:
            continue
        posture = needed_posture(
            info.original, info.mangled, own_stem, binary, conventions, counts, incomplete
        )
        if posture == LINKAGE_BUNDLED:
            # auditwheel and delvewheel rename what they vendor; delocate does not,
            # so a plain name that still resolves inside the wheel counts too. #57.
            return LINKAGE_BUNDLED
        if posture == LINKAGE_UNKNOWN:
            # Looks vendored (a `@loader_path`/`@rpath`/vendor-shaped RUNPATH), but
            # nothing in the wheel confirms it names a file that is actually there.
            # Not proof of "system" either -- see the reproduction in #57.
            uncertain = True
            continue
        system = True

    defined = _has_symbol(binary, library.symbol_group, BINDING_DEFINED)
    static = defined or _has_string(binary, library.string_group)
    if system and static:
        # A real `needed` match to the system library and a real definition or
        # banner inside this same object are both true at once: one names a
        # dependency the object declares, the other names code the object
        # compiled in, and neither is weaker evidence than the other. Returning
        # early on `system` alone used to let this defined/banner check go
        # unreached, so the record paired `DERIVED_SYSTEM_OPENSSL_ONLY` with
        # `BIN_OPENSSL_SYMBOLS_DEFINED` -- a contradiction in the clean
        # direction. See #60.
        return LINKAGE_MIXED
    if system:
        return LINKAGE_SYSTEM
    if uncertain:
        return LINKAGE_UNKNOWN

    if static:
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
