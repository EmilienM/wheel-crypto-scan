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

A structural rule underlies all of the above: an absolute `needed` path is never
resolved relative to anything -- not `RPATH`/`RUNPATH`, not a vendor directory, not
the wheel at all -- so it can never be evidence of vendoring, whatever else in the
wheel happens to share its basename. See #80.
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
    `libcrypto.so` that itself declares a same-named, genuinely-system dependency
    shares a stem with its own dependency purely by coincidence of file naming, and a
    `needed` entry can never legitimately resolve to the object declaring it.
    `_resolves_within_wheel` uses the count to discount an object's own contribution
    to its own answer while still honouring a second, genuinely different object that
    happens to share the same stem. See #57. (#57's own reproduction used an absolute
    dependency, `/usr/lib64/libcrypto.so.3`; #80 later gave every absolute `needed`
    entry its own, earlier short-circuit in `needed_posture` that never reaches this
    function at all, so the discount below is now exercised by a *relative*
    same-named dependency instead -- the coincidence is exactly as possible there,
    just reached through the ordinary, non-absolute path.)

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

    Assumes `needed` is a name a real loader could plausibly resolve inside the wheel
    at all -- `needed_posture` only calls this for a relative entry, never an absolute
    path, which no loader resolves this way regardless of what shares its basename.
    See #80.
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

    Also assumes `needed` is a relative entry: `needed_posture` never calls this for
    an absolute path, because an absolute path is never resolved relative to a loading
    object's `RPATH`/`RUNPATH` or its own directory, so a vendor-glob-shaped component
    inside one -- whether embedded directly or produced by the join below -- names
    nothing a real loader would ever look at. See #80.
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

    An absolute `needed` entry (an ELF `DT_NEEDED` or Mach-O `LC_LOAD_DYLIB` path
    starting with `/`; PE has no such shape) is `LINKAGE_SYSTEM` outright, ahead of
    and instead of consulting `_resolves_within_wheel` or `_looks_vendored`: no real
    dynamic loader resolves an absolute path via `$ORIGIN`/`@loader_path`/`@rpath`/
    `RPATH`/`RUNPATH` -- it is used literally -- so a same-basename object elsewhere
    in the wheel, or a vendor-shaped `RPATH`/`RUNPATH` alongside it, is meaningless
    for it. This also covers `_looks_vendored`'s *other* branch,
    `conventions.is_vendor_path(needed)` on the string by itself: that branch exists
    to catch delocate's own convention, `@loader_path/.dylibs/...`, where the
    vendor-directory component is meaningful only because the path gets resolved
    relative to the loading object in the first place. An absolute path is never
    resolved relative to anything, so auditwheel and delocate never emit one for a
    copy they vendor -- both always rewrite to a relative form for exactly that
    reason -- and a vendor-glob-shaped component inside an absolute path is therefore
    always a coincidence or a leftover build-time artifact, never a real vendoring
    reference, whether it is read via the join or read off the string on its own.
    `mangled` is checked first, ahead of the absolute-path return, and is unaffected
    by absoluteness: a hash-renamed basename is strong independent evidence on its
    own, and mangled detection has nothing to do with whether the path was absolute.
    #80.

    This closes the residual only for a genuinely absolute path (`startswith("/")`).
    A relative-looking entry that still cannot resolve inside the wheel by any real
    search order -- a `../`-relative path, or a Mach-O `@executable_path/`-anchored
    one, which resolves against the process's own binary rather than the loading
    object -- still reaches `_resolves_within_wheel` and `_looks_vendored` exactly as
    before #80 and can still read a spurious `bundled` or `unknown` from an unrelated
    basename collision. Narrower than the argument above technically allows;
    `DECISIONS.md` records it as a residual left open rather than assumed closed.

    Shared with `engine._match_dt_needed`, which reports this per `needed` entry
    rather than aggregating it, so the record and the finding cannot disagree about
    the same string.
    """
    if mangled:
        return LINKAGE_BUNDLED
    if info_original.startswith("/"):
        return LINKAGE_SYSTEM
    needed_stem = conventions.raw_stem(None, info_original)
    if _resolves_within_wheel(own_stem, needed_stem, counts):
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

    `mixed` can now arrive already resolved for a single object -- #60: a `needed`
    entry matched the system library and the object also defines or banners its own
    copy; #88: a `needed` entry resolved inside the wheel (`bundled`) alongside a
    different `needed` entry matching the system library, or alongside a
    definition/banner, on that same object -- not only as this function's own
    combination of two definite postures from different objects. `mixed` has no
    finer split than that in the vocabulary, so one object already reading `mixed`
    makes the wheel `mixed` outright, whatever any other object says.
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
    bundled = False
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
            #
            # This used to return immediately, before the rest of this loop -- a
            # second `needed` entry that resolves to `system`, say -- or the
            # defined/static check below it ever ran, so a merged fat-slice object
            # whose slices disagreed (one slice bundled, another system or static)
            # read `bundled` outright instead of `mixed`, unlike the same evidence
            # split across two separate objects. Set the flag and keep looping
            # instead: `bundled` is a `_DEFINITE` posture exactly like `system`, so
            # it belongs in the same disagreement check below, not in a return of
            # its own. See #88.
            bundled = True
            continue
        if posture == LINKAGE_UNKNOWN:
            # Looks vendored (a `@loader_path`/`@rpath`/vendor-shaped RUNPATH), but
            # nothing in the wheel confirms it names a file that is actually there.
            # Not proof of "system" either -- see the reproduction in #57.
            uncertain = True
            continue
        system = True

    defined = _has_symbol(binary, library.symbol_group, BINDING_DEFINED)
    static = defined or _has_string(binary, library.string_group)
    if sum((system, bundled, static)) > 1:
        # Two or more of `system`, `bundled` and `static` are true on this one
        # object at once. Each is a `_DEFINITE` posture (see the tuple above) drawn
        # from its own piece of evidence -- a `needed` entry resolving to the host
        # library, a different `needed` entry resolving inside the wheel, or a
        # defined symbol/banner -- and none of the three is weaker evidence than
        # the others, so none wins outright over the rest: this object's own
        # evidence already disagrees with itself the same way two different
        # objects' postures disagree in `_aggregate` (`len(definite) > 1: return
        # LINKAGE_MIXED`), so it reads `mixed` here too, before `_aggregate` ever
        # runs. #60 added this check for `system`-and-`static`; #88 widens it to a
        # three-way count that also catches `bundled`-and-`system` and
        # `bundled`-and-`static`, closing the gap left by `bundled`'s old early
        # return in the loop above.
        return LINKAGE_MIXED
    if system:
        return LINKAGE_SYSTEM
    if bundled:
        # No other `_DEFINITE` posture was also true above, so this is the
        # ordinary bundled case: the same answer the loop's old early return gave
        # for this shape, reached here instead only after confirming it did not
        # need to combine with a `system` or `static` signal found elsewhere on
        # this same object. #88.
        return LINKAGE_BUNDLED
    if uncertain and static:
        # A `needed` entry whose path/rpath shape looks vendored but that this
        # incompletely-read wheel cannot confirm either way, and a real definition
        # or banner in the same object, are both true at once. Returning `unknown`
        # here -- as this function did before #87 -- discarded the confirmed static
        # evidence in favour of the unconfirmed one, the opposite of what
        # "unreadable or uncertain must never read as NO_CRYPTO_DETECTED" asks for:
        # a real fact should never be the one that goes missing.
        #
        # Reached only when neither `system` nor `bundled` is true. That is not the
        # same shape as the two `_DEFINITE`-count branches above -- `system` and
        # `bundled` do NOT win outright over `static` there, they combine into
        # `mixed` -- so this branch's ordering answers a different question:
        # `uncertain` is exactly `needed_posture`'s `LINKAGE_UNKNOWN`, not one of
        # the `_DEFINITE` postures a few lines up, and `_aggregate` already treats
        # a non-definite posture as one that never outvotes a definite one already
        # present (`len(definite) == 1: return definite[0]`, discarding
        # `LINKAGE_UNKNOWN` outright, whatever else is true). This branch applies
        # that same rule within one object -- but only for `system` and `bundled`,
        # which, like `uncertain` itself, are read off `binary.needed` in the loop
        # above: a confirmed entry from that same loop already returns two branches
        # up without ever consulting an unconfirmed different entry from it.
        # `static` is a different kind of evidence entirely (`matched_symbols`/
        # `matched_strings`, not `needed`), so `uncertain` combines with it here
        # instead of being discarded the way it is against `system` or `bundled`.
        #
        # This branch's own position, below `if system:` and `if bundled:`, is not
        # what makes a confirmed `system` or `bundled` win outright over
        # `uncertain` -- that already happens a few lines up, unconditionally,
        # whether or not this branch exists at all (moving this branch above the
        # `_DEFINITE`-count check changes nothing the test suite can observe). It
        # sits here because `uncertain` and `static` are the only two facts left
        # for this branch to combine once `system` and `bundled` have both already
        # been ruled out. See #87, extended by #88 to also rule out `bundled`
        # ahead of it, and originally extending #60.
        return LINKAGE_MIXED
    if uncertain:
        return LINKAGE_UNKNOWN

    if static:
        return LINKAGE_STATIC

    if _has_symbol(binary, library.symbol_group, BINDING_IMPORTED):
        # It calls a library it neither ships nor declares. Whatever provides those
        # symbols at runtime is outside this wheel and outside our sight.
        return LINKAGE_UNKNOWN

    # `is_opaque` is deliberately NOT consulted here. An opaque object (`needed` is
    # non-empty for every loadable dylib and every `.pyd`, so this only fires for one
    # that yielded nothing at all) makes the *wheel* unable to answer for the whole
    # ruleset -- `_left_unanswered` already says so, and `resolve_linkage` passes that
    # signal into `_aggregate` gated on `library.always_report`. Returning
    # `LINKAGE_UNKNOWN` from here instead put that answer directly into this one
    # library's `postures` set, bypassing the gate: every library in the ruleset, not
    # only `openssl`, read `unknown` for an opaque binary, which is exactly what
    # `always_report`-gating exists to prevent. See #68.
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

    This is the one place a wheel-wide, library-agnostic non-answer belongs.
    `_binary_posture` may return `LINKAGE_UNKNOWN` only from a condition that depends
    on the specific `library` being asked about (an uncertain `needed` match against
    `library.sonames`, or an imported symbol from `library.symbol_group`) -- never
    from a fact about the object alone, because that answer is the same for every
    library in the ruleset and belongs here instead, gated through `resolve_linkage`
    on `library.always_report` rather than reported for all thirteen. `is_opaque` was
    a library-agnostic fact answered a second time inside `_binary_posture` until
    #68; if a future object-level non-answer is added, it belongs here, not there.
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
