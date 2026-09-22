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
ships". See `DESIGN.md`, "A `needed` entry is bundled by what it resolves to, not by
whether its name was renamed".

A structural rule underlies all of the above: an absolute `needed` path is never
resolved relative to anything -- not `RPATH`/`RUNPATH`, not a vendor directory, not
the wheel at all -- so it can never be evidence of vendoring, whatever else in the
wheel happens to share its basename.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping

from .conventions import Conventions
from .evidence import BINDING_DEFINED, BINDING_IMPORTED, STAGE_BINARY, BinaryEvidence, Evidence
from .ruleset import CryptoLibrary, Ruleset, sbom_crate_key, sbom_library_key

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
    happens to share the same stem. An absolute `needed` entry never reaches this
    count, because `needed_posture` answers it before asking, so the discount is
    exercised by a *relative* same-named dependency: the coincidence is exactly as
    possible there, reached through the ordinary, non-absolute path.

    The object's `path` is set by `layers.binaries.scan_binaries` for every member it
    attempts to read, whether or not the read succeeded, so a vendored copy whose
    internal structure could not be parsed still counts.

    `binary.from_archive` objects are excluded: a relocatable object inside a `.a`/
    `.lib` static archive (`binfmt.ar`) is never a file any real dynamic loader
    could resolve a `needed` entry to, so a `SONAME` on one -- bytes `binfmt.ar` reads
    exactly as written, including whatever an adversarial wheel chose to write there
    -- must not be able to confirm an unrelated `needed` entry as resolving inside the
    wheel. Counting it would let a crafted archive member flip a genuinely
    system-linked sibling extension's posture to `bundled`.
    """
    return Counter(
        conventions.raw_stem(binary.soname, binary.path)
        for binary in evidence.binaries
        if not binary.from_archive
    )


def _resolves_within_wheel(own_stem: str, needed_stem: str, counts: Mapping[str, int]) -> bool:
    """True when some object OTHER than the one declaring `needed` answers to its stem.

    An object's own stem never counts toward its own `needed` entries (see
    `member_stem_counts`), so when the two coincide, confirmation requires a second
    contributor; when they differ, the declaring object contributes nothing to that
    stem in the first place and any count at all is a different, genuine object.

    Assumes `needed` is a name a real loader could plausibly resolve inside the wheel
    at all -- `needed_posture` only calls this for a relative entry, never an absolute
    path, which no loader resolves this way regardless of what shares its basename.
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
    is genuine `system`, not `unknown`.

    Also assumes `needed` is a relative entry: `needed_posture` never calls this for
    an absolute path, because an absolute path is never resolved relative to a loading
    object's `RPATH`/`RUNPATH` or its own directory, so a vendor-glob-shaped component
    inside one -- whether embedded directly or produced by the join below -- names
    nothing a real loader would ever look at.
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
    and an incompletely-read wheel cannot rule it out either; `LINKAGE_SYSTEM`
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

    The short-circuit covers only a genuinely absolute path (`startswith("/")`). A
    relative-looking entry that still cannot resolve inside the wheel by any real
    search order -- a `../`-relative path, or a Mach-O `@executable_path/`-anchored
    one, which resolves against the process's own binary rather than the loading
    object -- reaches `_resolves_within_wheel` and `_looks_vendored` like any other
    relative entry, and can read a spurious `bundled` or `unknown` from an unrelated
    basename collision. That is narrower than the argument above technically allows;
    `DESIGN.md` records it as a residual left open rather than assumed closed.

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


def _object_postures(
    binaries: tuple[BinaryEvidence, ...],
    library: CryptoLibrary,
    conventions: Conventions,
    counts: Mapping[str, int],
    incomplete: bool,
) -> tuple[str, ...]:
    """`_binary_posture` for each binary, in `evidence.binaries` order."""
    return tuple(
        _binary_posture(binary, library, conventions, counts, incomplete) for binary in binaries
    )


def object_postures(ruleset: Ruleset, evidence: Evidence, name: str) -> tuple[str, ...]:
    """The per-object postures `resolve_linkage` aggregates for library `name`.

    Shared with `engine._match_linkage`, the same way `needed_posture` is shared with
    `engine._match_dt_needed`, so a rule reading an object's own posture and the field
    aggregated from it can never disagree about what that object said.

    This never carries `_left_unanswered`'s wheel-wide, library-agnostic signal: an
    object that could not be read at all contributes nothing here, only to
    `resolve_linkage`'s aggregate through `_aggregate`'s `unanswered` argument. A rule
    that reads this tuple therefore only ever sees `LINKAGE_UNKNOWN` from an object
    that was read and said the library is used without saying which copy, never from
    one that was not read at all.
    """
    counts = member_stem_counts(ruleset.conventions, evidence)
    incomplete = wheel_incompletely_read(evidence)
    return _object_postures(
        evidence.binaries, ruleset.libraries[name], ruleset.conventions, counts, incomplete
    )


def resolve_linkage(ruleset: Ruleset, evidence: Evidence) -> dict[str, str]:
    """Map each crypto library with evidence in this wheel to its linkage posture."""
    unanswered = _left_unanswered(ruleset, evidence)
    counts = member_stem_counts(ruleset.conventions, evidence)
    incomplete = wheel_incompletely_read(evidence)
    sbom_library_keys = _sbom_library_keys(evidence)
    sbom_crate_keys = _sbom_crate_keys(evidence)
    sbom_purls_by_key = _sbom_purls_by_library_key(evidence)
    rust_crate_keys = frozenset(sbom_crate_key(name) for name in ruleset.rust_crates)
    result: dict[str, str] = {}
    for name in sorted(ruleset.libraries):
        library = ruleset.libraries[name]
        postures = set(
            _object_postures(evidence.binaries, library, ruleset.conventions, counts, incomplete)
        )
        value = _aggregate(
            postures,
            unanswered and library.always_report,
            _declared_by_sbom(
                library, sbom_library_keys, sbom_crate_keys, sbom_purls_by_key, rust_crate_keys
            ),
        )
        if value != LINKAGE_NONE or library.always_report:
            result[name] = value
    return result


def _aggregate(postures: set[str], unanswered: bool, declared: bool) -> str:
    """Reduce per-binary postures to one answer for the whole wheel.

    `unanswered` is the wheel-wide signal that some object did not answer, and it is
    only consulted when nothing in the wheel answered definitely: one unreadable
    object must not erase what the readable ones said. It reaches here already gated
    on `always_report`, so an object we could not read makes the answer `unknown` for
    the libraries reported whatever the evidence -- where a false `none` is what does
    the damage -- and does not list every library in the ruleset as unknown.

    A per-object `unknown` this function drops beside a definite posture (the
    `len(definite) == 1` branch below) is still visible to rules through
    `object_postures`, which is how `DERIVED_SYSTEM_OPENSSL_ONLY` declines to fire
    beside an object that read `unknown`.

    `mixed` can also arrive already resolved for a single object: a `needed` entry
    matched the system library and the object also defines its own copy or carries a
    banner that is not header text, or a `needed` entry resolved inside the wheel
    (`bundled`) beside a different `needed` entry matching the system library, or
    beside a definition/banner, on that same object. It is not only this function's
    own combination of two definite postures from different objects. `mixed` has no
    finer split than that in the vocabulary, so one object already reading `mixed`
    makes the wheel `mixed` outright, whatever any other object says.

    `declared` is the library-specific signal that the wheel's own SBOM names this
    library, or a crate that binds it (`_declared_by_sbom`). Like `unanswered`, it is
    consulted only when nothing in the wheel answered definitely, and it can never
    outvote a `_DEFINITE` posture found on any object. It is not gated on
    `always_report`: `unanswered` is a fact about the wheel that applies to every
    library alike, but `declared` is already about this one library, the same way the
    crate branch in `_binary_posture` is not gated either.

    Unlike a per-object `unknown`, `declared` is wheel-level and never appears in
    `object_postures`'s tuple, so it stays invisible to a rule's own
    `exclude_object_values`/`object_values` check. A wheel whose SBOM names an OpenSSL
    crate beside an object that reads `system` still fires `DERIVED_SYSTEM_OPENSSL_ONLY`:
    `declared` never reaches `_aggregate` at all once a `_DEFINITE` posture exists (the
    `len(definite) == 1` branch above returns first), so there is nothing here for that
    rule's exclusion to see. That is a known residual, recorded in DESIGN.md, "An SBOM
    naming an OpenSSL crate reads `unknown`, not `none`".
    """
    if LINKAGE_MIXED in postures:
        return LINKAGE_MIXED
    definite = sorted(posture for posture in postures if posture in _DEFINITE)
    if len(definite) == 1:
        return definite[0]
    if len(definite) > 1:
        return LINKAGE_MIXED
    if LINKAGE_UNKNOWN in postures or unanswered or declared:
        return LINKAGE_UNKNOWN
    return LINKAGE_NONE


def _sbom_library_keys(evidence: Evidence) -> frozenset[str]:
    """Every SBOM component name, folded through `ruleset.sbom_library_key`."""
    if evidence.metadata is None:
        return frozenset()
    return frozenset(
        sbom_library_key(component.name) for component in evidence.metadata.sbom_components
    )


def _sbom_crate_keys(evidence: Evidence) -> frozenset[str]:
    """Every SBOM component name, folded through `ruleset.sbom_crate_key`."""
    if evidence.metadata is None:
        return frozenset()
    return frozenset(
        sbom_crate_key(component.name) for component in evidence.metadata.sbom_components
    )


def _sbom_purls_by_library_key(evidence: Evidence) -> Mapping[str, frozenset[str | None]]:
    """Every `purl` (including a missing one, as `None`) seen on a component whose name
    folds to a given `sbom_library_key`. `_declared_by_sbom` reads this only for the
    `argon2`/`blake2` name collision, to tell an SBOM component naming the C reference
    library apart from one naming the unrelated pure-Rust crate of the same name.
    """
    if evidence.metadata is None:
        return {}
    by_key: dict[str, set[str | None]] = {}
    for component in evidence.metadata.sbom_components:
        by_key.setdefault(sbom_library_key(component.name), set()).add(component.purl)
    return {key: frozenset(purls) for key, purls in by_key.items()}


def is_cargo_purl(purl: str | None) -> bool:
    """A `pkg:cargo/...` purl is PEP 770's own way of saying "this component is the
    crates.io crate": `cargo` is the purl `type` PEP 770 reserves for that registry.
    Anything else -- a different purl type, or none at all -- makes no such claim.
    Public because `engine._sbom_entry` reads the same purl to pick which table rates
    a component whose name collides between `crypto_library` and `rust_crate`.
    """
    return purl is not None and purl.startswith("pkg:cargo/")


def _declared_by_sbom(
    library: CryptoLibrary,
    library_keys: frozenset[str],
    crate_keys: frozenset[str],
    purls_by_library_key: Mapping[str, frozenset[str | None]],
    rust_crate_keys: frozenset[str],
) -> bool:
    """Does the wheel's own SBOM name this library, or a crate that binds it?

    Accepts only names `SBOM_CRYPTO_COMPONENT` also reports through its
    `crypto_library` and `rust_crate` tables (`engine._sbom_entry`), and compares them
    the same way it does: through `ruleset.sbom_library_key`/`sbom_crate_key`, never a
    raw string. That keeps this field and that finding from ever disagreeing about the
    same string -- the field cannot move on a component the record carries no finding
    for. That agreement holds only because
    `ruleset_loader._validate_sbom_component_coverage` refuses to load a ruleset whose
    `sbom_component` rules, taken together, do not cover both tables; this function
    assumes that check already ran.

    Deliberately excludes a distribution name (`crypto_distribution`): a distribution
    wrapping a library is not the same claim as the wheel carrying a copy of it --
    SCHEMA.md says a distribution name never moves this field. A soname is
    not a candidate in the first place, never mind excluded: it is a dependency
    string, not the name of a package or crate, so no SBOM component is ever spelled
    that way, and this field's `needed`-side matching already owns soname comparison.

    `library.name` collides with a *different* `[[rust_crate]]` this library does not
    itself list in `crates` for exactly two names: `argon2` and `blake2` are both a
    `[[crypto_library]]` (the C reference libargon2 and libb2) and, separately, a
    pure-Rust `[[rust_crate]]` of the same name that does not bind the C library --
    neither lists itself in `crates`, unlike `openssl`, whose own name is deliberately
    one of its `crates` because the `openssl` crate really does bind libssl/libcrypto.
    For that collision, a name match alone cannot say which of the two an SBOM
    component means, so this reads the component's own `purl`: only `pkg:cargo/...`
    -- the crates.io registry type -- says the component is the pure-Rust crate. A
    component named `argon2` with any other purl, or none at all (`pkg:generic/...`,
    or a purl-less entry a reader could not classify), still names something that
    could be the C library, so it still counts. Two simpler alternatives were rejected.
    Matching by name alone -- treating any component named `argon2`/`blake2` as the C
    library whatever its purl -- gives a false positive: a component under
    `pkg:cargo/argon2@...`, naming the pure-Rust crate, would move `argon2_linkage`
    off `none` when nothing about it says the C library is present. Skipping the name
    arm whenever the name merely collides, whatever the purl, gives the opposite
    failure: a component that really does name libargon2 or libb2 under a non-cargo
    purl, or none, would not move the field, while `SBOM_CRYPTO_COMPONENT` still fires
    on that same name -- the finding fires on the name whatever the purl, the purl
    only picks which table rates it -- leaving a finding with no field beside it to
    say so, the same "reports nothing" shape the invariants resist.
    See DESIGN.md, "An SBOM naming an OpenSSL crate reads `unknown`, not `none`".

    An SBOM component says the wheel uses the library, not which copy, exactly like a
    Rust crate: never a definite posture, only `unknown` in place of `none`.
    """
    # `library.name not in library.crates` is not checked here: when it does list
    # itself (openssl), the `crates` arm on the return below already matches its own
    # name regardless of purl, so this branch's outcome would be the same either way.
    name_is_someone_elses_crate = sbom_crate_key(library.name) in rust_crate_keys
    if name_is_someone_elses_crate:
        purls = purls_by_library_key.get(sbom_library_key(library.name), frozenset())
        name_matches = any(not is_cargo_purl(purl) for purl in purls)
    else:
        name_matches = sbom_library_key(library.name) in library_keys
    return name_matches or any(sbom_crate_key(crate) in crate_keys for crate in library.crates)


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
            # so a plain name that resolves inside the wheel counts too.
            #
            # No early return: returning here, before the rest of this loop (a
            # second `needed` entry that resolves to `system`, say) or the
            # defined/static check below it runs, would let a merged fat-slice
            # object whose slices disagree (one slice bundled, another system or
            # static) read `bundled` outright instead of `mixed`, unlike the same
            # evidence split across two separate objects. `bundled` is a
            # `_DEFINITE` posture exactly like `system`, so it belongs in the same
            # disagreement check below, not in a return of its own.
            bundled = True
            continue
        if posture == LINKAGE_UNKNOWN:
            # Looks vendored (a `@loader_path`/`@rpath`/vendor-shaped RUNPATH), but
            # nothing in the wheel confirms it names a file that is actually there.
            # Not proof of "system" either: the file it names may be the one member
            # of an incompletely-read wheel that never got read.
            uncertain = True
            continue
        system = True

    defined = _has_symbol(binary, library.symbol_group, BINDING_DEFINED)
    # A banner alone is not `static` when it is header text rather than a copy: the
    # object's `needed` entries already resolved the library from the host, and the
    # object imports from it, was read in full, and carries none of the strings that
    # mark a genuine compiled-in copy. See `_banner_is_header_text` for the gates.
    banner = _has_string(binary, library.string_group) and not (
        system and _banner_is_header_text(binary, library)
    )
    static = defined or banner
    if sum((system, bundled, static)) > 1:
        # Two or more of `system`, `bundled` and `static` are true on this one
        # object at once. Each is a `_DEFINITE` posture (see the tuple above) drawn
        # from its own piece of evidence -- a `needed` entry resolving to the host
        # library, a different `needed` entry resolving inside the wheel, or a
        # defined symbol, or a banner that is not header text -- and none of the
        # three is weaker evidence than the others, so none wins outright over the
        # rest: this object's own evidence already disagrees with itself the same
        # way two different objects' postures disagree in `_aggregate`
        # (`len(definite) > 1: return LINKAGE_MIXED`), so it reads `mixed` here
        # too, before `_aggregate` ever runs. The count is three-way so that
        # `bundled`-and-`system` and `bundled`-and-`static` are caught alongside
        # `system`-and-`static`.
        return LINKAGE_MIXED
    if system:
        return LINKAGE_SYSTEM
    if bundled:
        # No other `_DEFINITE` posture was also true above, so this is the
        # ordinary bundled case, reached only after confirming it does not need
        # to combine with a `system` or `static` signal found elsewhere on this
        # same object.
        return LINKAGE_BUNDLED
    if uncertain and static:
        # A `needed` entry whose path/rpath shape looks vendored but that this
        # incompletely-read wheel cannot confirm either way, and a real definition
        # or banner in the same object, are both true at once. Returning `unknown`
        # here would discard the confirmed static evidence in favour of the
        # unconfirmed one, the opposite of what "unreadable or uncertain must never
        # read as NO_CRYPTO_DETECTED" asks for: a real fact should never be the one
        # that goes missing.
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
        # been ruled out. See `DESIGN.md`, "An `uncertain` needed match beside a
        # definition is `mixed`".
        return LINKAGE_MIXED
    if uncertain:
        return LINKAGE_UNKNOWN

    if static:
        return LINKAGE_STATIC

    if _has_symbol(binary, library.symbol_group, BINDING_IMPORTED):
        # It calls a library it neither ships nor declares. Whatever provides those
        # symbols at runtime is outside this wheel and outside our sight.
        return LINKAGE_UNKNOWN

    if any(crate.name in library.crates for crate in binary.rust_crates):
        # The same answer for the same reason: a crate that binds the library was
        # compiled in, and nothing above says which copy it binds. `openssl-sys`
        # links the host's or vendors its own depending on a build feature the
        # object does not record, so the crate can say `unknown` and never more.
        return LINKAGE_UNKNOWN

    # `is_opaque` is deliberately NOT consulted here. An opaque object (`needed` is
    # non-empty for every loadable dylib and every `.pyd`, so this only fires for one
    # that yielded nothing at all) makes the *wheel* unable to answer for the whole
    # ruleset -- `_left_unanswered` already says so, and `resolve_linkage` passes that
    # signal into `_aggregate` gated on `library.always_report`. Returning
    # `LINKAGE_UNKNOWN` from here instead would put that answer directly into this
    # one library's `postures` set, bypassing the gate: every library in the ruleset,
    # not only `openssl`, would read `unknown` for an opaque binary, which is exactly
    # what `always_report`-gating exists to prevent.
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


def _banner_is_header_text(binary: BinaryEvidence, library: CryptoLibrary) -> bool:
    """Is a `string_group` match on this object header text rather than a copy?

    Assumes the caller has already established gate (a): a `needed` entry on this
    same object resolved the library from the host (`system` is true). Without that
    precondition, imported symbols beside a banner are the shape of a static copy
    linked alongside an unresolved dependency, not header text, and this must not be
    called.

    Each remaining gate answers one question: gate (b), imported symbols from the
    library's own `symbol_group`, means the object actually calls the host copy, not
    merely that it declares a dependency on one; gate (c), `partial_analysis` being
    true, means a partial read may have cut the very string that would prove a copy,
    for any cause, so the gate stays shut rather than reusing
    `linkage_policy.exclude_reasons`, which answers a different question about a
    different field; gate (d), a library with no `copy_string_group`, has no way to
    tell a header banner from a copy, so `None` never opens the gate; and gate (d)'s
    other half, a real compiled-in copy keeping its build strings beside its banner,
    means finding none of them is what actually says "header", not the absence of
    anything else.
    """
    if library.copy_string_group is None or binary.partial_analysis:
        return False
    return _has_symbol(binary, library.symbol_group, BINDING_IMPORTED) and not _has_string(
        binary, library.copy_string_group
    )


def _left_unanswered(ruleset: Ruleset, evidence: Evidence) -> bool:
    """Did any object in this wheel fail to answer the question linkage asks?

    Three ways. An object that yielded nothing at all; a binary that never produced a
    record, which shows up as a binary-stage error; and an object a reader read and
    explicitly marked as not read in full.

    That third one is the everyday case rather than the exotic one -- a stripped macOS
    extension records `macho_symtab_incomplete` and no error -- and without it the
    record would say both "we could not read this object's symbols" and "there is no
    OpenSSL in it", which is a claim the first half says we cannot make. `is_opaque`
    does not rescue it: `needed` is non-empty for every loadable dylib and every
    `.pyd`.

    Which causes count is policy and is read off the ruleset, because most of
    `partial_reasons` is a failure and some of it is a linker convention that leaves
    every field linkage reads intact. Counting the tuple wholesale would turn every
    ordinal import into `openssl_linkage: unknown`: the same noise that keeping a
    routine cause out of the verdict avoids.

    This is the one place a wheel-wide, library-agnostic non-answer belongs.
    `_binary_posture` may return `LINKAGE_UNKNOWN` only from a condition that depends
    on the specific `library` being asked about (an uncertain `needed` match against
    `library.sonames`, an imported symbol from `library.symbol_group`, or a crate
    from `library.crates`) -- never from a fact about the object alone, because that
    answer is the same for every library in the ruleset and belongs here instead,
    gated through `resolve_linkage` on `library.always_report` rather than reported
    for all thirteen. `is_opaque` is such a fact, and it is answered here and nowhere
    else; any other object-level non-answer belongs here too, not there. A
    library-specific wheel-level signal -- the wheel's own SBOM naming a library or a
    crate that binds it -- goes through `_declared_by_sbom` instead, not here.
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
