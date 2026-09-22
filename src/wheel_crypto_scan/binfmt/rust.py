"""Rust crate inference from embedded cargo source paths.

A Rust object carries the source path of every crate it was built from, usually
because a panic location or an `assert!` message embeds it. That makes this a
medium-confidence signal by nature: a crate that never contributed such a string is
invisible here, but a crate that shows up is unambiguous about being compiled in.

The path comes from whichever layout built the object: the cargo registry (with or
without the `src/<index>/` segment distro packaging omits), a `cargo vendor` tree, or
a git dependency checkout (`git/checkouts/<repo>-<hash>/<rev>/...`). A layout that
names no version, such as `cargo vendor` without `--versioned-dirs` or a git checkout
(pinned by revision, not a version), yields a crate with `version=None` rather than an
invented one. A git checkout also names a root crate after its repository rather than
the crate itself, since the checkout directory is `<repo>-<hash>`, not `<crate>-
<hash>`; a workspace member's own directory, immediately above its `src/`, is read as
the crate name where the repository holds more than one.
"""

from __future__ import annotations

import re
from bisect import bisect_right

from ..evidence import RustCrate
from ..caps import cap

# Directory components between a registry crate's directory and a `vendor/` inside it:
# no run separator, no NUL or quote, and no component reaching a `.rs` file, which is
# where that crate's own source path ends. Bounded like `cargo_vendor_path_regex`.
_NESTED_GAP = re.compile(r"(?:(?:(?!\.rs)[^/\\\x00\"'\n]){1,255}[/\\]){0,16}")


def find_rust_crates(
    text: str,
    max_crates: int,
    *,
    registry: re.Pattern[str] | None,
    vendor: re.Pattern[str] | None,
    git: re.Pattern[str] | None,
    claimed: frozenset[str],
) -> tuple[tuple[RustCrate, ...], bool]:
    """Extract every distinct (name, version) pair the registry, vendor and git-checkout
    layouts find.

    `registry` matches the crates.io registry layout (with or without the `src/<index>/`
    segment distro packaging omits), `vendor` matches a `cargo vendor` tree, and `git`
    matches a git dependency checkout (`git/checkouts/<repo>-<hash>/<rev>/...`). Any of
    the three may be `None`, meaning that layout is not read; the tests that cover one
    layout at a time pass `None` for the others rather than relying on a default, which
    would turn that layout off silently for a caller that forgot it.

    A `vendor/` tree inside a registry crate's directory is that crate's own vendored
    source, not a crate of its own: `.../bar-1.0.0/vendor/ring/src/x.rs` is `bar`
    1.0.0, and the `ring` match nested inside it is dropped. The registry crate's
    directory is taken to end at the first `.rs` file on its path, not at the end of
    the printable run, because rustc packs `&'static str` panic locations for
    unrelated crates back to back in read-only data. A `vendor/` match that starts
    before that point, in the directory components between the registry match and its
    `.rs`, is nested; a `vendor/` match starting after it is a separate path and is
    kept. This only runs one way: a registry match inside an outer `vendor/` directory
    is unaffected, which is the nesting gap `DESIGN.md` already documents for that
    layout. A `vendor/` tree inside a git-checkout workspace member gets no such
    precedence: `git`'s own `name` group already reads the directory immediately above
    `src/`, so it agrees with `vendor` on the same crate without needing one pattern to
    defer to the other, unlike a registry match, whose own pattern stops short of the
    `.rs` file and so cannot see a nested `vendor/` match's name by itself.

    `text` must be `binfmt.strings.RUN_SEPARATOR`-joined runs, and none of `registry`,
    `vendor` or `git` may match across that separator: the caller (`strings.py`) relies
    on this the same way `match_string_groups` does, to keep a hit inside one printable
    run rather than splicing two unrelated ones together. `registry` must also end its
    match at the separator that closes the crate directory, which is what lets the gap
    between a registry match and a nested `vendor/` match be read as directory
    components.

    Each pattern must have `name` and `version` groups (`ruleset_loader` guarantees
    this for every cargo convention). `version` is `None` when a pattern's `version`
    group did not participate in the match, which is how a layout that carries no
    version is told apart from one that does. Deduplication happens before sorting and
    the cap is applied after, so which crates survive truncation never depends on scan
    order.

    `claimed` is the crate names the ruleset has an entry for, and `caps` keeps
    one version of each ahead of everything else. Required rather than defaulted: a
    default would turn the protection off for a caller that forgot it, silently.

    A cut through a plain sort dropped them for no better reason than the alphabet.
    Every crypto crate named today -- `openssl`, `ring`, `rustls`, `sha1`, `sha2`,
    `pbkdf2` -- sits in the o-to-s range, and a Rust wheel carrying three hundred
    crates has a hundred and twenty-eight `anyhow`-class names in front of them. That
    wheel read `NO_CRYPTO_DETECTED` with nothing recorded at all, which is the one
    outcome this tool exists to prevent.

    This is the list that needs the pin, and the other two do not: a string or a symbol
    only reaches a cap because a group matched it, where a crate list is also an
    inventory of everything compiled in. The extractor is no more policy-aware for
    holding the names -- it is told which strings matter and still has no idea what any
    of them means.
    """
    registry_matches = list(registry.finditer(text)) if registry else []
    ends = [match.end() for match in registry_matches]

    crates = {
        RustCrate(name=match.group("name"), version=match.group("version"))
        for match in registry_matches
    }

    if git:
        crates.update(
            RustCrate(name=match.group("name"), version=match.group("version"))
            for match in git.finditer(text)
        )

    if vendor:
        for match in vendor.finditer(text):
            index = bisect_right(ends, match.start()) - 1
            if index >= 0 and _NESTED_GAP.fullmatch(text, ends[index], match.start()):
                continue
            crates.add(RustCrate(name=match.group("name"), version=match.group("version")))

    return cap(crates, max_crates, pin=lambda crate: crate.name in claimed)
