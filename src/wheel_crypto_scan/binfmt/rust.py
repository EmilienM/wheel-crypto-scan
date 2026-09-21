"""Rust crate inference from embedded cargo source paths.

A Rust object carries the source path of every crate it was built from, usually
because a panic location or an `assert!` message embeds it. That makes this a
medium-confidence signal by nature: a crate that never contributed such a string is
invisible here, but a crate that shows up is unambiguous about being compiled in.

The path comes from whichever layout built the object: the cargo registry (with or
without the `src/<index>/` segment distro packaging omits), or a `cargo vendor` tree.
A layout that names no version, such as `cargo vendor` without `--versioned-dirs`,
yields a crate with `version=None` rather than an invented one.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from ..evidence import RustCrate
from ..caps import cap


def find_rust_crates(
    text: str,
    patterns: Sequence[re.Pattern[str]],
    max_crates: int,
    *,
    claimed: frozenset[str],
) -> tuple[tuple[RustCrate, ...], bool]:
    """Extract every distinct (name, version) pair any pattern in `patterns` finds.

    `text` must be `binfmt.strings.RUN_SEPARATOR`-joined runs, and every pattern in
    `patterns` must not match across that separator: the caller (`strings.py`) relies
    on this the same way `match_string_groups` does, to keep a hit inside one printable
    run rather than splicing two unrelated ones together.

    Each pattern must have `name` and `version` groups (`ruleset_loader` guarantees
    this for every cargo convention). `version` is `None` when a pattern's `version`
    group did not participate in the match, which is how a layout that carries no
    version is told apart from one that does. Deduplication happens before sorting and
    the cap is applied after, so which crates survive truncation never depends on scan
    order or on which pattern found a given crate first.

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
    crates = {
        RustCrate(name=match.group("name"), version=match.group("version"))
        for pattern in patterns
        for match in pattern.finditer(text)
    }
    return cap(crates, max_crates, pin=lambda crate: crate.name in claimed)
