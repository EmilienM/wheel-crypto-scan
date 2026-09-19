"""Rust crate inference from embedded cargo registry paths.

A Rust object carries the source path of every crate it was built from, usually
because a panic location or an `assert!` message embeds it. That makes this a
medium-confidence signal by nature: a crate that never contributed such a string is
invisible here, but a crate that shows up is unambiguous about being compiled in.
"""

from __future__ import annotations

import re

from ..evidence import RustCrate
from .caps import cap


def find_rust_crates(
    text: str, pattern: re.Pattern[str], max_crates: int, *, claimed: frozenset[str]
) -> tuple[tuple[RustCrate, ...], bool]:
    """Extract every distinct (name, version) pair `pattern` finds in `text`.

    `pattern` must have `name` and `version` groups (`BinaryPatterns.cargo_path_regex`
    guarantees this). Deduplication happens before sorting and the cap is applied
    after, so which crates survive truncation never depends on scan order.

    `claimed` is the crate names the ruleset has an entry for, and `binfmt.caps` keeps
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
        for match in pattern.finditer(text)
    }
    return cap(crates, max_crates, pin=lambda crate: crate.name in claimed)
