"""Rust crate inference from embedded cargo registry paths.

A Rust object carries the source path of every crate it was built from, usually
because a panic location or an `assert!` message embeds it. That makes this a
medium-confidence signal by nature: a crate that never contributed such a string is
invisible here, but a crate that shows up is unambiguous about being compiled in.
"""

from __future__ import annotations

import re

from ..evidence import RustCrate


def find_rust_crates(
    text: str, pattern: re.Pattern[str], max_crates: int
) -> tuple[tuple[RustCrate, ...], bool]:
    """Extract every distinct (name, version) pair `pattern` finds in `text`.

    `pattern` must have `name` and `version` groups (`ScanPatterns.cargo_path_regex`
    guarantees this). Deduplication happens before sorting and the cap is applied
    after, so which crates survive truncation never depends on scan order.
    """
    crates = {
        RustCrate(name=match.group("name"), version=match.group("version"))
        for match in pattern.finditer(text)
    }
    ordered = tuple(sorted(crates, key=lambda crate: crate.sort_key()))
    truncated = len(ordered) > max_crates
    return ordered[:max_crates], truncated
