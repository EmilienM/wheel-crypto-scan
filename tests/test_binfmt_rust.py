"""Rust crate inference from embedded cargo source paths."""

from __future__ import annotations

from wheel_crypto_scan.binfmt.rust import find_rust_crates
from wheel_crypto_scan.ruleset_loader import load_ruleset

_CONV = load_ruleset().conventions
_PATTERNS = (_CONV.cargo_path_regex, _CONV.cargo_vendor_path_regex)


def test_finds_a_crate_from_a_cargo_registry_path() -> None:
    text = "/root/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ring-0.17.8/src/lib.rs"
    crates, truncated = find_rust_crates(text, _PATTERNS, max_crates=128, claimed=frozenset())
    assert truncated is False
    assert len(crates) == 1
    assert crates[0].name == "ring"
    assert crates[0].version == "0.17.8"


def test_finds_a_crate_from_a_distro_registry_path_with_no_index_segment() -> None:
    """Fedora's RPM Rust macros lay a crate out at `<registry>/<name>-<version>/`,
    with no `src/<index>/` segment, so the `src/<index>/` segment in
    `cargo_path_regex` must be optional."""
    text = "/usr/share/cargo/registry/openssl-0.10.81/src/ssl/mod.rs"
    crates, truncated = find_rust_crates(text, _PATTERNS, max_crates=128, claimed=frozenset())
    assert truncated is False
    assert [(c.name, c.version) for c in crates] == [("openssl", "0.10.81")]


def test_finds_a_versionless_crate_from_a_cargo_vendor_path() -> None:
    """`cargo vendor` without `--versioned-dirs`, which is what fromager configures,
    writes `vendor/<name>/...` with no version anywhere in the path."""
    text = "/build/cryptography-44.0.0/vendor/openssl-sys/src/lib.rs"
    crates, truncated = find_rust_crates(text, _PATTERNS, max_crates=128, claimed=frozenset())
    assert truncated is False
    assert [(c.name, c.version) for c in crates] == [("openssl-sys", None)]


def test_finds_a_versionless_crate_from_a_backslash_vendor_path() -> None:
    text = r"C:\b\vendor\ring\src\lib.rs"
    crates, truncated = find_rust_crates(text, _PATTERNS, max_crates=128, claimed=frozenset())
    assert truncated is False
    assert [(c.name, c.version) for c in crates] == [("ring", None)]


def test_vendor_path_missing_the_pattern_falls_back_to_no_source_layouts() -> None:
    """A patterns tuple without `cargo_vendor_path_regex` cannot match a vendor-only
    path -- a property of `find_rust_crates` itself, not a guard on which patterns
    `binfmt.strings` wires in; that guard is `test_review_fixes.py`'s end-to-end
    cargo-vendor-layout case."""
    crates, _ = find_rust_crates(
        r"C:\b\vendor\ring\src\lib.rs",
        (_CONV.cargo_path_regex,),
        max_crates=128,
        claimed=frozenset(),
    )
    assert crates == ()


def test_a_versioned_vendor_directory_is_read_as_name_and_version_not_one_name() -> None:
    """`vendor/gimli-0.32.3/` -- cargo's `--versioned-dirs`, and how rustc vendors its
    own dependencies -- must read as `gimli` `0.32.3`, not as a crate literally named
    `gimli-0.32.3` with no version. That needs the name class to exclude `.`, so the
    version's leading `-` is necessarily the last `-` before the first `.`."""
    text = "/b/rustc-1.97.1-src/vendor/gimli-0.32.3/src/read/line.rs"
    crates, _ = find_rust_crates(text, _PATTERNS, max_crates=128, claimed=frozenset())
    assert [(c.name, c.version) for c in crates] == [("gimli", "0.32.3")]


def test_a_hyphenated_crate_name_with_no_version_is_not_mistaken_for_one() -> None:
    text = "vendor/sha-1/src/lib.rs"
    crates, _ = find_rust_crates(text, _PATTERNS, max_crates=128, claimed=frozenset())
    assert [(c.name, c.version) for c in crates] == [("sha-1", None)]


def test_a_vendored_non_rust_tree_is_not_read_as_a_rust_crate() -> None:
    """A vendored C or Go tree must never surface as a Rust crate claim. Every one of
    these paths ends in a source file that is not `.rs`, or is not under a whole
    `vendor` path component, and none should yield a crate. The last two span two
    printable runs joined by a newline, which the negated character classes in
    `cargo_vendor_path_regex` must not bridge: without the `\\n` exclusion, the `.c`
    in the first run and the `.rs` in the second combine into a false crate match."""
    texts = [
        "/p/vendor/openssl/crypto/evp/evp_enc.c",
        "/p/vendor/zlib-1.3.1/deflate.c",
        "/go/src/vendor/golang.org/x/crypto/sha3/sha3.go",
        "/p/xvendor/foo/src/lib.rs",
        "/p/vendor/openssl/crypto/evp/evp_enc.c\nsrc/mod.rs",
        "/p/vendor/openssl/crypto/evp/evp_enc.c\nmod.rs",
    ]
    for text in texts:
        crates, _ = find_rust_crates(
            text, _PATTERNS, max_crates=128, claimed=frozenset({"openssl"})
        )
        assert crates == (), text


def test_a_vendor_path_with_no_nul_terminator_still_matches() -> None:
    """Rust does not NUL-terminate a panic location the way a C string literal would,
    so the file-extension anchor must not require anything after `.rs`."""
    text = "vendor/openssl/src/ssl/mod.rsassertion failed"
    crates, _ = find_rust_crates(text, _PATTERNS, max_crates=128, claimed=frozenset())
    assert [(c.name, c.version) for c in crates] == [("openssl", None)]


def test_a_registry_and_a_vendor_hit_for_the_same_crate_sort_deterministically() -> None:
    """`sort_key` must total over `version` even when it is `None` for one of two
    entries with the same name, or a plain `(name, version)` tuple sort raises
    TypeError comparing `str` to `None`."""
    text = "\n".join(
        [
            "cargo/registry/src/index.crates.io-x/ring-0.17.8/src/lib.rs",
            "vendor/ring/src/lib.rs",
        ]
    )
    crates, _ = find_rust_crates(text, _PATTERNS, max_crates=128, claimed=frozenset())
    assert [(c.name, c.version) for c in crates] == [("ring", None), ("ring", "0.17.8")]


def test_deduplicates_repeated_paths_for_the_same_crate() -> None:
    path = "/root/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ring-0.17.8/src/aead.rs"
    text = "\n".join([path, path.replace("aead", "hkdf")])
    crates, truncated = find_rust_crates(text, _PATTERNS, max_crates=128, claimed=frozenset())
    assert crates == (crates[0],)


def test_sorts_multiple_distinct_crates_by_name_then_version() -> None:
    text = "\n".join(
        [
            "cargo/registry/src/index.crates.io-x/zeroize-1.7.0/src/lib.rs",
            "cargo/registry/src/index.crates.io-x/aws-lc-sys-0.19.0/src/lib.rs",
        ]
    )
    crates, _ = find_rust_crates(text, _PATTERNS, max_crates=128, claimed=frozenset())
    assert [c.name for c in crates] == ["aws-lc-sys", "zeroize"]


def test_caps_after_sorting_and_flags_truncation() -> None:
    """With nothing claimed the cap is the plain one, which is what it always was."""
    text = "\n".join(
        f"cargo/registry/src/index.crates.io-x/crate{i}-0.1.{i}/src/lib.rs" for i in range(5)
    )
    crates, truncated = find_rust_crates(text, _PATTERNS, max_crates=2, claimed=frozenset())
    assert truncated is True
    assert [c.name for c in crates] == ["crate0", "crate1"]


def test_a_claimed_crate_outranks_the_alphabet() -> None:
    """The path production actually takes, which the test above never exercised.

    `claimed` is always non-empty in the scanner, so a test suite that only passed the
    empty set pinned a branch nothing uses and left the one that matters uncovered.
    """
    text = "\n".join(
        [f"cargo/registry/src/index.crates.io-x/aaa{i:03d}-0.1.0/src/lib.rs" for i in range(10)]
        + ["cargo/registry/src/index.crates.io-x/ring-0.17.8/src/lib.rs"]
    )
    crates, truncated = find_rust_crates(text, _PATTERNS, max_crates=3, claimed=frozenset({"ring"}))
    assert truncated is True
    assert "ring" in {crate.name for crate in crates}
    assert len(crates) == 3


def test_no_match_yields_empty_tuple_not_an_exception() -> None:
    crates, truncated = find_rust_crates(
        "nothing interesting here", _PATTERNS, max_crates=128, claimed=frozenset()
    )
    assert crates == ()
    assert truncated is False
