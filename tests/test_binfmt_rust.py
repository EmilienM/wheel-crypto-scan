"""Rust crate inference from embedded cargo source paths."""

from __future__ import annotations

import pytest

from wheel_crypto_scan.binfmt.rust import find_rust_crates
from wheel_crypto_scan.binfmt.strings import RUN_SEPARATOR, extract_printable
from wheel_crypto_scan.ruleset_loader import load_ruleset

_CONV = load_ruleset().conventions
_PATTERNS = {
    "registry": _CONV.cargo_path_regex,
    "vendor": _CONV.cargo_vendor_path_regex,
    "git": _CONV.cargo_git_path_regex,
}


def test_finds_a_crate_from_a_cargo_registry_path() -> None:
    text = "/root/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ring-0.17.8/src/lib.rs"
    crates, truncated = find_rust_crates(text, max_crates=128, **_PATTERNS, claimed=frozenset())
    assert truncated is False
    assert len(crates) == 1
    assert crates[0].name == "ring"
    assert crates[0].version == "0.17.8"


def test_finds_a_crate_from_a_distro_registry_path_with_no_index_segment() -> None:
    """Fedora's RPM Rust macros lay a crate out at `<registry>/<name>-<version>/`,
    with no `src/<index>/` segment, so the `src/<index>/` segment in
    `cargo_path_regex` must be optional."""
    text = "/usr/share/cargo/registry/openssl-0.10.81/src/ssl/mod.rs"
    crates, truncated = find_rust_crates(text, max_crates=128, **_PATTERNS, claimed=frozenset())
    assert truncated is False
    assert [(c.name, c.version) for c in crates] == [("openssl", "0.10.81")]


def test_finds_a_versionless_crate_from_a_cargo_vendor_path() -> None:
    """`cargo vendor` without `--versioned-dirs`, which is what fromager configures,
    writes `vendor/<name>/...` with no version anywhere in the path."""
    text = "/build/cryptography-44.0.0/vendor/openssl-sys/src/lib.rs"
    crates, truncated = find_rust_crates(text, max_crates=128, **_PATTERNS, claimed=frozenset())
    assert truncated is False
    assert [(c.name, c.version) for c in crates] == [("openssl-sys", None)]


def test_finds_a_versionless_crate_from_a_backslash_vendor_path() -> None:
    text = r"C:\b\vendor\ring\src\lib.rs"
    crates, truncated = find_rust_crates(text, max_crates=128, **_PATTERNS, claimed=frozenset())
    assert truncated is False
    assert [(c.name, c.version) for c in crates] == [("ring", None)]


def test_vendor_path_missing_the_pattern_falls_back_to_no_source_layouts() -> None:
    """`vendor=None` cannot match a vendor-only path -- a property of
    `find_rust_crates` itself, not a guard on which patterns `binfmt.strings` wires
    in; that guard is `test_acceptance.py`'s end-to-end cargo-vendor-layout case."""
    crates, _ = find_rust_crates(
        r"C:\b\vendor\ring\src\lib.rs",
        max_crates=128,
        registry=_CONV.cargo_path_regex,
        vendor=None,
        git=None,
        claimed=frozenset(),
    )
    assert crates == ()


def test_a_versioned_vendor_directory_is_read_as_name_and_version_not_one_name() -> None:
    """`vendor/gimli-0.32.3/` -- cargo's `--versioned-dirs`, and how rustc vendors its
    own dependencies -- must read as `gimli` `0.32.3`, not as a crate literally named
    `gimli-0.32.3` with no version. That needs the name class to exclude `.`, so the
    version's leading `-` is necessarily the last `-` before the first `.`."""
    text = "/b/rustc-1.97.1-src/vendor/gimli-0.32.3/src/read/line.rs"
    crates, _ = find_rust_crates(text, max_crates=128, **_PATTERNS, claimed=frozenset())
    assert [(c.name, c.version) for c in crates] == [("gimli", "0.32.3")]


def test_a_hyphenated_crate_name_with_no_version_is_not_mistaken_for_one() -> None:
    text = "vendor/sha-1/src/lib.rs"
    crates, _ = find_rust_crates(text, max_crates=128, **_PATTERNS, claimed=frozenset())
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
            text, max_crates=128, **_PATTERNS, claimed=frozenset({"openssl"})
        )
        assert crates == (), text


def test_a_vendor_path_with_no_nul_terminator_still_matches() -> None:
    """Rust does not NUL-terminate a panic location the way a C string literal would,
    so the file-extension anchor must not require anything after `.rs`."""
    text = "vendor/openssl/src/ssl/mod.rsassertion failed"
    crates, _ = find_rust_crates(text, max_crates=128, **_PATTERNS, claimed=frozenset())
    assert [(c.name, c.version) for c in crates] == [("openssl", None)]


@pytest.mark.parametrize(
    "text",
    [
        "/r/cargo/registry/src/idx/bar-1.0.0/vendor/ring/src/x.rs",
        "/r/cargo/registry/src/idx/bar-1.0.0/vendor/zz/src/x.rs",
        "/r/cargo/registry/src/idx/bar-1.0.0/third_party/vendor/ring/src/x.rs",
        r"C:\r\cargo\registry\src\idx\bar-1.0.0\vendor\ring\src\x.rs",
        "/usr/share/cargo/registry/bar-1.0.0/vendor/ring/src/x.rs",
    ],
)
def test_a_vendor_tree_inside_a_registry_crate_is_part_of_that_crate(text: str) -> None:
    """A `vendor/` tree inside a registry crate's own directory is that crate's
    vendored source, not a crate of its own: the nested `vendor/ring/...` or
    `vendor/zz/...` match is dropped and only the registry crate is read."""
    crates, _ = find_rust_crates(text, max_crates=128, **_PATTERNS, claimed=frozenset({"ring"}))
    assert [(c.name, c.version) for c in crates] == [("bar", "1.0.0")]


def test_a_vendor_tree_nests_in_the_nearest_preceding_registry_crate_only() -> None:
    """With two registry matches ahead of a `vendor/` match, the nesting check must
    measure the gap from the nearer one's end, not the first one found: `a`'s
    directory does not contain `bar`'s nested `vendor/ring/...`, only `bar`'s does."""
    text = "\n".join(
        [
            "cargo/registry/src/i/a-1.0.0/src/lib.rs",
            "cargo/registry/src/i/bar-1.0.0/vendor/ring/src/x.rs",
        ]
    )
    crates, _ = find_rust_crates(text, max_crates=128, **_PATTERNS, claimed=frozenset({"ring"}))
    assert [(c.name, c.version) for c in crates] == [("a", "1.0.0"), ("bar", "1.0.0")]


def test_a_vendor_path_after_a_registry_crates_own_source_file_is_still_read() -> None:
    """rustc packs `&'static str` panic locations for unrelated crates back to back in
    read-only data, so a registry crate's directory ends at its first `.rs` file, not
    at the end of the printable run: a `vendor/` path that starts after that point is
    a separate path and is kept."""
    text = "/r/cargo/registry/src/idx/bar-1.0.0/src/lib.rs/w/vendor/ring/src/x.rs"
    crates, _ = find_rust_crates(text, max_crates=128, **_PATTERNS, claimed=frozenset())
    assert [(c.name, c.version) for c in crates] == [("bar", "1.0.0"), ("ring", None)]


def test_a_vendor_path_in_the_next_run_is_not_nested_in_a_registry_crate() -> None:
    """A `vendor/` match in a printable run that follows a registry crate's own run,
    joined by `RUN_SEPARATOR` plus a directory separator, is never read as nested in
    it: the gap between the two contains the run separator, which the nesting check
    excludes from a directory component."""
    text = "/r/cargo/registry/src/idx/bar-1.0.0/\n/vendor/ring/src/x.rs"
    crates, _ = find_rust_crates(text, max_crates=128, **_PATTERNS, claimed=frozenset())
    assert [(c.name, c.version) for c in crates] == [("bar", "1.0.0"), ("ring", None)]


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
    crates, _ = find_rust_crates(text, max_crates=128, **_PATTERNS, claimed=frozenset())
    assert [(c.name, c.version) for c in crates] == [("ring", None), ("ring", "0.17.8")]


def test_deduplicates_repeated_paths_for_the_same_crate() -> None:
    path = "/root/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ring-0.17.8/src/aead.rs"
    text = "\n".join([path, path.replace("aead", "hkdf")])
    crates, truncated = find_rust_crates(text, max_crates=128, **_PATTERNS, claimed=frozenset())
    assert crates == (crates[0],)


def test_sorts_multiple_distinct_crates_by_name_then_version() -> None:
    text = "\n".join(
        [
            "cargo/registry/src/index.crates.io-x/zeroize-1.7.0/src/lib.rs",
            "cargo/registry/src/index.crates.io-x/aws-lc-sys-0.19.0/src/lib.rs",
        ]
    )
    crates, _ = find_rust_crates(text, max_crates=128, **_PATTERNS, claimed=frozenset())
    assert [c.name for c in crates] == ["aws-lc-sys", "zeroize"]


def test_caps_after_sorting_and_flags_truncation() -> None:
    """With nothing claimed the cap is the plain one, which is what it always was."""
    text = "\n".join(
        f"cargo/registry/src/index.crates.io-x/crate{i}-0.1.{i}/src/lib.rs" for i in range(5)
    )
    crates, truncated = find_rust_crates(text, max_crates=2, **_PATTERNS, claimed=frozenset())
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
    crates, truncated = find_rust_crates(
        text, max_crates=3, **_PATTERNS, claimed=frozenset({"ring"})
    )
    assert truncated is True
    assert "ring" in {crate.name for crate in crates}
    assert len(crates) == 3


def test_finds_a_root_crate_from_a_git_checkout_path() -> None:
    """A checkout directory with no workspace member holding `src/` names a root
    crate (`ring`, not a library crate nested under it) after the repository, minus
    its trailing content hash."""
    text = "/root/.cargo/git/checkouts/ring-abcdef0123456789/1a2b3c4/src/lib.rs"
    crates, _ = find_rust_crates(text, max_crates=128, **_PATTERNS, claimed=frozenset())
    assert [(c.name, c.version) for c in crates] == [("ring", None)]


def test_finds_a_workspace_member_crate_from_a_git_checkout_path() -> None:
    """The checkout directory is named after the repository (`rust-openssl`), not the
    crate; a workspace member's own directory, the one immediately holding `src/`
    (`openssl-sys`), is the crate name."""
    text = "/root/.cargo/git/checkouts/rust-openssl-1d556dee1f65bd53/eadfd90/openssl-sys/src/lib.rs"
    crates, _ = find_rust_crates(text, max_crates=128, **_PATTERNS, claimed=frozenset())
    assert [(c.name, c.version) for c in crates] == [("openssl-sys", None)]


def test_a_measured_git_checkout_path_under_a_non_default_cargo_home_is_read() -> None:
    """CARGO_HOME is whatever the build set it to -- a custom directory, or
    `/usr/local/cargo` in the Rust Docker images -- so the pattern anchors on
    `git/checkouts/` rather than on `cargo/git/checkouts/`. A root crate is read
    under its repository's name, which is a known cost: `rust-base64`, not `base64`.
    """
    text = "/opt/cargohome/git/checkouts/rust-base64-9af66aca7bf9fca2/5b98ee1/src/engine/mod.rs"
    crates, _ = find_rust_crates(text, max_crates=128, **_PATTERNS, claimed=frozenset())
    assert [(c.name, c.version) for c in crates] == [("rust-base64", None)]


def test_a_git_checkout_path_with_backslash_separators_is_read() -> None:
    text = r"C:\cargo\git\checkouts\rustls-1234567890abcdef\eadfd90\rustls\src\lib.rs"
    crates, _ = find_rust_crates(text, max_crates=128, **_PATTERNS, claimed=frozenset())
    assert [(c.name, c.version) for c in crates] == [("rustls", None)]


def test_a_c_tree_under_a_git_checkout_workspace_member_is_not_read_as_a_rust_crate() -> None:
    """A `-sys` crate's vendored C sources sit under its member directory too; the
    `.rs` anchor must keep a C file there from being misread as the member crate."""
    text = (
        "/root/.cargo/git/checkouts/git2-rs-abcdef0123456789/eadfd90/libgit2-sys/libgit2/src/foo.c"
    )
    crates, _ = find_rust_crates(text, max_crates=128, **_PATTERNS, claimed=frozenset())
    assert crates == ()


def test_a_git_checkouts_directory_with_no_content_hash_is_not_read() -> None:
    """`git/checkouts/<name>-<hash>` is what tells this layout apart from an
    unrelated directory that happens to be called `checkouts`; without the 16-hex
    hash there is nothing cargo-specific to read a crate from."""
    text = "/x/git/checkouts/ring/src/lib.rs"
    crates, _ = find_rust_crates(text, max_crates=128, **_PATTERNS, claimed=frozenset())
    assert crates == ()


def test_a_vendor_tree_inside_a_git_checkout_member_reads_the_same_crate_both_ways() -> None:
    """`cargo_git_path_regex`'s own `name` group already reads the directory
    immediately above `src/`, so a `vendor/` tree nested inside a git-checkout
    workspace member is read as the same crate by both patterns, with no need for
    `_NESTED_GAP` precedence between them the way a registry match needs it over an
    inner `vendor/` match: the two candidate names never disagree."""
    text = "/root/.cargo/git/checkouts/foo-abcdef0123456789/eadfd90/member/vendor/ring/src/lib.rs"
    crates, _ = find_rust_crates(text, max_crates=128, **_PATTERNS, claimed=frozenset({"ring"}))
    assert [(c.name, c.version) for c in crates] == [("ring", None)]


def test_a_git_checkout_path_does_not_bridge_two_printable_runs() -> None:
    """Like `cargo_vendor_path_regex`, every negated class in `cargo_git_path_regex`
    must exclude `\\n`, the run separator `binfmt.strings.RUN_SEPARATOR` joins
    printable runs with: without it, a `.c` file ending one run and an unrelated
    `lib.rs` opening the next combine into a false crate match."""
    text = "git/checkouts/repo-abcdef0123456789/eadfd90/member/src/x.c\nunrelated/lib.rs"
    crates, _ = find_rust_crates(text, max_crates=128, **_PATTERNS, claimed=frozenset())
    assert crates == ()


def test_no_match_yields_empty_tuple_not_an_exception() -> None:
    crates, truncated = find_rust_crates(
        "nothing interesting here", max_crates=128, **_PATTERNS, claimed=frozenset()
    )
    assert crates == ()
    assert truncated is False


def test_a_registry_path_spliced_from_two_runs_is_not_a_crate() -> None:
    """The `src/<index>/` segment must not bridge `RUN_SEPARATOR`: a name from one
    printable run and a version from an unrelated one must never combine into a crate.
    Built through `extract_printable` so the separator is the real one `scan_strings`
    produces, not a hand-typed `\\n`. Both path separators, since a Windows-built
    object spells the same path with backslashes."""
    cases = [
        b"/x/cargo/registry/src/index\x00docs/openssl-0.10.1/README\x00",
        b"\x00see cargo\\registry\\src\\abcd\x00\x00etc\\ring-0.17.8\\README\x00",
    ]
    for raw in cases:
        text = extract_printable(raw, 4, 1 << 20).text
        crates, _ = find_rust_crates(
            text, max_crates=128, **_PATTERNS, claimed=frozenset({"openssl", "ring"})
        )
        assert crates == (), text


def test_no_cargo_convention_reads_a_crate_across_the_run_separator() -> None:
    """Every negated character class in both cargo patterns must exclude
    `RUN_SEPARATOR`, over every shipped layout, not just the reproduction above: for
    every split point in a known-good one-run path, splicing `RUN_SEPARATOR` in must
    never produce a crate that the two halves alone do not already produce between
    them."""
    paths = [
        "/root/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ring-0.17.8/src/lib.rs",
        "/usr/share/cargo/registry/openssl-0.10.66/src/lib.rs",
        "/b/vendor/gimli-0.32.3/src/read/line.rs",
    ]
    for path in paths:
        for i in range(1, len(path) - 1):
            spliced = path[:i] + RUN_SEPARATOR + path[i:]
            got, _ = find_rust_crates(spliced, max_crates=128, **_PATTERNS, claimed=frozenset())
            head, _ = find_rust_crates(path[:i], max_crates=128, **_PATTERNS, claimed=frozenset())
            tail, _ = find_rust_crates(path[i:], max_crates=128, **_PATTERNS, claimed=frozenset())
            expected = tuple(sorted(set(head) | set(tail), key=lambda c: (c.name, c.version or "")))
            assert got == expected, (path, i)


def test_a_numeric_semver_prerelease_splits_at_the_first_version() -> None:
    """Excluding `.` from the name class is what makes this split unique: with `.`
    excluded, a greedy name and a lazy name agree on `foo` / `1.0.0-1.2.3`, so this
    test alone does not pin laziness. It fails only when `.` is allowed back into the
    name class and the name stays greedy at the same time; either change alone leaves
    it green, and `.` allowed alone is already caught by
    `test_a_directory_name_with_a_dot_before_the_version_is_not_a_crate`."""
    text = "cargo/registry/src/index.crates.io-x/foo-1.0.0-1.2.3/src/lib.rs"
    crates, _ = find_rust_crates(text, max_crates=128, **_PATTERNS, claimed=frozenset())
    assert [(c.name, c.version) for c in crates] == [("foo", "1.0.0-1.2.3")]


def test_a_directory_name_with_a_dot_before_the_version_is_not_a_crate() -> None:
    """Cargo refuses `.` in a package name, so the name class excludes it: allowing
    `.` would let the name and version groups split a digit-and-dot run several ways,
    which costs several times as much per MiB of near-misses."""
    text = "cargo/registry/src/index.crates.io-x/a.b-1.0.0/src/lib.rs"
    crates, _ = find_rust_crates(text, max_crates=128, **_PATTERNS, claimed=frozenset())
    assert crates == ()


def test_a_64_character_crate_name_crates_ios_maximum_still_reads_in_full() -> None:
    """The name bound is crates.io's own limit, not an arbitrary tightening of it."""
    name = "a" * 64
    text = f"cargo/registry/src/index.crates.io-x/{name}-1.0.0/src/lib.rs"
    crates, _ = find_rust_crates(text, max_crates=128, **_PATTERNS, claimed=frozenset())
    assert [(c.name, c.version) for c in crates] == [(name, "1.0.0")]
