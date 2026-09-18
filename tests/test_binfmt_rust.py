"""Rust crate inference from embedded cargo registry paths."""

from __future__ import annotations

from wheel_crypto_scan.binfmt.rust import find_rust_crates
from wheel_crypto_scan.ruleset import load_ruleset

_PATTERN = load_ruleset().conventions.cargo_path_regex


def test_finds_a_crate_from_a_cargo_registry_path() -> None:
    text = "/root/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ring-0.17.8/src/lib.rs"
    crates, truncated = find_rust_crates(text, _PATTERN, max_crates=128)
    assert truncated is False
    assert len(crates) == 1
    assert crates[0].name == "ring"
    assert crates[0].version == "0.17.8"


def test_deduplicates_repeated_paths_for_the_same_crate() -> None:
    path = "/root/.cargo/registry/src/index.crates.io-6f17d22bba15001f/ring-0.17.8/src/aead.rs"
    text = "\n".join([path, path.replace("aead", "hkdf")])
    crates, truncated = find_rust_crates(text, _PATTERN, max_crates=128)
    assert crates == (crates[0],)


def test_sorts_multiple_distinct_crates_by_name_then_version() -> None:
    text = "\n".join(
        [
            "cargo/registry/src/index.crates.io-x/zeroize-1.7.0/src/lib.rs",
            "cargo/registry/src/index.crates.io-x/aws-lc-sys-0.19.0/src/lib.rs",
        ]
    )
    crates, _ = find_rust_crates(text, _PATTERN, max_crates=128)
    assert [c.name for c in crates] == ["aws-lc-sys", "zeroize"]


def test_caps_after_sorting_and_flags_truncation() -> None:
    text = "\n".join(
        f"cargo/registry/src/index.crates.io-x/crate{i}-0.1.{i}/src/lib.rs" for i in range(5)
    )
    crates, truncated = find_rust_crates(text, _PATTERN, max_crates=2)
    assert truncated is True
    assert [c.name for c in crates] == ["crate0", "crate1"]


def test_no_match_yields_empty_tuple_not_an_exception() -> None:
    crates, truncated = find_rust_crates("nothing interesting here", _PATTERN, max_crates=128)
    assert crates == ()
    assert truncated is False
